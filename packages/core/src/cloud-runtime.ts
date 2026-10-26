import { createUuidV7 } from "./crypto.js";
import { resolveFetchImplementation } from "./fetch-implementation.js";
import type { EmailMessage, EmailProvider, SmsMessage, SmsProvider } from "./providers.js";
import type { CloudSnapshotRecord, CloudStorage } from "./cloud-storage.js";
import type { AuthStorage } from "./storage.js";
import {
  cloudAppId,
  auditCloudEvent,
  cloudEventsForOperation,
  cloudOrganisationMemberAddedEvent,
  cloudOrganisationMemberRemovedEvent,
  cloudUserAuthMethods,
  cloudUserEvent,
  createCloudEvent,
  failedLoginEvent,
  isPriorityCloudEvent,
  rateLimitCloudEvent,
  sessionRevokedCloudEvent,
  validateCloudEvent
} from "./cloud-events.js";
import type {
  ClearCloudOutboxInput,
  CloudBackfillInput,
  CloudBackfillResult,
  CloudDeliveryError,
  CloudEvent,
  CloudOperationContext,
  CloudPluginOptions,
  FlushCloudOutboxInput,
  FlushCloudOutboxResult
} from "./cloud-types.js";
import type { OwnAuth } from "./auth-engine.js";
import { CloudDeliveryFailure, CloudHttpError } from "./cloud-errors.js";
import { CloudCommandHandler } from "./cloud-commands.js";
import { CloudSecurity } from "./cloud-security.js";
import type { AuditEvent, OrganisationMember, RequestContext, Session } from "./types.js";
import {
  cloudEmailType,
  cloudPositiveInteger,
  cloudSmsType,
  safeCloudError
} from "./cloud-runtime-helpers.js";

const maximumOutboxSize = 10_000;
const cloudBatchSize = 50;
const cloudRequestTimeoutMs = 15_000;
const cloudIngestionWindowMs = 7 * 24 * 60 * 60_000;
const authMethodAuditEvents = new Set([
  "email.removed",
  "external_provider.linked",
  "external_provider.unlinked",
  "mfa.totp_enabled",
  "mfa.totp_disabled",
  "passkey.registered",
  "passkey.revoked",
  "saml.identity_linked",
  "saml.identity_unlinked"
]);
const memberAddedAuditEvents = new Set([
  "saml.member_provisioned"
]);

export class CloudRuntime {
  readonly emailProvider: EmailProvider;
  readonly smsProvider: SmsProvider;
  readonly webhookPath: string | null;
  private readonly options: Readonly<CloudPluginOptions>;
  private readonly appId: string;
  private readonly endpoint: string;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly commands: CloudCommandHandler;
  private readonly security: CloudSecurity;
  private warnedOutboxFullAt = 0;
  private nextCleanupAt = 0;

  constructor(
    options: Readonly<CloudPluginOptions>,
    private readonly storage: CloudStorage,
    private readonly authStorage: AuthStorage
  ) {
    this.options = options;
    this.endpoint = String(options.endpoint).replace(/\/$/, "");
    this.appId = cloudAppId(options.key);
    this.webhookPath = options.webhookSigningSecret ? options.webhookPath as string : null;
    const fetchImpl = resolveFetchImplementation(options.fetch);
    if (!fetchImpl) throw new Error("Own Auth Cloud requires a Fetch API implementation");
    this.fetchImpl = fetchImpl;
    this.commands = new CloudCommandHandler(storage, [
      { id: options.webhookKeyId as string, secret: options.webhookSigningSecret },
      {
        id: options.webhookPreviousKeyId as string,
        secret: options.webhookPreviousSigningSecret,
        validUntil: options.webhookPreviousValidUntil
      }
    ]);
    this.security = new CloudSecurity({
      options,
      storage,
      appId: this.appId,
      request: (path, init, timeoutMs) => this.cloudRequest(path, init, timeoutMs),
      enqueue: (draft) => this.enqueue(draft).then(() => undefined),
      warn: (message) => this.warn(message)
    });
    this.emailProvider = { send: (message) => this.sendEmail(message) };
    this.smsProvider = { send: (message) => this.sendSms(message) };
  }

  beforeOperation(context: CloudOperationContext): Promise<void> {
    return this.security.beforeOperation(context);
  }

  async afterOperation(context: CloudOperationContext): Promise<void> {
    try {
      await this.syncAfterOperation(context);
    } catch (error) {
      this.warn(`Cloud post-operation sync failed: ${safeCloudError(error)}`);
    }
  }

  private async syncAfterOperation(context: CloudOperationContext): Promise<void> {
    await this.security.afterOperation(context);
    const drafts = context.error
      ? [failedLoginEvent(context)].filter((draft) => draft !== null)
      : cloudEventsForOperation(context);
    const enrichedDrafts = context.error
      ? drafts
      : await this.enrichOperationDrafts(context, drafts);
    for (const draft of enrichedDrafts) {
      await this.enqueue(draft).catch((error) => {
        this.warn(`Cloud event could not be recorded: ${safeCloudError(error)}`);
      });
    }
    await this.flushAfterOperation();
    if (Date.now() >= this.nextCleanupAt) {
      this.nextCleanupAt = Date.now() + 60 * 60_000;
      await this.cleanup(new Date(Date.now() - cloudIngestionWindowMs))
        .catch((error) => this.warn(`Cloud cleanup failed: ${safeCloudError(error)}`));
    }
  }

  private async flushAfterOperation(): Promise<void> {
    if (this.options.flushMode === "manual") return;
    const task = this.flushOutbox({ limit: 10 })
      .then(() => undefined)
      .catch((error) => this.warn(safeCloudError(error)));
    if (this.options.flushMode !== "background") {
      await task;
      return;
    }
    try {
      this.options.schedule?.(task);
    } catch (error) {
      this.warn(`Cloud background flush could not be scheduled: ${safeCloudError(error)}`);
      await task;
    }
  }

  async flushOutbox(input: FlushCloudOutboxInput = {}): Promise<FlushCloudOutboxResult> {
    const limit = cloudPositiveInteger(input.limit ?? cloudBatchSize, 1, 500, "Cloud flush limit");
    const now = new Date();
    const records = await this.storage.claimCloudOutbox(
      limit,
      now,
      new Date(now.getTime() + 30_000)
    );
    let sent = 0;
    let regularSent = 0;
    let failed = 0;
    const regular = records.filter((record) => !record.priority);
    const priority = records.filter((record) => record.priority);
    for (const record of records) validateCloudEvent(record.event, true);
    const ingestionCutoff = now.getTime() - cloudIngestionWindowMs;
    const expired: typeof regular = [];
    const deliverable: typeof regular = [];
    for (const record of regular) {
      const target = new Date(record.event.timestamp).getTime() < ingestionCutoff
        ? expired
        : deliverable;
      target.push(record);
    }
    if (expired.length > 0) {
      await this.markDataGap(expired.reduce(
        (earliest, { event }) => event.timestamp < earliest ? event.timestamp : earliest,
        expired[0]!.event.timestamp
      ));
      await this.storage.acknowledgeCloudOutbox(expired.map(({ id }) => id), now);
      this.warn(
        "Cloud events outside the seven-day ingestion window were discarded and recorded as a data gap."
      );
    }
    for (let offset = 0; offset < deliverable.length; offset += cloudBatchSize) {
      const batch = deliverable.slice(offset, offset + cloudBatchSize);
      try {
        await this.cloudRequest("/ingest/events", {
          method: "POST",
          body: JSON.stringify({ events: batch.map((record) => record.event) }),
          signal: input.signal
        });
        await this.storage.acknowledgeCloudOutbox(batch.map(({ id }) => id), new Date());
        sent += batch.length;
        regularSent += batch.length;
      } catch (error) {
        if (error instanceof CloudHttpError && error.status === 422) {
          await this.storage.acknowledgeCloudOutbox(batch.map(({ id }) => id), new Date());
          this.warn("Cloud rejected an invalid event batch. The batch was discarded.");
        } else {
          failed += batch.length;
          await Promise.all(batch.map((record) => this.retry(record.id, record.attempts + 1)));
        }
      }
    }
    for (const record of priority) {
      try {
        await this.cloudRequest("/ingest/priority", {
          method: "POST",
          body: JSON.stringify(record.event),
          signal: input.signal
        });
        await this.storage.acknowledgeCloudOutbox([record.id], new Date());
        sent += 1;
      } catch {
        failed += 1;
        await this.retry(record.id, record.attempts + 1);
      }
    }
    if (regularSent > 0) {
      await this.reportDataGap(new Date()).catch((error) => {
        this.warn(`Cloud data gap could not be reported: ${safeCloudError(error)}`);
      });
    }
    return { sent, failed, remaining: await this.storage.countCloudOutbox() };
  }

  clearOutbox(input: ClearCloudOutboxInput = {}): Promise<number> {
    return this.storage.clearCloudOutbox(input.includePriority ?? false);
  }

  async eraseUser(userId: string): Promise<{ eventId: string; removedPendingEvents: number }> {
    const normalizedUserId = userId.trim();
    if (!normalizedUserId) throw new Error("Cloud user ID is required");
    this.security.eraseUser(normalizedUserId);
    const user = await this.authStorage.getUserById(normalizedUserId);
    const removedPendingEvents = await this.storage.purgeCloudOutboxForUser(
      normalizedUserId,
      user?.email
    );
    const event = await this.enqueue({
      type: "user.deleted",
      data: { userId: normalizedUserId },
      entity: { type: "user", id: normalizedUserId },
      priority: true,
      userId: normalizedUserId
    });
    if (!event) throw new Error("Cloud user deletion event could not be recorded");
    await this.flushOutbox({ limit: cloudBatchSize });
    return { eventId: event.id, removedPendingEvents };
  }

  async backfill(input: CloudBackfillInput = {}): Promise<CloudBackfillResult> {
    const batchSize = cloudPositiveInteger(
      input.batchSize ?? 100, 1, 500, "Cloud backfill batch size"
    );
    let cursor = input.cursor ?? await this.storage.getCloudConfig("backfill_cursor");
    let sent = 0;
    while (true) {
      if (input.signal?.aborted) throw input.signal.reason;
      const page = await this.storage.listCloudSnapshot(cursor, batchSize);
      if (page.records.length === 0) {
        await this.storage.setCloudConfig("backfill_cursor", "");
        return { sent, cursor: null, complete: true };
      }
      const records = await Promise.all(page.records.map((record) => this.enrichSnapshot(record)));
      await this.cloudRequest("/ingest/backfill", {
        method: "POST",
        body: JSON.stringify({ records, cursor: page.cursor }),
        signal: input.signal
      });
      sent += page.records.length;
      cursor = page.cursor;
      await this.storage.setCloudConfig("backfill_cursor", cursor ?? "");
      input.onProgress?.({ sent, total: null, cursor });
      if (!cursor) return { sent, cursor: null, complete: true };
      await backfillPace(page.records.length, input.signal);
    }
  }

  rotateChallengeSecret(): Promise<void> {
    return this.security.rotateChallengeSecret();
  }

  handleCommand(
    auth: OwnAuth<string, string>,
    request: Request,
    body: string
  ) {
    return this.commands.handle(auth, request, body);
  }

  cleanup(olderThan: Date): Promise<number> {
    return this.storage.cleanupCloudState(olderThan);
  }

  async recordAuditEvent(event: AuditEvent): Promise<void> {
    await this.enqueue(auditCloudEvent(event)).catch((error) => {
      this.warn(`Cloud audit event could not be recorded: ${safeCloudError(error)}`);
    });
    const userId = event.targetUserId ?? event.actorUserId;
    const projectionType = event.eventType === "user.signed_up"
      ? "user.created"
      : authMethodAuditEvents.has(event.eventType) ? "user.updated" : null;
    if (userId && projectionType) {
      await this.enqueueUserProjection(userId, projectionType).catch((error) => {
        this.warn(`Cloud user projection could not be recorded: ${safeCloudError(error)}`);
      });
    }
    if (event.organisationId && event.targetUserId) {
      await this.enqueueMemberProjection(event).catch((error) => {
        this.warn(`Cloud organisation member projection could not be recorded: ${safeCloudError(error)}`);
      });
    }
  }

  private async enrichUserDrafts(
    context: CloudOperationContext,
    drafts: Parameters<typeof createCloudEvent>[1][]
  ): Promise<Parameters<typeof createCloudEvent>[1][]> {
    const existing = drafts.find(({ type }) => type === "user.created" || type === "user.updated");
    if (!existing) return drafts;
    const userId = existing.userId ?? resultUserId(context.result) ?? context.userId;
    if (!userId) return drafts;
    const user = await this.authStorage.getUserById(userId);
    if (!user) return drafts;
    const projection = cloudUserEvent(
      existing.type === "user.created" ? "user.created" : "user.updated",
      user,
      await cloudUserAuthMethods(this.authStorage, user),
      context.request
    );
    return drafts.map((draft) => draft === existing ? projection : draft);
  }

  private async enrichOperationDrafts(
    context: CloudOperationContext,
    drafts: Parameters<typeof createCloudEvent>[1][]
  ): Promise<Parameters<typeof createCloudEvent>[1][]> {
    const userDrafts = await this.enrichUserDrafts(context, drafts);
    if (!context.operation.startsWith("scim.")) return userDrafts;
    const resource = context.result && typeof context.result === "object"
      ? context.result as Record<string, unknown>
      : null;
    const membershipId = typeof resource?.membershipId === "string"
      ? resource.membershipId
      : null;
    const userId = typeof resource?.userId === "string" ? resource.userId : null;
    if (!membershipId || !userId) return userDrafts;
    const member = await this.authStorage.getOrganisationMemberById(membershipId);
    if (!member) return userDrafts;
    const membershipDraft = resource?.active === true && member.status === "active"
      ? cloudOrganisationMemberAddedEvent(member, context.request, context.userId)
      : cloudOrganisationMemberRemovedEvent(
          member.organisationId,
          userId,
          context.request,
          context.userId
        );
    return [membershipDraft, ...userDrafts];
  }

  private async enrichSnapshot(record: CloudSnapshotRecord): Promise<CloudSnapshotRecord> {
    if (record.type !== "user") return record;
    const userId = typeof record.data.userId === "string" ? record.data.userId : null;
    const user = userId ? await this.authStorage.getUserById(userId) : null;
    if (!user) return record;
    return {
      ...record,
      data: {
        ...record.data,
        authMethods: await cloudUserAuthMethods(this.authStorage, user)
      }
    };
  }

  private async enqueueUserProjection(
    userId: string,
    type: "user.created" | "user.updated"
  ): Promise<void> {
    const user = await this.authStorage.getUserById(userId);
    if (!user) return;
    await this.enqueue(cloudUserEvent(
      type,
      user,
      await cloudUserAuthMethods(this.authStorage, user)
    ));
  }

  private async enqueueMemberProjection(event: AuditEvent): Promise<void> {
    const organisationId = event.organisationId as string;
    const userId = event.targetUserId as string;
    if (memberAddedAuditEvents.has(event.eventType)) {
      const member = await this.authStorage.getOrganisationMember(organisationId, userId);
      if (member?.status === "active") {
        await this.enqueue(cloudOrganisationMemberAddedEvent(
          member,
          auditRequestContext(event),
          event.actorUserId ?? undefined
        ));
      }
    }
  }

  async recordRateLimit(action: string, limit: number, windowMs: number): Promise<void> {
    await this.enqueue(rateLimitCloudEvent(action, limit, windowMs)).catch((error) => {
      this.warn(`Cloud rate-limit event could not be recorded: ${safeCloudError(error)}`);
    });
  }

  async recordSessionRevoked(session: Session, context?: RequestContext): Promise<void> {
    await this.enqueue(sessionRevokedCloudEvent(session, context)).catch((error) => {
      this.warn(`Cloud session revocation event could not be recorded: ${safeCloudError(error)}`);
    });
  }

  async recordEmailMembershipReassigned(
    originalUserId: string,
    member: OrganisationMember<string>,
    context?: RequestContext
  ): Promise<void> {
    try {
      await this.enqueue(cloudOrganisationMemberRemovedEvent(member.organisationId, originalUserId, context));
      if (member.status === "active") {
        await this.enqueue(cloudOrganisationMemberAddedEvent(member, context ?? {}));
      }
    } catch (error) {
      this.warn(`Cloud email ownership membership could not be recorded: ${safeCloudError(error)}`);
    }
  }

  private async enqueue(
    draft: Parameters<typeof createCloudEvent>[1] | null
  ): Promise<CloudEvent | null> {
    if (!draft) return null;
    const priority = draft.priority ?? isPriorityCloudEvent(draft.type);
    const event = createCloudEvent(this.appId, draft);
    const stored = await this.storage.enqueueCloudEvent(
      event,
      draft.entity ?? null,
      priority,
      priority ? undefined : maximumOutboxSize
    );
    if (!stored) {
      if (!priority) await this.markDataGap(event.timestamp);
      const now = Date.now();
      if (now - this.warnedOutboxFullAt >= 10 * 60_000) {
        this.warn(
          "Cloud outbox is full. New non-priority events are being dropped, so dashboard and analytics data may be incomplete."
        );
        this.warnedOutboxFullAt = now;
      }
      return null;
    }
    return stored;
  }

  private async markDataGap(startedAt: string): Promise<void> {
    const current = await this.storage.getCloudConfig("data_gap_started_at");
    if (current === null) {
      const stored = await this.storage.getOrCreateCloudConfig("data_gap_started_at", startedAt);
      if (stored && startedAt < stored) {
        await this.storage.setCloudConfig("data_gap_started_at", startedAt);
      }
      return;
    }
    if (!current || startedAt < current) {
      await this.storage.setCloudConfig("data_gap_started_at", startedAt);
    }
  }

  private async reportDataGap(endedAt: Date): Promise<void> {
    const startedAt = await this.storage.getCloudConfig("data_gap_started_at");
    if (!startedAt) return;
    if (await this.storage.countCloudOutbox(false) >= maximumOutboxSize) return;
    await this.cloudRequest("/ingest/gaps", {
      method: "POST",
      body: JSON.stringify({ startedAt, endedAt: endedAt.toISOString() })
    });
    if (await this.storage.getCloudConfig("data_gap_started_at") === startedAt &&
      await this.storage.countCloudOutbox(false) < maximumOutboxSize) {
      await this.storage.setCloudConfig("data_gap_started_at", "");
    }
  }

  private async retry(id: string, attempts: number): Promise<void> {
    const delay = Math.min(300_000, 2 ** Math.min(attempts - 1, 18) * 1_000);
    await this.storage.retryCloudOutbox(id, attempts, new Date(Date.now() + delay));
  }

  private sendEmail(message: EmailMessage): Promise<void> {
    return this.sendDelivery("email", {
      idempotencyKey: createUuidV7(),
      to: message.to,
      recipientUserId: message.recipientUserId,
      type: cloudEmailType(message.type),
      templateData: {
        url: message.url,
        expiresAt: message.expiresAt.toISOString()
      }
    });
  }

  private sendSms(message: SmsMessage): Promise<void> {
    return this.sendDelivery("sms", {
      idempotencyKey: createUuidV7(),
      to: message.to,
      recipientUserId: message.recipientUserId,
      type: cloudSmsType(message.purpose),
      templateData: {
        code: message.code,
        expiresAt: message.expiresAt.toISOString()
      }
    });
  }

  private async sendDelivery(channel: "email" | "sms", payload: Record<string, unknown>): Promise<void> {
    try {
      const response = await this.cloudRequest(`/delivery/${channel}`, {
        method: "POST",
        headers: { "idempotency-key": String(payload.idempotencyKey) },
        body: JSON.stringify(payload)
      });
      const result = await response.json().catch(() => null) as {
        messageId?: string;
        quotaWarning?: boolean;
      } | null;
      if (!result?.messageId) {
        throw new CloudHttpError(502, "invalid_delivery_response");
      }
      await this.enqueue({
        type: channel === "email" ? "email.requested" : "sms.requested",
        data: {
          messageId: result.messageId,
          type: payload.type,
          recipientUserId: payload.recipientUserId
        }
      }).catch((error) => {
        this.warn(`Cloud delivery event could not be recorded: ${safeCloudError(error)}`);
      });
      if (result?.quotaWarning) {
        this.warn(`Own Auth Cloud ${channel} usage has reached 80% of the included quota.`);
      }
    } catch (error) {
      const status = error instanceof CloudHttpError ? error.status : 0;
      const deliveryError: CloudDeliveryError = {
        code: error instanceof CloudHttpError && error.code === "quota_exhausted"
          ? "quota_exhausted" : status >= 500 || status === 0
          ? "transient_error"
          : status >= 400 ? "invalid_request" : "provider_rejected",
        channel,
        status
      };
      if (this.options.onDeliveryError) {
        try {
          await this.options.onDeliveryError(deliveryError);
        } catch (callbackError) {
          this.warn(`Cloud delivery error callback failed: ${safeCloudError(callbackError)}`);
        }
      } else {
        this.warn(
          `Own Auth Cloud ${channel} delivery failed: ${deliveryError.code}`
        );
      }
      throw new CloudDeliveryFailure(deliveryError);
    }
  }

  private async cloudRequest(
    path: string,
    init: RequestInit,
    timeoutMs = cloudRequestTimeoutMs
  ): Promise<Response> {
    const controller = new AbortController();
    const externalSignal = init.signal;
    const abort = () => controller.abort(externalSignal?.reason);
    externalSignal?.addEventListener("abort", abort, { once: true });
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const headers = new Headers(init.headers);
      headers.set("authorization", `Bearer ${this.options.key}`);
      headers.set("content-type", "application/json");
      const response = await this.fetchImpl(`${this.endpoint}${path}`, {
        ...init,
        headers,
        signal: controller.signal
      });
      if (!response.ok) {
        const body = await response.clone().json().catch(() => null) as {
          code?: string;
          error?: { code?: string };
        } | null;
        throw new CloudHttpError(response.status, body?.error?.code ?? body?.code);
      }
      return response;
    } finally {
      clearTimeout(timeout);
      externalSignal?.removeEventListener("abort", abort);
    }
  }

  private warn(message: string): void {
    if (this.options.onWarning) this.options.onWarning(message);
    else console.warn(`[own-auth cloud] ${message}`);
  }
}

async function backfillPace(recordCount: number, signal?: AbortSignal): Promise<void> {
  const delayMs = Math.ceil(recordCount * 2) + 25;
  await new Promise<void>((resolve, reject) => {
    const finish = () => {
      signal?.removeEventListener("abort", abort);
      resolve();
    };
    const abort = () => {
      clearTimeout(timeout);
      reject(signal?.reason);
    };
    const timeout = setTimeout(finish, delayMs);
    signal?.addEventListener("abort", abort, { once: true });
  });
}

function resultUserId(result: unknown): string | undefined {
  if (!result || typeof result !== "object") return undefined;
  const record = result as Record<string, unknown>;
  if (record.user && typeof record.user === "object") {
    const id = (record.user as Record<string, unknown>).id;
    if (typeof id === "string") return id;
  }
  return typeof record.userId === "string" ? record.userId : undefined;
}

function auditRequestContext(event: AuditEvent): RequestContext {
  return {
    ipAddress: event.ipAddress ?? undefined,
    userAgent: event.userAgent ?? undefined
  };
}
