import { createId } from "./crypto.js";
import { AuthError } from "./errors.js";
import { isUserErasureCapableStorage } from "./user-erasure.js";
import type { AuthEngineContext } from "./auth-engine-context.js";
import { traceWebhookDelivery } from "./telemetry.js";
import {
  createWebhookSignature,
  webhookIdHeader,
  webhookSignatureHeader,
  webhookTimestampHeader
} from "./webhook-signing.js";
import type { ClaimedWebhookDelivery, WebhookStorage } from "./webhook-storage.js";
import type {
  CleanupWebhookDeliveriesInput,
  ListWebhookDeliveriesInput,
  ProcessWebhookDeliveriesInput,
  ProcessWebhookDeliveriesResult,
  RetryWebhookDeliveryInput,
  WebhookAttemptErrorCode,
  WebhookAttemptOutcome,
  WebhookDeliveryDetails
} from "./webhook-types.js";

const retryDelaysMs = [30_000, 120_000, 600_000, 3_600_000, 21_600_000] as const;
const maxAttemptsPerCycle = retryDelaysMs.length + 1;
const requestTimeoutMs = 10_000;
const leaseDurationMs = 30_000;
const maxRetryAfterMs = 24 * 60 * 60 * 1_000;

interface AttemptDecision {
  status: "delivered" | "failed" | "pending";
  outcome: WebhookAttemptOutcome;
  statusCode: number | null;
  errorCode: WebhookAttemptErrorCode | null;
  nextAttemptAt: Date;
  finishedAt: Date;
}

export async function processWebhookDeliveries(
  ctx: AuthEngineContext,
  input: ProcessWebhookDeliveriesInput = {}
): Promise<ProcessWebhookDeliveriesResult> {
  const storage = requireWebhookStorage(ctx);
  const limit = boundedLimit(input.limit, 10);
  const now = new Date();
  const leaseToken = createId("whl");
  const claimed = await storage.claimWebhookDeliveries({
    now,
    leaseToken,
    leaseExpiresAt: new Date(now.getTime() + leaseDurationMs),
    limit
  });
  const outcomes = await Promise.all(claimed.map((item) =>
    deliverClaimed(ctx, storage, item, leaseToken)));

  return {
    claimed: claimed.length,
    delivered: outcomes.filter((outcome) => outcome === "delivered").length,
    retried: outcomes.filter((outcome) => outcome === "pending").length,
    failed: outcomes.filter((outcome) => outcome === "failed").length,
    leaseLost: outcomes.filter((outcome) => outcome === "lease_lost").length
  };
}

export async function listWebhookDeliveries(
  ctx: AuthEngineContext,
  input: ListWebhookDeliveriesInput = {}
): Promise<WebhookDeliveryDetails[]> {
  const storage = requireWebhookStorage(ctx);
  const deliveries = await storage.listWebhookDeliveries({
    ...input,
    limit: boundedLimit(input.limit, 50)
  });
  const attempts = await storage.listWebhookAttempts(
    deliveries.map(({ delivery }) => delivery.id)
  );
  const attemptsByDelivery = new Map<string, typeof attempts>();
  for (const attempt of attempts) {
    const existing = attemptsByDelivery.get(attempt.deliveryId) ?? [];
    existing.push(attempt);
    attemptsByDelivery.set(attempt.deliveryId, existing);
  }
  return deliveries.map(({ delivery, eventType }) => {
    const { leaseToken, ...visibleDelivery } = delivery;
    void leaseToken;
    return {
      ...visibleDelivery,
      eventType,
      attempts: attemptsByDelivery.get(delivery.id) ?? []
    };
  });
}

export async function retryWebhookDelivery(
  ctx: AuthEngineContext,
  input: RetryWebhookDeliveryInput
): Promise<void> {
  const retried = await requireWebhookStorage(ctx).retryWebhookDelivery(
    input.deliveryId,
    new Date()
  );
  if (!retried) {
    throw new AuthError(
      "webhook_delivery_not_retryable",
      "Webhook delivery was not found or is not failed",
      409
    );
  }
}

export function cleanupWebhookDeliveries(
  ctx: AuthEngineContext,
  input: CleanupWebhookDeliveriesInput
): Promise<number> {
  if (!(input.olderThan instanceof Date) || !Number.isFinite(input.olderThan.getTime())) {
    throw new AuthError("validation_error", "olderThan must be a valid date", 400);
  }
  return requireWebhookStorage(ctx).cleanupWebhookDeliveries(input.olderThan);
}

async function deliverClaimed(
  ctx: AuthEngineContext,
  storage: WebhookStorage,
  claimed: ClaimedWebhookDelivery,
  leaseToken: string
): Promise<"delivered" | "failed" | "lease_lost" | "pending"> {
  const endpoint = ctx.webhooks?.endpointsById.get(claimed.delivery.endpointId);
  const startedAt = new Date();
  const attemptInCycle = Math.max(1, Math.min(
    claimed.delivery.attemptsInCycle + 1,
    maxAttemptsPerCycle
  ));
  const decision = await traceWebhookDelivery(
    claimed.delivery.endpointId,
    claimed.event.type,
    attemptInCycle,
    () => endpoint
      ? sendWebhook(ctx, claimed, endpoint.secret, attemptInCycle, startedAt, leaseToken)
      : Promise.resolve(permanentFailure(startedAt, "endpoint_not_configured"))
  );
  if (!decision) return "lease_lost";
  const attemptNumber = claimed.delivery.totalAttempts + 1;
  const settled = await storage.settleWebhookDelivery({
    deliveryId: claimed.delivery.id,
    leaseToken,
    expectedTotalAttempts: claimed.delivery.totalAttempts,
    attempt: {
      id: createId("wha"),
      deliveryId: claimed.delivery.id,
      attemptNumber,
      startedAt,
      finishedAt: decision.finishedAt,
      outcome: decision.outcome,
      statusCode: decision.statusCode,
      errorCode: decision.errorCode,
      nextRetryAt: decision.status === "pending" ? decision.nextAttemptAt : null
    },
    status: decision.status,
    nextAttemptAt: decision.nextAttemptAt
  });
  return settled ? decision.status : "lease_lost";
}

async function sendWebhook(
  ctx: AuthEngineContext,
  claimed: ClaimedWebhookDelivery,
  secret: string,
  attemptInCycle: number,
  startedAt: Date,
  leaseToken: string
): Promise<AttemptDecision | null> {
  const timestamp = Math.floor(startedAt.getTime() / 1_000).toString();
  const signature = await createWebhookSignature({
    body: claimed.event.payload,
    eventId: claimed.event.id,
    timestamp,
    secret
  });
  if (isUserErasureCapableStorage(ctx.storage) && !await ctx.storage.userErasureStorage.authorizeWebhookSend(claimed.delivery.id, leaseToken)) return null;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);

  try {
    const response = await ctx.webhooks!.fetch(claimed.delivery.url, {
      method: "POST",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "content-type": "application/json",
        [webhookIdHeader]: claimed.event.id,
        [webhookTimestampHeader]: timestamp,
        [webhookSignatureHeader]: signature
      },
      body: claimed.event.payload
    });
    await response.body?.cancel().catch(() => undefined);
    return responseDecision(response, attemptInCycle, new Date());
  } catch {
    const finishedAt = new Date();
    return retryableFailure(
      attemptInCycle,
      finishedAt,
      controller.signal.aborted ? "timeout" : "network_error"
    );
  } finally {
    clearTimeout(timeout);
  }
}

function responseDecision(response: Response, attempt: number, finishedAt: Date): AttemptDecision {
  if (response.status >= 200 && response.status < 300) {
    return {
      status: "delivered",
      outcome: "delivered",
      statusCode: response.status,
      errorCode: null,
      nextAttemptAt: finishedAt,
      finishedAt
    };
  }
  if (response.status === 408 || response.status === 429 || response.status >= 500) {
    return retryableFailure(
      attempt,
      finishedAt,
      "http_retryable",
      response.status,
      retryAfterMs(response, finishedAt)
    );
  }
  return permanentFailure(finishedAt, "http_permanent", response.status);
}

function retryableFailure(
  attempt: number,
  finishedAt: Date,
  errorCode: WebhookAttemptErrorCode,
  statusCode: number | null = null,
  requestedDelayMs = 0
): AttemptDecision {
  if (attempt >= maxAttemptsPerCycle) {
    return permanentFailure(finishedAt, errorCode, statusCode);
  }
  const defaultDelay = retryDelaysMs[attempt - 1] ?? retryDelaysMs.at(-1)!;
  const delay = Math.max(defaultDelay, Math.min(requestedDelayMs, maxRetryAfterMs));
  return {
    status: "pending",
    outcome: "retry_scheduled",
    statusCode,
    errorCode,
    nextAttemptAt: new Date(finishedAt.getTime() + delay),
    finishedAt
  };
}

function permanentFailure(
  finishedAt: Date,
  errorCode: WebhookAttemptErrorCode,
  statusCode: number | null = null
): AttemptDecision {
  return {
    status: "failed",
    outcome: "failed",
    statusCode,
    errorCode,
    nextAttemptAt: finishedAt,
    finishedAt
  };
}

function retryAfterMs(response: Response, now: Date): number {
  if (response.status !== 429 && response.status !== 503) return 0;
  const value = response.headers.get("retry-after")?.trim();
  if (!value) return 0;
  if (/^\d+$/u.test(value)) return Number(value) * 1_000;
  const date = Date.parse(value);
  return Number.isFinite(date) ? Math.max(0, date - now.getTime()) : 0;
}

function requireWebhookStorage(ctx: AuthEngineContext): WebhookStorage {
  if (!ctx.webhooks || !ctx.webhookStorage) {
    throw new Error("Webhook delivery is not configured");
  }
  return ctx.webhookStorage;
}

function boundedLimit(value: number | undefined, fallback: number): number {
  const limit = value ?? fallback;
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    throw new AuthError("validation_error", "Webhook delivery limit must be between 1 and 100", 400);
  }
  return limit;
}
