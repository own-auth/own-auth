import type {
  CloudCommandPayload,
  CloudCommandResult,
  CloudEvent,
  CloudEventEntity
} from "./cloud-types.js";
import type {
  CloudCommandReservation,
  CloudOutboxRecord,
  CloudSnapshotRecord,
  CloudStorage
} from "./cloud-storage.js";
import type { Organisation, OrganisationMember, Session, User } from "./types.js";

interface MemoryCloudCommand {
  idempotencyKey: string;
  nonce: string;
  action: CloudCommandPayload["action"];
  payloadHash: string;
  payload: CloudCommandPayload;
  status: "reserved" | "completed" | "failed";
  result: CloudCommandResult | null;
  reservedAt: Date;
  leaseUntil: Date;
  completedAt: Date | null;
}

export class MemoryCloudStorage implements CloudStorage {
  /** @internal */
  erasureMaps(): Map<string, any>[] { return [this.outbox, this.commands]; }
  /** @internal */
  get erasureOutbox(): Map<string, CloudOutboxRecord> { return this.outbox; }
  /** @internal */
  get erasureVersions(): Map<string, number> { return this.entityVersions; }
  readonly durable = false;
  private readonly outbox = new Map<string, CloudOutboxRecord>();
  private readonly entityVersions = new Map<string, number>();
  private readonly config = new Map<string, string>();
  private readonly challengeNonces = new Map<string, Date>();
  private readonly commands = new Map<string, MemoryCloudCommand>();
  private readonly commandNonces = new Map<string, Date>();

  constructor(private readonly source: {
    users: Map<string, User>;
    sessions: Map<string, Session>;
    organisations: Map<string, Organisation>;
    members: Map<string, OrganisationMember<string>>;
    isErasureEvent?(id: string): Promise<boolean>;
  }) {}

  async enqueueCloudEvent(
    event: CloudEvent,
    entity: CloudEventEntity | null,
    priority: boolean,
    maximumPending?: number
  ): Promise<CloudEvent | null> {
    const pendingRegular = [...this.outbox.values()].filter(
      (record) => !record.ackAt && !record.priority
    ).length;
    if (maximumPending !== undefined && pendingRegular >= maximumPending) {
      return null;
    }
    const stored = structuredClone(event);
    if (entity) {
      const key = `${entity.type}:${entity.id}`;
      const version = (this.entityVersions.get(key) ?? 0) + 1;
      stored.entityVersion = version;
    }
    const now = new Date(event.timestamp);
    this.outbox.set(event.id, {
      id: event.id,
      event: stored,
      priority,
      createdAt: now,
      sentAt: null,
      ackAt: null,
      attempts: 0,
      nextRetryAt: now,
      leaseUntil: null
    });
    if (entity) this.entityVersions.set(`${entity.type}:${entity.id}`, stored.entityVersion!);
    return structuredClone(stored);
  }

  async claimCloudOutbox(limit: number, now: Date, leaseUntil: Date): Promise<CloudOutboxRecord[]> {
    const eligible = [...this.outbox.values()]
      .filter((record) =>
        !record.ackAt &&
        record.nextRetryAt.getTime() <= now.getTime() &&
        (!record.leaseUntil || record.leaseUntil.getTime() <= now.getTime())
      )
      .sort((left, right) => Number(right.priority) - Number(left.priority) ||
        left.createdAt.getTime() - right.createdAt.getTime())
      .slice(0, limit);
    for (const record of eligible) {
      record.leaseUntil = new Date(leaseUntil);
      record.sentAt = new Date(now);
    }
    return structuredClone(eligible);
  }

  async acknowledgeCloudOutbox(ids: readonly string[], acknowledgedAt: Date): Promise<void> {
    for (const id of ids) {
      const record = this.outbox.get(id);
      if (!record) continue;
      record.ackAt = new Date(acknowledgedAt);
      record.leaseUntil = null;
    }
  }

  async retryCloudOutbox(id: string, attempts: number, nextRetryAt: Date): Promise<void> {
    const record = this.outbox.get(id);
    if (!record) return;
    record.attempts = attempts;
    record.nextRetryAt = new Date(nextRetryAt);
    record.leaseUntil = null;
  }

  async countCloudOutbox(includePriority = true): Promise<number> {
    return [...this.outbox.values()].filter(
      (record) => !record.ackAt && (includePriority || !record.priority)
    ).length;
  }

  async clearCloudOutbox(includePriority: boolean): Promise<number> {
    let deleted = 0;
    for (const [id, record] of this.outbox) {
      if (!includePriority && record.priority) continue;
      if (record.priority && await this.source.isErasureEvent?.(id)) continue;
      this.outbox.delete(id);
      deleted += 1;
    }
    return deleted;
  }

  async purgeCloudOutboxForUser(userId: string, email?: string | null): Promise<number> {
    let deleted = 0;
    for (const [id, record] of this.outbox) {
      if (record.ackAt || !cloudEventReferencesUser(record.event, userId, email)) continue;
      if (record.priority && await this.source.isErasureEvent?.(id)) continue;
      this.outbox.delete(id);
      deleted += 1;
    }
    return deleted;
  }

  async listCloudSnapshot(cursor: string | null, limit: number): Promise<{
    records: CloudSnapshotRecord[];
    cursor: string | null;
  }> {
    const records = [
      ...[...this.source.users.values()].map((user) => snapshotUser(user, this.version("user", user.id))),
      ...[...this.source.organisations.values()].map((org) => snapshotOrg(org, this.version("org", org.id))),
      ...[...this.source.members.values()]
        .filter((member) => member.status === "active")
        .map((member) => snapshotMember(
          member,
          this.version("org", member.organisationId)
        )),
      ...[...this.source.sessions.values()]
        .filter((session) => !session.revokedAt && session.expiresAt.getTime() > Date.now())
        .map((session) => snapshotSession(session, this.version("session", session.id)))
    ].sort((left, right) => snapshotKey(left).localeCompare(snapshotKey(right)));
    const start = cursor ? records.findIndex((record) => snapshotKey(record) > cursor) : 0;
    const page = records.slice(Math.max(0, start), Math.max(0, start) + limit);
    return {
      records: structuredClone(page),
      cursor: page.length === limit ? snapshotKey(page[page.length - 1] as CloudSnapshotRecord) : null
    };
  }

  async getCloudConfig(key: string): Promise<string | null> {
    return this.config.get(key) ?? null;
  }

  async getOrCreateCloudConfig(key: string, value: string): Promise<string> {
    const existing = this.config.get(key);
    if (existing !== undefined) return existing;
    this.config.set(key, value);
    return value;
  }

  async setCloudConfig(key: string, value: string): Promise<void> {
    this.config.set(key, value);
  }

  async consumeCloudChallengeNonce(nonce: string, expiresAt: Date): Promise<boolean> {
    if (this.challengeNonces.has(nonce)) return false;
    this.challengeNonces.set(nonce, new Date(expiresAt));
    return true;
  }

  async reserveCloudCommand(input: {
    idempotencyKey: string;
    nonce: string;
    action: CloudCommandPayload["action"];
    payloadHash: string;
    payload: CloudCommandPayload;
    now: Date;
    leaseUntil: Date;
  }): Promise<CloudCommandReservation> {
    if (this.commandNonces.has(input.nonce)) return { status: "replay" };
    const existing = this.commands.get(input.idempotencyKey);
    if (existing) {
      if (existing.action !== input.action || existing.payloadHash !== input.payloadHash) {
        return { status: "replay" };
      }
      if (existing.status !== "reserved") {
        return { status: "resolved", result: existing.result as CloudCommandResult };
      }
      if (existing.leaseUntil.getTime() > input.now.getTime()) return { status: "in_progress" };
      this.commandNonces.set(input.nonce, new Date(input.now));
      existing.nonce = input.nonce;
      existing.reservedAt = new Date(input.now);
      existing.leaseUntil = new Date(input.leaseUntil);
      return { status: "execute" };
    }
    this.commandNonces.set(input.nonce, new Date(input.now));
    this.commands.set(input.idempotencyKey, {
      idempotencyKey: input.idempotencyKey,
      nonce: input.nonce,
      action: input.action,
      payloadHash: input.payloadHash,
      payload: structuredClone(input.payload),
      status: "reserved",
      result: null,
      reservedAt: new Date(input.now),
      leaseUntil: new Date(input.leaseUntil),
      completedAt: null
    });
    return { status: "execute" };
  }

  async completeCloudCommand(
    idempotencyKey: string,
    status: "completed" | "failed",
    result: CloudCommandResult,
    completedAt: Date
  ): Promise<void> {
    const command = this.commands.get(idempotencyKey);
    if (!command) throw new Error("Cloud command reservation is missing");
    command.status = status;
    command.result = structuredClone(result);
    command.completedAt = new Date(completedAt);
  }

  async cleanupCloudState(olderThan: Date): Promise<number> {
    let deleted = 0;
    for (const [id, record] of this.outbox) {
      if (record.ackAt && record.ackAt < olderThan) {
        this.outbox.delete(id);
        deleted += 1;
      }
    }
    for (const [nonce, expiresAt] of this.challengeNonces) {
      if (expiresAt.getTime() < Date.now()) {
        this.challengeNonces.delete(nonce);
        deleted += 1;
      }
    }
    for (const [id, command] of this.commands) {
      if (
        command.completedAt && command.completedAt < olderThan ||
        command.status === "reserved" && command.leaseUntil < olderThan
      ) {
        this.commands.delete(id);
        deleted += 1;
      }
    }
    for (const [nonce, createdAt] of this.commandNonces) {
      if (createdAt < olderThan) {
        this.commandNonces.delete(nonce);
        deleted += 1;
      }
    }
    return deleted;
  }

  private version(type: CloudEventEntity["type"], id: string): number {
    return Math.max(1, this.entityVersions.get(`${type}:${id}`) ?? 1);
  }
}

function cloudEventReferencesUser(
  event: CloudEvent,
  userId: string,
  email?: string | null
): boolean {
  return event.data.userId === userId || event.data.actorId === userId ||
    (event.data.targetType === "user" && event.data.targetId === userId) ||
    event.data.recipientUserId === userId ||
    event.meta.userId === userId || Boolean(
      email && typeof event.data.inviteeEmail === "string" &&
      event.data.inviteeEmail.toLowerCase() === email.toLowerCase()
    );
}

function snapshotUser(user: User, entityVersion: number): CloudSnapshotRecord {
  return {
    type: "user",
    entityVersion,
    data: {
      userId: user.id,
      email: user.email,
      name: user.name,
      status: user.disabledAt ? "disabled" : "active",
      authMethods: [
        ...(user.passwordHash ? ["password"] : []),
        ...(user.email ? ["magic_link"] : []),
        ...(user.phone ? ["phone"] : [])
      ],
      createdAt: user.createdAt.toISOString(),
      lastLoginAt: user.lastLoginAt?.toISOString() ?? null
    }
  };
}

function snapshotOrg(org: Organisation, entityVersion: number): CloudSnapshotRecord {
  return {
    type: "org",
    entityVersion,
    data: {
      orgId: org.id,
      name: org.name,
      ownerId: org.ownerUserId,
      createdAt: org.createdAt.toISOString()
    }
  };
}

function snapshotSession(session: Session, entityVersion: number): CloudSnapshotRecord {
  return {
    type: "session",
    entityVersion,
    data: {
      sessionId: session.id,
      userId: session.userId,
      createdAt: session.createdAt.toISOString(),
      expiresAt: session.expiresAt.toISOString(),
      ip: session.ipAddress,
      userAgent: session.userAgent,
      authMethods: [...session.authenticationMethods]
    }
  };
}

function snapshotMember(
  member: OrganisationMember<string>,
  entityVersion: number
): CloudSnapshotRecord {
  return {
    type: "member",
    entityVersion,
    data: {
      orgId: member.organisationId,
      userId: member.userId,
      role: member.role,
      createdAt: (member.joinedAt ?? member.createdAt).toISOString()
    }
  };
}

function snapshotKey(record: CloudSnapshotRecord): string {
  const id = record.type === "member"
    ? `${String(record.data.orgId)}:${String(record.data.userId)}`
    : record.data.userId ?? record.data.orgId ?? record.data.sessionId;
  return `${record.type}:${String(id)}`;
}
