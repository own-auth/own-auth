import type {
  CloudCommandPayload,
  CloudCommandResult,
  CloudEvent,
  CloudEventEntity
} from "../cloud-types.js";
import type {
  CloudCommandReservation,
  CloudOutboxRecord,
  CloudSnapshotRecord,
  CloudStorage
} from "../cloud-storage.js";
import type { DatabaseRow } from "../database-types.js";
import { D1StorageBase } from "./d1-storage-base.js";
import type { D1DatabaseLike } from "./d1-types.js";

export class D1CloudStorage extends D1StorageBase implements CloudStorage {
  readonly durable = true;

  constructor(db: D1DatabaseLike) {
    super(db);
  }

  async enqueueCloudEvent(
    event: CloudEvent,
    entity: CloudEventEntity | null,
    priority: boolean,
    maximumPending?: number
  ): Promise<CloudEvent | null> {
    if (entity) {
      const results = await this.db.batch<DatabaseRow>([
        this.prepare(
          `insert into own_auth_cloud_entity_versions (entity_type, entity_id, version)
           select ?1, ?2, 1 where ?3 is null or (
             select count(*) from own_auth_cloud_outbox
             where ack_at is null and priority = 0
           ) < ?3
           on conflict (entity_type, entity_id) do update set version = version + 1
           where ?3 is null or (
             select count(*) from own_auth_cloud_outbox
             where ack_at is null and priority = 0
           ) < ?3`,
          [entity.type, entity.id, maximumPending ?? null]
        ),
        this.prepare(
          `insert into own_auth_cloud_outbox
            (id, event_type, payload, entity_version, priority, created_at, next_retry_at)
           select ?1, ?2, ?3,
             (select version from own_auth_cloud_entity_versions where entity_type = ?4 and entity_id = ?5),
             ?6, ?7, ?7 where ?8 is null or (
               select count(*) from own_auth_cloud_outbox
               where ack_at is null and priority = 0
             ) < ?8`,
          [
            event.id,
            event.type,
            JSON.stringify(event),
            entity.type,
            entity.id,
            priority,
            new Date(event.timestamp),
            maximumPending ?? null
          ]
        )
      ]);
      assertBatch(results);
      const version = await this.prepare(
        "select entity_version as version from own_auth_cloud_outbox where id = ?1",
        [event.id]
      ).first<{ version: number }>();
      if (!version) return null;
      return { ...event, entityVersion: Number(version?.version ?? 1) };
    }
    const inserted = await this.prepare(
      `insert into own_auth_cloud_outbox
        (id, event_type, payload, entity_version, priority, created_at, next_retry_at)
       select ?1, ?2, ?3, null, ?4, ?5, ?5 where ?6 is null or (
         select count(*) from own_auth_cloud_outbox
         where ack_at is null and priority = 0
       ) < ?6 returning id`,
      [
        event.id,
        event.type,
        JSON.stringify(event),
        priority,
        new Date(event.timestamp),
        maximumPending ?? null
      ]
    ).all<DatabaseRow>();
    if (!(inserted.results?.length)) return null;
    return event;
  }

  async claimCloudOutbox(limit: number, now: Date, leaseUntil: Date): Promise<CloudOutboxRecord[]> {
    const result = await this.prepare(
      `update own_auth_cloud_outbox set sent_at = ?1, lease_until = ?2
       where id in (
         select id from own_auth_cloud_outbox
         where ack_at is null and next_retry_at <= ?1
           and (lease_until is null or lease_until <= ?1)
         order by priority desc, created_at asc limit ?3
       ) returning *`,
      [now, leaseUntil, limit]
    ).all<DatabaseRow>();
    return (result.results ?? []).map(mapD1Outbox);
  }

  async acknowledgeCloudOutbox(ids: readonly string[], acknowledgedAt: Date): Promise<void> {
    if (ids.length === 0) return;
    await this.prepare(
      `update own_auth_cloud_outbox set ack_at = ?1, lease_until = null
       where id in (${ids.map((_, index) => `?${index + 2}`).join(", ")})`,
      [acknowledgedAt, ...ids]
    ).run();
  }

  async retryCloudOutbox(id: string, attempts: number, nextRetryAt: Date): Promise<void> {
    await this.prepare(
      `update own_auth_cloud_outbox set attempts = ?2, next_retry_at = ?3, lease_until = null
       where id = ?1`,
      [id, attempts, nextRetryAt]
    ).run();
  }

  async countCloudOutbox(includePriority = true): Promise<number> {
    const row = await this.prepare(
      `select count(*) as count from own_auth_cloud_outbox
       where ack_at is null ${includePriority ? "" : "and priority = 0"}`
    ).first<{ count: number }>();
    return Number(row?.count ?? 0);
  }

  async clearCloudOutbox(includePriority: boolean): Promise<number> {
    const result = await this.prepare(
      `delete from own_auth_cloud_outbox ${includePriority ? "" : "where priority = 0"} returning id`
    ).all<DatabaseRow>();
    return result.results?.length ?? 0;
  }

  async purgeCloudOutboxForUser(userId: string, email?: string | null): Promise<number> {
    const result = await this.prepare(
      `delete from own_auth_cloud_outbox
       where ack_at is null and (
         json_extract(payload, '$.data.userId') = ?1 or
         json_extract(payload, '$.data.actorId') = ?1 or
         (json_extract(payload, '$.data.targetType') = 'user' and
          json_extract(payload, '$.data.targetId') = ?1) or
         json_extract(payload, '$.data.recipientUserId') = ?1 or
         json_extract(payload, '$.meta.userId') = ?1 or
         (?2 is not null and lower(json_extract(payload, '$.data.inviteeEmail')) = lower(?2))
       )
       returning id`,
      [userId, email ?? null]
    ).all<DatabaseRow>();
    return result.results?.length ?? 0;
  }

  async listCloudSnapshot(cursor: string | null, limit: number): Promise<{
    records: CloudSnapshotRecord[];
    cursor: string | null;
  }> {
    const result = await this.prepare(
      `select kind, entity_id, entity_version, data from (
         select 'user' as kind, u.id as entity_id, coalesce(v.version, 1) as entity_version,
           json_object(
             'userId', u.id, 'email', u.email, 'name', u.name,
             'status', case when u.disabled_at is null then 'active' else 'disabled' end,
             'authMethods', json((
               select coalesce(json_group_array(method), '[]')
               from (
                 select method from (
                   select 'password' as method where u.password_hash is not null
                   union select 'magic_link' where u.email is not null
                   union select 'phone' where u.phone is not null
                   union select a.provider from own_auth_accounts a where a.user_id = u.id
                   union select 'totp' where exists (
                     select 1 from own_auth_mfa_factors f
                     where f.user_id = u.id and f.factor_type = 'totp' and f.status = 'active'
                   )
                   union select 'passkey' where exists (
                     select 1 from own_auth_passkeys p where p.user_id = u.id
                   )
                 ) unordered_methods order by method
               ) methods
             )),
             'createdAt', u.created_at, 'lastLoginAt', u.last_login_at
           ) as data
         from own_auth_users u left join own_auth_cloud_entity_versions v
           on v.entity_type = 'user' and v.entity_id = u.id
         union all
         select 'org', o.id, coalesce(v.version, 1),
           json_object(
             'orgId', o.id, 'name', o.name, 'ownerId', o.owner_user_id,
             'createdAt', o.created_at
           )
         from own_auth_organisations o left join own_auth_cloud_entity_versions v
           on v.entity_type = 'org' and v.entity_id = o.id
         union all
         select 'member', m.organisation_id || ':' || m.user_id,
           coalesce(v.version, 1),
           json_object(
             'orgId', m.organisation_id, 'userId', m.user_id,
             'role', m.role, 'createdAt', m.joined_at
           )
         from own_auth_organisation_members m
         left join own_auth_cloud_entity_versions v
           on v.entity_type = 'org' and v.entity_id = m.organisation_id
         where m.status = 'active'
         union all
         select 'session', s.id, coalesce(v.version, 1),
           json_object(
             'sessionId', s.id, 'userId', s.user_id, 'createdAt', s.created_at,
             'expiresAt', s.expires_at, 'ip', s.ip_address, 'userAgent', s.user_agent,
             'authMethods', json(s.authentication_methods)
           )
         from own_auth_sessions s left join own_auth_cloud_entity_versions v
           on v.entity_type = 'session' and v.entity_id = s.id
         where s.revoked_at is null and s.expires_at > ?1
       ) where (?2 is null or kind || ':' || entity_id > ?2)
       order by kind || ':' || entity_id asc limit ?3`,
      [Date.now(), cursor, limit]
    ).all<{ kind: CloudSnapshotRecord["type"]; entity_id: string; entity_version: number; data: string }>();
    const rows = result.results ?? [];
    const records = rows.map((row) => ({
      type: row.kind,
      entityVersion: Number(row.entity_version),
      data: normalizeSnapshotData(row.kind, JSON.parse(row.data) as Record<string, unknown>)
    }));
    const last = rows[rows.length - 1];
    return { records, cursor: rows.length === limit && last ? `${last.kind}:${last.entity_id}` : null };
  }

  async getCloudConfig(key: string): Promise<string | null> {
    const row = await this.prepare(
      "select value from own_auth_cloud_config where key = ?1",
      [key]
    ).first<{ value: string }>();
    return row?.value ?? null;
  }

  async getOrCreateCloudConfig(key: string, value: string): Promise<string> {
    const result = await this.prepare(
      `insert into own_auth_cloud_config (key, value) values (?1, ?2)
       on conflict (key) do update set value = own_auth_cloud_config.value
       returning value`,
      [key, value]
    ).first<{ value: string }>();
    return result?.value ?? value;
  }

  async setCloudConfig(key: string, value: string): Promise<void> {
    await this.prepare(
      `insert into own_auth_cloud_config (key, value) values (?1, ?2)
       on conflict (key) do update set value = excluded.value`,
      [key, value]
    ).run();
  }

  async consumeCloudChallengeNonce(nonce: string, expiresAt: Date): Promise<boolean> {
    const result = await this.prepare(
      `insert into own_auth_cloud_challenge_nonces (nonce, expires_at)
       values (?1, ?2) on conflict (nonce) do nothing returning nonce`,
      [nonce, expiresAt]
    ).all<DatabaseRow>();
    return (result.results?.length ?? 0) === 1;
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
    try {
      const inserted = await this.prepare(
        `insert into own_auth_cloud_commands
          (idempotency_key, nonce, action, payload_hash, payload, status, reserved_at, lease_until)
         values (?1, ?2, ?3, ?4, ?5, 'reserved', ?6, ?7)
         on conflict (idempotency_key) do nothing returning idempotency_key`,
        [
          input.idempotencyKey,
          input.nonce,
          input.action,
          input.payloadHash,
          JSON.stringify(input.payload),
          input.now,
          input.leaseUntil
        ]
      ).all<DatabaseRow>();
      if ((inserted.results?.length ?? 0) === 1) return { status: "execute" };
    } catch (error) {
      if (isD1UniqueError(error)) return { status: "replay" };
      throw error;
    }
    const existing = await this.prepare(
      `select action, payload_hash, status, result, lease_until
       from own_auth_cloud_commands where idempotency_key = ?1`,
      [input.idempotencyKey]
    ).first<{
      action: CloudCommandPayload["action"];
      payload_hash: string;
      status: "reserved" | "completed" | "failed";
      result: string | null;
      lease_until: number;
    }>();
    if (!existing || existing.action !== input.action || existing.payload_hash !== input.payloadHash) {
      return { status: "replay" };
    }
    if (existing.status !== "reserved") {
      return { status: "resolved", result: JSON.parse(existing.result ?? "null") as CloudCommandResult };
    }
    if (Number(existing.lease_until) > input.now.getTime()) return { status: "in_progress" };
    try {
      const reclaimed = await this.prepare(
        `update own_auth_cloud_commands set nonce = ?2, reserved_at = ?3, lease_until = ?4
         where idempotency_key = ?1 and status = 'reserved' and lease_until <= ?3
         returning idempotency_key`,
        [input.idempotencyKey, input.nonce, input.now, input.leaseUntil]
      ).all<DatabaseRow>();
      return (reclaimed.results?.length ?? 0) === 1
        ? { status: "execute" }
        : { status: "in_progress" };
    } catch (error) {
      if (isD1UniqueError(error)) return { status: "replay" };
      throw error;
    }
  }

  async completeCloudCommand(
    idempotencyKey: string,
    status: "completed" | "failed",
    result: CloudCommandResult,
    completedAt: Date
  ): Promise<void> {
    await this.prepare(
      `update own_auth_cloud_commands set status = ?2, result = ?3, completed_at = ?4
       where idempotency_key = ?1 and status = 'reserved'`,
      [idempotencyKey, status, JSON.stringify(result), completedAt]
    ).run();
  }

  async cleanupCloudState(olderThan: Date): Promise<number> {
    const results = await this.db.batch<DatabaseRow>([
      this.prepare("delete from own_auth_cloud_outbox where ack_at < ?1 returning id", [olderThan]),
      this.prepare(
        `delete from own_auth_cloud_commands
         where completed_at < ?1 or (status = 'reserved' and lease_until < ?1)
         returning idempotency_key`,
        [olderThan]
      ),
      this.prepare(
        "delete from own_auth_cloud_challenge_nonces where expires_at < ?1 returning nonce",
        [new Date()]
      )
    ]);
    return results.reduce((count, result) => count + (result.results?.length ?? 0), 0);
  }
}

function normalizeSnapshotData(
  type: CloudSnapshotRecord["type"],
  data: Record<string, unknown>
): Record<string, unknown> {
  const dateFields = type === "session"
    ? ["createdAt", "expiresAt"]
    : type === "user" ? ["createdAt", "lastLoginAt"] : ["createdAt"];
  for (const key of dateFields) {
    if (typeof data[key] === "number") data[key] = new Date(data[key]).toISOString();
  }
  if (Array.isArray(data.authMethods)) {
    data.authMethods = data.authMethods.filter((method): method is string => typeof method === "string");
  }
  return data;
}

function mapD1Outbox(row: DatabaseRow): CloudOutboxRecord {
  const event = JSON.parse(String(row.payload)) as CloudEvent;
  if (row.entity_version !== null && row.entity_version !== undefined) {
    event.entityVersion = Number(row.entity_version);
  }
  return {
    id: String(row.id),
    event,
    priority: Boolean(row.priority),
    createdAt: new Date(Number(row.created_at)),
    sentAt: row.sent_at === null ? null : new Date(Number(row.sent_at)),
    ackAt: row.ack_at === null ? null : new Date(Number(row.ack_at)),
    attempts: Number(row.attempts),
    nextRetryAt: new Date(Number(row.next_retry_at)),
    leaseUntil: row.lease_until === null ? null : new Date(Number(row.lease_until))
  };
}

function assertBatch(results: { success?: boolean; error?: string }[]): void {
  const failure = results.find((result) => result.success === false || result.error);
  if (failure) throw new Error(failure.error ?? "D1 Cloud outbox batch failed");
}

function isD1UniqueError(error: unknown): boolean {
  return error instanceof Error && /unique constraint|constraint failed/i.test(error.message);
}
