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
import type { PostgresQueryable } from "./postgres-types.js";

interface CloudOutboxRow {
  id: string;
  payload: CloudEvent;
  entity_version: number | null;
  priority: boolean;
  created_at: Date | string;
  sent_at: Date | string | null;
  ack_at: Date | string | null;
  attempts: number;
  next_retry_at: Date | string;
  lease_until: Date | string | null;
}

interface CommandRow {
  action: CloudCommandPayload["action"];
  payload_hash: string;
  status: "reserved" | "completed" | "failed";
  result: CloudCommandResult | null;
  lease_until: Date | string;
}

export class PostgresCloudStorage implements CloudStorage {
  readonly durable = true;

  constructor(private readonly db: PostgresQueryable) {}

  async enqueueCloudEvent(
    event: CloudEvent,
    entity: CloudEventEntity | null,
    priority: boolean,
    maximumPending?: number
  ): Promise<CloudEvent | null> {
    const result = await this.db.query<{
      inserted: boolean;
      entity_version: number | null;
    }>(
      `select inserted, entity_version
       from own_auth_enqueue_cloud_event($1, $2, $3::jsonb, $4, $5, $6, $7, $8)`,
      [
        event.id,
        event.type,
        JSON.stringify(event),
        entity?.type ?? null,
        entity?.id ?? null,
        priority,
        event.timestamp,
        maximumPending ?? null
      ]
    );
    if (!result.rows[0]?.inserted) return null;
    const version = result.rows[0].entity_version;
    return version ? { ...event, entityVersion: version } : event;
  }

  async claimCloudOutbox(limit: number, now: Date, leaseUntil: Date): Promise<CloudOutboxRecord[]> {
    const result = await this.db.query<CloudOutboxRow>(
      `with candidates as (
         select id from own_auth_cloud_outbox
         where ack_at is null and next_retry_at <= $1
           and (lease_until is null or lease_until <= $1)
         order by priority desc, created_at asc
         for update skip locked
         limit $2
       )
       update own_auth_cloud_outbox as outbox
       set sent_at = $1, lease_until = $3
       from candidates where outbox.id = candidates.id
       returning outbox.*`,
      [now, limit, leaseUntil]
    );
    return result.rows.map(mapOutboxRow);
  }

  async acknowledgeCloudOutbox(ids: readonly string[], acknowledgedAt: Date): Promise<void> {
    if (ids.length === 0) return;
    await this.db.query(
      "update own_auth_cloud_outbox set ack_at = $2, lease_until = null where id = any($1::text[])",
      [ids, acknowledgedAt]
    );
  }

  async retryCloudOutbox(id: string, attempts: number, nextRetryAt: Date): Promise<void> {
    await this.db.query(
      `update own_auth_cloud_outbox
       set attempts = $2, next_retry_at = $3, lease_until = null where id = $1`,
      [id, attempts, nextRetryAt]
    );
  }

  async countCloudOutbox(includePriority = true): Promise<number> {
    const result = await this.db.query<{ count: string }>(
      `select count(*)::text as count from own_auth_cloud_outbox
       where ack_at is null ${includePriority ? "" : "and priority = false"}`
    );
    return Number(result.rows[0]?.count ?? 0);
  }

  async clearCloudOutbox(includePriority: boolean): Promise<number> {
    const result = await this.db.query<{ id: string }>(
      `delete from own_auth_cloud_outbox where ${includePriority ? "true" : "priority = false"} and not ${pendingErasureCloudEventSql("postgres")} returning id`
    );
    return result.rows.length;
  }

  async purgeCloudOutboxForUser(userId: string, email?: string | null): Promise<number> {
    const result = await this.db.query<{ id: string }>(
      `delete from own_auth_cloud_outbox
       where ack_at is null and not ${pendingErasureCloudEventSql("postgres")} and (
         payload #>> '{data,userId}' = $1 or
         payload #>> '{data,actorId}' = $1 or
         (payload #>> '{data,targetType}' = 'user' and payload #>> '{data,targetId}' = $1) or
         payload #>> '{data,recipientUserId}' = $1 or
         payload #>> '{meta,userId}' = $1 or
         ($2::text is not null and lower(payload #>> '{data,inviteeEmail}') = lower($2))
       )
       returning id`,
      [userId, email ?? null]
    );
    return result.rows.length;
  }

  async listCloudSnapshot(cursor: string | null, limit: number): Promise<{
    records: CloudSnapshotRecord[];
    cursor: string | null;
  }> {
    const result = await this.db.query<{
      kind: CloudSnapshotRecord["type"];
      entity_id: string;
      entity_version: number;
      data: Record<string, unknown>;
    }>(
      `with snapshot as (
         select 'user'::text as kind, u.id as entity_id,
           coalesce(v.version, 1) as entity_version,
           jsonb_build_object(
             'userId', u.id, 'email', u.email, 'name', u.name,
             'status', case when u.disabled_at is null then 'active' else 'disabled' end,
             'authMethods', (
               select to_jsonb(coalesce(array_agg(method order by method), array[]::text[]))
               from (
                 select 'password'::text as method where u.password_hash is not null
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
               ) methods
             ),
             'createdAt', u.created_at, 'lastLoginAt', u.last_login_at
           ) as data
         from own_auth_users u left join own_auth_cloud_entity_versions v
           on v.entity_type = 'user' and v.entity_id = u.id
         union all
         select 'org', o.id, coalesce(v.version, 1),
           jsonb_build_object(
             'orgId', o.id, 'name', o.name, 'ownerId', o.owner_user_id,
             'createdAt', o.created_at
           )
         from own_auth_organisations o left join own_auth_cloud_entity_versions v
           on v.entity_type = 'org' and v.entity_id = o.id
         union all
         select 'member', m.organisation_id || ':' || m.user_id,
           coalesce(v.version, 1),
           jsonb_build_object(
             'orgId', m.organisation_id, 'userId', m.user_id,
             'role', m.role, 'createdAt', m.joined_at
           )
         from own_auth_organisation_members m
         left join own_auth_cloud_entity_versions v
           on v.entity_type = 'org' and v.entity_id = m.organisation_id
         where m.status = 'active'
         union all
         select 'session', s.id, coalesce(v.version, 1),
           jsonb_build_object(
             'sessionId', s.id, 'userId', s.user_id, 'createdAt', s.created_at,
             'expiresAt', s.expires_at, 'ip', s.ip_address, 'userAgent', s.user_agent,
             'authMethods', to_jsonb(s.authentication_methods)
           )
         from own_auth_sessions s left join own_auth_cloud_entity_versions v
           on v.entity_type = 'session' and v.entity_id = s.id
         where s.revoked_at is null and s.expires_at > now()
       )
       select kind, entity_id, entity_version, data from snapshot
       where ($1::text is null or kind || ':' || entity_id > $1)
       order by kind || ':' || entity_id asc limit $2`,
      [cursor, limit]
    );
    const records = result.rows.map((row) => ({
      type: row.kind,
      entityVersion: row.entity_version,
      data: row.data
    }));
    const last = result.rows[result.rows.length - 1];
    return { records, cursor: result.rows.length === limit && last ? `${last.kind}:${last.entity_id}` : null };
  }

  async getCloudConfig(key: string): Promise<string | null> {
    const result = await this.db.query<{ value: string }>(
      "select value from own_auth_cloud_config where key = $1",
      [key]
    );
    return result.rows[0]?.value ?? null;
  }

  async getOrCreateCloudConfig(key: string, value: string): Promise<string> {
    const result = await this.db.query<{ value: string }>(
      `insert into own_auth_cloud_config (key, value) values ($1, $2)
       on conflict (key) do update set value = own_auth_cloud_config.value
       returning value`,
      [key, value]
    );
    return result.rows[0]?.value ?? value;
  }

  async setCloudConfig(key: string, value: string): Promise<void> {
    await this.db.query(
      `insert into own_auth_cloud_config (key, value) values ($1, $2)
       on conflict (key) do update set value = excluded.value`,
      [key, value]
    );
  }

  async consumeCloudChallengeNonce(nonce: string, expiresAt: Date): Promise<boolean> {
    const result = await this.db.query<{ nonce: string }>(
      `insert into own_auth_cloud_challenge_nonces (nonce, expires_at)
       values ($1, $2) on conflict (nonce) do nothing returning nonce`,
      [nonce, expiresAt]
    );
    return result.rows.length === 1;
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
      const inserted = await this.db.query<{ idempotency_key: string }>(
        `insert into own_auth_cloud_commands
          (idempotency_key, nonce, action, payload_hash, payload, status, reserved_at, lease_until)
         values ($1, $2, $3, $4, $5::jsonb, 'reserved', $6, $7)
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
      );
      if (inserted.rows.length === 1) return { status: "execute" };
    } catch (error) {
      if (isUniqueViolation(error)) return { status: "replay" };
      throw error;
    }
    const existing = await this.command(input.idempotencyKey);
    if (!existing || existing.action !== input.action || existing.payload_hash !== input.payloadHash) {
      return { status: "replay" };
    }
    if (existing.status !== "reserved") {
      return { status: "resolved", result: existing.result as CloudCommandResult };
    }
    if (toDate(existing.lease_until).getTime() > input.now.getTime()) {
      return { status: "in_progress" };
    }
    try {
      const reclaimed = await this.db.query<{ idempotency_key: string }>(
        `update own_auth_cloud_commands set nonce = $2, reserved_at = $3, lease_until = $4
         where idempotency_key = $1 and status = 'reserved' and lease_until <= $3
         returning idempotency_key`,
        [input.idempotencyKey, input.nonce, input.now, input.leaseUntil]
      );
      return reclaimed.rows.length === 1 ? { status: "execute" } : { status: "in_progress" };
    } catch (error) {
      if (isUniqueViolation(error)) return { status: "replay" };
      throw error;
    }
  }

  async completeCloudCommand(
    idempotencyKey: string,
    status: "completed" | "failed",
    result: CloudCommandResult,
    completedAt: Date
  ): Promise<void> {
    await this.db.query(
      `update own_auth_cloud_commands set status = $2, result = $3::jsonb, completed_at = $4
       where idempotency_key = $1 and status = 'reserved'`,
      [idempotencyKey, status, JSON.stringify(result), completedAt]
    );
  }

  async cleanupCloudState(olderThan: Date): Promise<number> {
    const result = await this.db.query<{ count: string }>(
      `with deleted_outbox as (
         delete from own_auth_cloud_outbox where ack_at < $1 returning 1
       ), deleted_commands as (
         delete from own_auth_cloud_commands
         where completed_at < $1 or (status = 'reserved' and lease_until < $1) returning 1
       ), deleted_nonces as (
         delete from own_auth_cloud_challenge_nonces where expires_at < now() returning 1
       ) select (
         (select count(*) from deleted_outbox) +
         (select count(*) from deleted_commands) +
         (select count(*) from deleted_nonces)
       )::text as count`,
      [olderThan]
    );
    return Number(result.rows[0]?.count ?? 0);
  }

  private async command(idempotencyKey: string): Promise<CommandRow | null> {
    const result = await this.db.query<CommandRow>(
      `select action, payload_hash, status, result, lease_until
       from own_auth_cloud_commands where idempotency_key = $1`,
      [idempotencyKey]
    );
    return result.rows[0] ?? null;
  }
}

function mapOutboxRow(row: CloudOutboxRow): CloudOutboxRecord {
  const event = { ...row.payload };
  if (row.entity_version) event.entityVersion = row.entity_version;
  return {
    id: row.id,
    event,
    priority: row.priority,
    createdAt: toDate(row.created_at),
    sentAt: nullableDate(row.sent_at),
    ackAt: nullableDate(row.ack_at),
    attempts: row.attempts,
    nextRetryAt: toDate(row.next_retry_at),
    leaseUntil: nullableDate(row.lease_until)
  };
}

function toDate(value: Date | string): Date {
  return value instanceof Date ? value : new Date(value);
}

function nullableDate(value: Date | string | null): Date | null {
  return value === null ? null : toDate(value);
}

function isUniqueViolation(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "code" in error &&
    (error as { code?: unknown }).code === "23505");
}
import { pendingErasureCloudEventSql } from "../user-erasure-sql-match.js";
