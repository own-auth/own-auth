import { AuthError } from "./errors.js";
import { matchesErasureIdentity } from "./user-erasure-subject.js";
import {
  erasureStatement, mapUserErasure, prepareErasureSql,
  type ErasureSqlDatabase, type ErasureSqlStatement
} from "./user-erasure-sql.js";
import type { AtomicUserErasureInput, StoredUserErasure, UserErasureStorage } from "./user-erasure.js";
import { cloudErasureSubject, isUserErasureProtected, requireResumableUserErasure } from "./user-erasure.js";

export class SqlUserErasureStorage implements UserErasureStorage {
  constructor(
    protected readonly database: ErasureSqlDatabase,
    private readonly eraseInTransaction?: (input: AtomicUserErasureInput) => Promise<void>
  ) {}

  async eraseAtomically(input: AtomicUserErasureInput): Promise<StoredUserErasure> {
    const previous = await this.get(input.operationId);
    if (previous) return requireResumableUserErasure(previous, input.userId);
    const pending = await this.findByUser(input.userId);
    if (pending) return pending;
    try {
      if (this.eraseInTransaction) await this.eraseInTransaction(input);
      else await this.database.atomic(await prepareErasureSql(this.database, input));
    } catch (error) {
      const joined = await this.get(input.operationId) ?? await this.findByUser(input.userId);
      if (joined) return requireResumableUserErasure(joined, input.userId);
      throw error;
    }
    const record = await this.get(input.operationId) ?? await this.findByUser(input.userId);
    if (!record) throw new AuthError("erasure_operation_conflict", "The account changed. Retry erasure.", 409);
    return requireResumableUserErasure(record, input.userId);
  }

  async get(operationId: string): Promise<StoredUserErasure | null> {
    const row = (await this.read("select * from own_auth_user_erasures where operation_id = ?", [operationId]))[0];
    return row ? mapUserErasure(row) : null;
  }

  async findByUser(userId: string): Promise<StoredUserErasure | null> {
    const row = (await this.read("select * from own_auth_user_erasures where user_id = ?", [userId]))[0];
    return row ? mapUserErasure(row) : null;
  }

  async settleStore(operationId: string, store: string): Promise<void> {
    const pending = this.database.dialect === "postgres"
      ? "pending_stores - ?" : "coalesce((select json_group_array(value) from json_each(pending_stores) where value <> ?), '[]')";
    await this.write(`update own_auth_user_erasures set pending_stores = ${pending} where operation_id = ?`, [store, operationId]);
  }

  async settleCloud(eventId: string): Promise<void> {
    const pg = this.database.dialect === "postgres";
    const remaining = pg
      ? "coalesce((select jsonb_agg(value) from jsonb_array_elements(pending_cloud_events) value where value #>> '{}' <> ?), '[]'::jsonb)"
      : "coalesce((select json_group_array(value) from json_each(pending_cloud_events) where value <> ?), '[]')";
    await this.database.atomic([
      erasureStatement(this.database, `update own_auth_user_erasures set pending_cloud_events = ${remaining} where ${this.cloudEventMatch()}`, [eventId, eventId, eventId]),
      erasureStatement(this.database, `update own_auth_user_erasures set cloud_complete = ${pg ? "true" : "1"} where cloud_event_id is not null and ${pg ? "pending_cloud_events = '[]'::jsonb" : "pending_cloud_events = '[]'"}`),
      erasureStatement(this.database, "delete from own_auth_cloud_outbox where id = ?", [eventId])
    ]);
  }

  async isCloudErasure(eventId: string): Promise<boolean> {
    return (await this.read(`select operation_id from own_auth_user_erasures where ${this.cloudEventMatch()}`, [eventId, eventId])).length > 0;
  }

  private cloudEventMatch(): string {
    return "(cloud_event_id = ? or exists (select 1 from " +
      (this.database.dialect === "postgres" ? "jsonb_array_elements_text(pending_cloud_events)" : "json_each(pending_cloud_events)") +
      " e where " + (this.database.dialect === "postgres" ? "e" : "e.value") + " = ?))";
  }

  async finish(operationId: string, now: number): Promise<StoredUserErasure | null> {
    const record = await this.get(operationId);
    if (!record || !record.subject || record.pendingStores.length || record.protectedUntil > now) return record;
    const subject = JSON.stringify(cloudErasureSubject(record.subject.userId));
    const complete = this.database.dialect === "postgres" ? "(cloud_event_id is null or cloud_complete)" : "(cloud_event_id is null or cloud_complete = 1)";
    const updates: ErasureSqlStatement[] = [];
    for (const id of record.subject.references) updates.push(erasureStatement(this.database,
      "delete from own_auth_cloud_entity_versions where entity_id = ?", [id]));
    updates.push(erasureStatement(this.database,
      `update own_auth_user_erasures set subject = case when ${complete} then null else ${this.database.dialect === "postgres" ? "?::jsonb" : "?"} end, user_id = case when ${complete} then null else user_id end, completed_at_ms = case when ${complete} then ${this.database.dialect === "postgres" ? "?::bigint" : "?"} else null end where operation_id = ? and completed_at_ms is null and subject is not null and protected_until_ms <= ? and ` +
      (this.database.dialect === "postgres" ? "pending_stores = '[]'::jsonb" : "pending_stores = '[]'"),
      [subject, now, operationId, now]));
    await this.database.atomic(updates);
    return this.get(operationId);
  }

  async assertIdentityAllowed(identity: Parameters<UserErasureStorage["assertIdentityAllowed"]>[0]): Promise<void> {
    const records = await this.read("select * from own_auth_user_erasures where subject is not null");
    for (const row of records) {
      const record = mapUserErasure(row);
      if (isUserErasureProtected(record) && matchesErasureIdentity(identity, record.subject)) {
        throw new AuthError("invalid_credentials", "Authentication request is no longer valid", 401);
      }
    }
  }

  async authorizeWebhookSend(deliveryId: string, leaseToken: string): Promise<boolean> {
    const statement = erasureStatement(this.database,
      "update own_auth_webhook_deliveries set send_started_at = ? where id = ? and lease_token = ? and status = 'processing' and exists " +
      "(select 1 from own_auth_webhook_events e where e.id = own_auth_webhook_deliveries.event_id) returning id",
      [this.database.dialect === "postgres" ? new Date() : Date.now(), deliveryId, leaseToken]);
    return (await this.database.read(statement.sql, statement.values)).length > 0;
  }

  protected read(sql: string, values: unknown[] = []): Promise<Record<string, unknown>[]> {
    const statement = erasureStatement(this.database, sql, values);
    return this.database.read(statement.sql, statement.values);
  }

  private write(sql: string, values: unknown[]): Promise<void> {
    return this.database.atomic([erasureStatement(this.database, sql, values)]);
  }
}
