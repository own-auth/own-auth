import type { DatabaseRow } from "../database-types.js";
import type { AuditEvent } from "../types.js";
import {
  mapStoredWebhookEvent,
  mapWebhookAttempt,
  mapWebhookDelivery
} from "../webhook-database-mappers.js";
import {
  webhookAttemptReturning,
  webhookDeliveryReturning,
  webhookDeliverySelection,
  webhookEventReturning
} from "../webhook-database-schema.js";
import type {
  ClaimWebhookDeliveriesInput,
  ClaimedWebhookDelivery,
  ListedWebhookDelivery,
  SettleWebhookDeliveryInput,
  WebhookDeliverySeed,
  WebhookStorage
} from "../webhook-storage.js";
import type {
  ListWebhookDeliveriesInput,
  StoredWebhookEvent,
  WebhookAttempt,
  WebhookDelivery
} from "../webhook-types.js";
import type { D1DatabaseLike, D1PreparedStatementLike } from "./d1-types.js";
import { toD1Value } from "./d1-values.js";

export class D1WebhookStorage implements WebhookStorage {
  constructor(private readonly db: D1DatabaseLike) {}

  async recordAuditEventWithWebhooks(
    audit: AuditEvent,
    event: StoredWebhookEvent,
    deliveries: readonly WebhookDeliverySeed[]
  ): Promise<void> {
    const statements = [
      this.statement(
        `insert into own_auth_audit_events (
           id, event_type, actor_user_id, target_user_id, organisation_id,
           api_key_id, ip_address, user_agent, metadata, created_at
         ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
        [
          audit.id,
          audit.eventType,
          audit.actorUserId,
          audit.targetUserId,
          audit.organisationId,
          audit.apiKeyId,
          audit.ipAddress,
          audit.userAgent,
          JSON.stringify(audit.metadata),
          audit.createdAt.getTime()
        ]
      ),
      this.statement(
        `insert into own_auth_webhook_events (id, event_type, version, payload, created_at)
         values (?1, ?2, ?3, ?4, ?5)`,
        [event.id, event.type, event.version, event.payload, event.createdAt.getTime()]
      ),
      ...deliveries.map((delivery) => this.statement(
        `insert into own_auth_webhook_deliveries (
           id, event_id, endpoint_id, endpoint_url, status, attempts_in_cycle,
           total_attempts, next_attempt_at, created_at, updated_at
         ) values (?1, ?2, ?3, ?4, 'pending', 0, 0, ?5, ?5, ?5)`,
        [
          delivery.id,
          event.id,
          delivery.endpointId,
          delivery.url,
          delivery.createdAt.getTime()
        ]
      ))
    ];
    await this.db.batch(statements);
  }

  async claimWebhookDeliveries(
    input: ClaimWebhookDeliveriesInput
  ): Promise<ClaimedWebhookDelivery[]> {
    const claimed: ClaimedWebhookDelivery[] = [];
    for (let index = 0; index < input.limit; index += 1) {
      const row = await this.statement(
        `update own_auth_webhook_deliveries
         set status = 'processing', lease_token = ?2, lease_expires_at = ?3, updated_at = ?1
         where id = (
           select id from own_auth_webhook_deliveries
           where (status = 'pending' and next_attempt_at <= ?1)
              or (status = 'processing' and lease_expires_at <= ?1)
           order by next_attempt_at asc, created_at asc limit 1
         ) returning ${webhookDeliveryReturning}`,
        [input.now.getTime(), input.leaseToken, input.leaseExpiresAt.getTime()]
      ).first<DatabaseRow>();
      if (!row) break;
      const delivery = mapWebhookDelivery(row);
      const eventRow = await this.statement(
        `select ${webhookEventReturning} from own_auth_webhook_events where id = ?1`,
        [delivery.eventId]
      ).first<DatabaseRow>();
      if (!eventRow) throw new Error("Claimed webhook delivery has no event");
      claimed.push({ delivery, event: mapStoredWebhookEvent(eventRow) });
    }
    return claimed;
  }

  async settleWebhookDelivery(input: SettleWebhookDeliveryInput): Promise<boolean> {
    const { attempt } = input;
    const finishedAt = attempt.finishedAt.getTime();
    const results = await this.db.batch<DatabaseRow>([
      this.statement(
        `update own_auth_webhook_deliveries
         set status = ?4,
           attempts_in_cycle = attempts_in_cycle + 1,
           total_attempts = total_attempts + 1,
           next_attempt_at = ?5,
           delivered_at = case when ?4 = 'delivered' then ?6 else null end,
           failed_at = case when ?4 = 'failed' then ?6 else null end,
           last_status_code = ?7,
           last_error_code = ?8,
           updated_at = ?6
         where id = ?1 and status = 'processing' and lease_token = ?2
           and total_attempts = ?3`,
        [
          input.deliveryId,
          input.leaseToken,
          input.expectedTotalAttempts,
          input.status,
          input.nextAttemptAt.getTime(),
          finishedAt,
          attempt.statusCode,
          attempt.errorCode
        ]
      ),
      this.statement(
        `insert into own_auth_webhook_attempts (
           id, delivery_id, attempt_number, started_at, finished_at,
           outcome, status_code, error_code, next_retry_at
         )
         select ?4, id, ?5, ?6, ?7, ?8, ?9, ?10, ?11
         from own_auth_webhook_deliveries
         where id = ?1 and status = ?2 and total_attempts = ?3
           and updated_at = ?7 and lease_token = ?12
         returning id`,
        [
          input.deliveryId,
          input.status,
          input.expectedTotalAttempts + 1,
          attempt.id,
          attempt.attemptNumber,
          attempt.startedAt.getTime(),
          finishedAt,
          attempt.outcome,
          attempt.statusCode,
          attempt.errorCode,
          attempt.nextRetryAt?.getTime() ?? null,
          input.leaseToken
        ]
      ),
      this.statement(
        `update own_auth_webhook_deliveries
         set lease_token = null, lease_expires_at = null
         where id = ?1 and lease_token = ?2`,
        [input.deliveryId, input.leaseToken]
      )
    ]);
    return Boolean(results[1]?.results?.[0]);
  }

  async listWebhookDeliveries(input: ListWebhookDeliveriesInput): Promise<ListedWebhookDelivery[]> {
    const values: unknown[] = [];
    const filters: string[] = [];
    if (input.status) {
      values.push(input.status);
      filters.push(`delivery.status = ?${values.length}`);
    }
    if (input.endpointId) {
      values.push(input.endpointId);
      filters.push(`delivery.endpoint_id = ?${values.length}`);
    }
    values.push(input.limit ?? 50);
    const where = filters.length > 0 ? `where ${filters.join(" and ")}` : "";
    const result = await this.statement(
      `select ${webhookDeliverySelection("delivery")}, event.event_type as webhook_event_type
       from own_auth_webhook_deliveries delivery
       join own_auth_webhook_events event on event.id = delivery.event_id
       ${where} order by delivery.created_at desc limit ?${values.length}`,
      values
    ).all<DatabaseRow>();
    return (result.results ?? []).map((row) => ({
      delivery: mapWebhookDelivery(row),
      eventType: row.webhook_event_type as ListedWebhookDelivery["eventType"]
    }));
  }

  async listWebhookAttempts(deliveryIds: readonly string[]): Promise<WebhookAttempt[]> {
    if (deliveryIds.length === 0) return [];
    const placeholders = deliveryIds.map((_, index) => `?${index + 1}`).join(", ");
    const result = await this.statement(
      `select ${webhookAttemptReturning} from own_auth_webhook_attempts
       where delivery_id in (${placeholders}) order by delivery_id, attempt_number`,
      deliveryIds
    ).all<DatabaseRow>();
    return (result.results ?? []).map(mapWebhookAttempt);
  }

  async retryWebhookDelivery(deliveryId: string, retriedAt: Date): Promise<WebhookDelivery | null> {
    const row = await this.statement(
      `update own_auth_webhook_deliveries
       set status = 'pending', attempts_in_cycle = 0, next_attempt_at = ?2,
         lease_token = null, lease_expires_at = null, failed_at = null, updated_at = ?2
       where id = ?1 and status = 'failed'
       returning ${webhookDeliveryReturning}`,
      [deliveryId, retriedAt.getTime()]
    ).first<DatabaseRow>();
    return row ? mapWebhookDelivery(row) : null;
  }

  async cleanupWebhookDeliveries(olderThan: Date): Promise<number> {
    const results = await this.db.batch([
      this.statement(
        `delete from own_auth_webhook_deliveries
         where status in ('delivered', 'failed') and updated_at < ?1`,
        [olderThan.getTime()]
      ),
      this.statement(
        `delete from own_auth_webhook_events
         where not exists (
           select 1 from own_auth_webhook_deliveries delivery
           where delivery.event_id = own_auth_webhook_events.id
         )`
      )
    ]);
    const changes = results[0]?.meta?.changes;
    return typeof changes === "number" ? changes : 0;
  }

  private statement(sql: string, values: readonly unknown[] = []): D1PreparedStatementLike {
    const statement = this.db.prepare(sql);
    return values.length > 0 ? statement.bind(...values.map(toD1Value)) : statement;
  }
}
