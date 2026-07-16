import type { AuditEvent } from "../types.js";
import {
  mapStoredWebhookEvent,
  mapWebhookAttempt,
  mapWebhookDelivery
} from "../webhook-database-mappers.js";
import {
  webhookAttemptReturning,
  webhookDeliveryReturning,
  webhookDeliverySelection
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
import type { PostgresQueryable, Row } from "./postgres-types.js";

export class PostgresWebhookStorage implements WebhookStorage {
  constructor(private readonly db: PostgresQueryable) {}

  async recordAuditEventWithWebhooks(
    audit: AuditEvent,
    event: StoredWebhookEvent,
    deliveries: readonly WebhookDeliverySeed[]
  ): Promise<void> {
    await this.db.query(
      `with inserted_audit as (
         insert into own_auth_audit_events (
           id, event_type, actor_user_id, target_user_id, organisation_id,
           api_key_id, ip_address, user_agent, metadata, created_at
         ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)
         returning id
       ), inserted_event as (
         insert into own_auth_webhook_events (id, event_type, version, payload, created_at)
         select $11, $12, $13, $14, $15 from inserted_audit
         returning id
       ), delivery_rows as (
         select * from jsonb_to_recordset($16::jsonb) as item(
           id text, endpoint_id text, endpoint_url text, created_at timestamptz
         )
       )
       insert into own_auth_webhook_deliveries (
         id, event_id, endpoint_id, endpoint_url, status, attempts_in_cycle,
         total_attempts, next_attempt_at, created_at, updated_at
       )
       select item.id, inserted_event.id, item.endpoint_id, item.endpoint_url,
         'pending', 0, 0, item.created_at, item.created_at, item.created_at
       from delivery_rows item cross join inserted_event`,
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
        audit.createdAt,
        event.id,
        event.type,
        event.version,
        event.payload,
        event.createdAt,
        JSON.stringify(deliveries.map((delivery) => ({
          id: delivery.id,
          endpoint_id: delivery.endpointId,
          endpoint_url: delivery.url,
          created_at: delivery.createdAt.toISOString()
        })))
      ]
    );
  }

  async claimWebhookDeliveries(
    input: ClaimWebhookDeliveriesInput
  ): Promise<ClaimedWebhookDelivery[]> {
    const result = await this.db.query<Row>(
      `with candidates as (
         select id from own_auth_webhook_deliveries
         where (status = 'pending' and next_attempt_at <= $1)
            or (status = 'processing' and lease_expires_at <= $1)
         order by next_attempt_at asc, created_at asc
         for update skip locked
         limit $2
       ), claimed as (
         update own_auth_webhook_deliveries delivery
         set status = 'processing', lease_token = $3, lease_expires_at = $4, updated_at = $1
         from candidates
         where delivery.id = candidates.id
         returning delivery.*
       )
       select claimed.*, event.event_type as webhook_event_type,
         event.version as webhook_event_version, event.payload as webhook_event_payload,
         event.created_at as webhook_event_created_at
       from claimed join own_auth_webhook_events event on event.id = claimed.event_id
       order by claimed.next_attempt_at asc, claimed.created_at asc`,
      [input.now, input.limit, input.leaseToken, input.leaseExpiresAt]
    );
    return result.rows.map((row) => ({
      delivery: mapWebhookDelivery(row),
      event: mapStoredWebhookEvent({
        id: row.event_id,
        event_type: row.webhook_event_type,
        version: row.webhook_event_version,
        payload: row.webhook_event_payload,
        created_at: row.webhook_event_created_at
      })
    }));
  }

  async settleWebhookDelivery(input: SettleWebhookDeliveryInput): Promise<boolean> {
    const { attempt } = input;
    const result = await this.db.query<Row>(
      `with updated as (
         update own_auth_webhook_deliveries
         set status = $4,
           attempts_in_cycle = attempts_in_cycle + 1,
           total_attempts = total_attempts + 1,
           next_attempt_at = $5,
           lease_token = null,
           lease_expires_at = null,
           delivered_at = case when $4 = 'delivered' then $6 else null end,
           failed_at = case when $4 = 'failed' then $6 else null end,
           last_status_code = $7,
           last_error_code = $8,
           updated_at = $6
         where id = $1 and status = 'processing' and lease_token = $2
           and total_attempts = $3
         returning id
       )
       insert into own_auth_webhook_attempts (
         id, delivery_id, attempt_number, started_at, finished_at,
         outcome, status_code, error_code, next_retry_at
       )
       select $9, updated.id, $10, $11, $6, $12, $7, $8, $13
       from updated returning id`,
      [
        input.deliveryId,
        input.leaseToken,
        input.expectedTotalAttempts,
        input.status,
        input.nextAttemptAt,
        attempt.finishedAt,
        attempt.statusCode,
        attempt.errorCode,
        attempt.id,
        attempt.attemptNumber,
        attempt.startedAt,
        attempt.outcome,
        attempt.nextRetryAt
      ]
    );
    return result.rows.length === 1;
  }

  async listWebhookDeliveries(input: ListWebhookDeliveriesInput): Promise<ListedWebhookDelivery[]> {
    const params: unknown[] = [];
    const filters: string[] = [];
    if (input.status) {
      params.push(input.status);
      filters.push(`delivery.status = $${params.length}`);
    }
    if (input.endpointId) {
      params.push(input.endpointId);
      filters.push(`delivery.endpoint_id = $${params.length}`);
    }
    params.push(input.limit ?? 50);
    const where = filters.length > 0 ? `where ${filters.join(" and ")}` : "";
    const result = await this.db.query<Row>(
      `select ${webhookDeliverySelection("delivery")}, event.event_type as webhook_event_type
       from own_auth_webhook_deliveries delivery
       join own_auth_webhook_events event on event.id = delivery.event_id
       ${where} order by delivery.created_at desc limit $${params.length}`,
      params
    );
    return result.rows.map((row) => ({
      delivery: mapWebhookDelivery(row),
      eventType: row.webhook_event_type as ListedWebhookDelivery["eventType"]
    }));
  }

  async listWebhookAttempts(deliveryIds: readonly string[]): Promise<WebhookAttempt[]> {
    if (deliveryIds.length === 0) return [];
    const result = await this.db.query<Row>(
      `select ${webhookAttemptReturning} from own_auth_webhook_attempts
       where delivery_id = any($1::text[]) order by delivery_id, attempt_number`,
      [deliveryIds]
    );
    return result.rows.map(mapWebhookAttempt);
  }

  async retryWebhookDelivery(deliveryId: string, retriedAt: Date): Promise<WebhookDelivery | null> {
    const result = await this.db.query<Row>(
      `update own_auth_webhook_deliveries
       set status = 'pending', attempts_in_cycle = 0, next_attempt_at = $2,
         lease_token = null, lease_expires_at = null, failed_at = null, updated_at = $2
       where id = $1 and status = 'failed'
       returning ${webhookDeliveryReturning}`,
      [deliveryId, retriedAt]
    );
    return result.rows[0] ? mapWebhookDelivery(result.rows[0]) : null;
  }

  async cleanupWebhookDeliveries(olderThan: Date): Promise<number> {
    const result = await this.db.query<{ count: string | number }>(
      `with deleted as (
         delete from own_auth_webhook_deliveries
         where status in ('delivered', 'failed') and updated_at < $1
         returning event_id
       ), removed_events as (
         delete from own_auth_webhook_events event
         where event.id in (select event_id from deleted)
           and not exists (
             select 1 from own_auth_webhook_deliveries delivery where delivery.event_id = event.id
           )
       )
       select count(*) as count from deleted`,
      [olderThan]
    );
    return Number(result.rows[0]?.count ?? 0);
  }
}
