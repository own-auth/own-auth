import type { DatabaseRow } from "./database-types.js";
import {
  dateValue,
  nullableDate,
  nullableNumber,
  nullableString,
  numberValue,
  stringValue
} from "./database-row.js";
import type {
  StoredWebhookEvent,
  WebhookAttempt,
  WebhookAttemptErrorCode,
  WebhookAttemptOutcome,
  WebhookDelivery,
  WebhookDeliveryStatus,
  WebhookEventType
} from "./webhook-types.js";

export function mapStoredWebhookEvent(row: DatabaseRow): StoredWebhookEvent {
  return {
    id: stringValue(row.id),
    type: stringValue(row.event_type) as WebhookEventType,
    version: numberValue(row.version) as 1,
    payload: stringValue(row.payload),
    createdAt: dateValue(row.created_at)
  };
}

export function mapWebhookDelivery(row: DatabaseRow): WebhookDelivery {
  return {
    id: stringValue(row.id),
    eventId: stringValue(row.event_id),
    endpointId: stringValue(row.endpoint_id),
    url: stringValue(row.endpoint_url),
    status: stringValue(row.status) as WebhookDeliveryStatus,
    attemptsInCycle: numberValue(row.attempts_in_cycle),
    totalAttempts: numberValue(row.total_attempts),
    nextAttemptAt: dateValue(row.next_attempt_at),
    leaseToken: nullableString(row.lease_token),
    leaseExpiresAt: nullableDate(row.lease_expires_at),
    deliveredAt: nullableDate(row.delivered_at),
    failedAt: nullableDate(row.failed_at),
    lastStatusCode: nullableNumber(row.last_status_code),
    lastErrorCode: nullableString(row.last_error_code) as WebhookAttemptErrorCode | null,
    createdAt: dateValue(row.created_at),
    updatedAt: dateValue(row.updated_at)
  };
}

export function mapWebhookAttempt(row: DatabaseRow): WebhookAttempt {
  return {
    id: stringValue(row.id),
    deliveryId: stringValue(row.delivery_id),
    attemptNumber: numberValue(row.attempt_number),
    startedAt: dateValue(row.started_at),
    finishedAt: dateValue(row.finished_at),
    outcome: stringValue(row.outcome) as WebhookAttemptOutcome,
    statusCode: nullableNumber(row.status_code),
    errorCode: nullableString(row.error_code) as WebhookAttemptErrorCode | null,
    nextRetryAt: nullableDate(row.next_retry_at)
  };
}
