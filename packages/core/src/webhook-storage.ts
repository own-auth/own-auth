import type { AuthStorage } from "./storage.js";
import type { AuditEvent } from "./types.js";
import type {
  ListWebhookDeliveriesInput,
  StoredWebhookEvent,
  WebhookAttempt,
  WebhookDelivery,
  WebhookDeliveryStatus
} from "./webhook-types.js";

export interface WebhookDeliverySeed {
  id: string;
  endpointId: string;
  url: string;
  createdAt: Date;
}

export interface ClaimedWebhookDelivery {
  delivery: WebhookDelivery;
  event: StoredWebhookEvent;
}

export interface ListedWebhookDelivery {
  delivery: WebhookDelivery;
  eventType: StoredWebhookEvent["type"];
}

export interface ClaimWebhookDeliveriesInput {
  now: Date;
  leaseToken: string;
  leaseExpiresAt: Date;
  limit: number;
}

export interface SettleWebhookDeliveryInput {
  deliveryId: string;
  leaseToken: string;
  expectedTotalAttempts: number;
  attempt: WebhookAttempt;
  status: Extract<WebhookDeliveryStatus, "delivered" | "failed" | "pending">;
  nextAttemptAt: Date;
}

export interface WebhookStorage {
  recordAuditEventWithWebhooks(
    auditEvent: AuditEvent,
    webhookEvent: StoredWebhookEvent,
    deliveries: readonly WebhookDeliverySeed[]
  ): Promise<void>;
  claimWebhookDeliveries(
    input: ClaimWebhookDeliveriesInput
  ): Promise<ClaimedWebhookDelivery[]>;
  settleWebhookDelivery(input: SettleWebhookDeliveryInput): Promise<boolean>;
  listWebhookDeliveries(input: ListWebhookDeliveriesInput): Promise<ListedWebhookDelivery[]>;
  listWebhookAttempts(deliveryIds: readonly string[]): Promise<WebhookAttempt[]>;
  retryWebhookDelivery(deliveryId: string, retriedAt: Date): Promise<WebhookDelivery | null>;
  cleanupWebhookDeliveries(olderThan: Date): Promise<number>;
}

export interface WebhookCapableStorage extends AuthStorage {
  readonly webhookStorage: WebhookStorage;
}

export function isWebhookCapableStorage(storage: AuthStorage): storage is WebhookCapableStorage {
  const candidate = storage as Partial<WebhookCapableStorage>;
  const webhookStorage = candidate.webhookStorage;
  return Boolean(webhookStorage) && [
    "recordAuditEventWithWebhooks",
    "claimWebhookDeliveries",
    "settleWebhookDelivery",
    "listWebhookDeliveries",
    "listWebhookAttempts",
    "retryWebhookDelivery",
    "cleanupWebhookDeliveries"
  ].every((method) => typeof webhookStorage?.[method as keyof WebhookStorage] === "function");
}
