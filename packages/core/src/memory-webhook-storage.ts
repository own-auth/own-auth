import { cloneStored as clone } from "./memory-storage-helpers.js";
import type { AuditEvent } from "./types.js";
import type {
  ClaimWebhookDeliveriesInput,
  ClaimedWebhookDelivery,
  ListedWebhookDelivery,
  SettleWebhookDeliveryInput,
  WebhookDeliverySeed,
  WebhookStorage
} from "./webhook-storage.js";
import type {
  ListWebhookDeliveriesInput,
  StoredWebhookEvent,
  WebhookAttempt,
  WebhookDelivery
} from "./webhook-types.js";

export class MemoryWebhookStorage implements WebhookStorage {
  private readonly events = new Map<string, StoredWebhookEvent>();
  private readonly deliveries = new Map<string, WebhookDelivery>();
  private readonly attempts = new Map<string, WebhookAttempt>();

  constructor(private readonly auditEvents: Map<string, AuditEvent>) {}

  async recordAuditEventWithWebhooks(
    auditEvent: AuditEvent,
    webhookEvent: StoredWebhookEvent,
    deliveries: readonly WebhookDeliverySeed[]
  ): Promise<void> {
    if (this.auditEvents.has(auditEvent.id) || this.events.has(webhookEvent.id)) {
      throw new Error("Webhook event already exists");
    }
    if (deliveries.some((delivery) => this.deliveries.has(delivery.id))) {
      throw new Error("Webhook delivery already exists");
    }
    if (new Set(deliveries.map((delivery) => delivery.endpointId)).size !== deliveries.length) {
      throw new Error("Webhook deliveries must use unique endpoints");
    }

    this.auditEvents.set(auditEvent.id, clone(auditEvent));
    this.events.set(webhookEvent.id, clone(webhookEvent));
    for (const delivery of deliveries) {
      this.deliveries.set(delivery.id, clone(deliveryFromSeed(delivery, webhookEvent.id)));
    }
  }

  async claimWebhookDeliveries(
    input: ClaimWebhookDeliveriesInput
  ): Promise<ClaimedWebhookDelivery[]> {
    const eligible = [...this.deliveries.values()]
      .filter((delivery) => isEligible(delivery, input.now))
      .sort((left, right) =>
        left.nextAttemptAt.getTime() - right.nextAttemptAt.getTime() ||
        left.createdAt.getTime() - right.createdAt.getTime())
      .slice(0, input.limit);

    return eligible.flatMap((delivery) => {
      const event = this.events.get(delivery.eventId);
      if (!event) return [];
      const claimed: WebhookDelivery = {
        ...delivery,
        status: "processing",
        leaseToken: input.leaseToken,
        leaseExpiresAt: input.leaseExpiresAt,
        updatedAt: input.now
      };
      this.deliveries.set(claimed.id, clone(claimed));
      return [{ delivery: clone(claimed), event: clone(event) }];
    });
  }

  async settleWebhookDelivery(input: SettleWebhookDeliveryInput): Promise<boolean> {
    const delivery = this.deliveries.get(input.deliveryId);
    if (
      !delivery ||
      delivery.status !== "processing" ||
      delivery.leaseToken !== input.leaseToken ||
      delivery.totalAttempts !== input.expectedTotalAttempts ||
      this.attempts.has(input.attempt.id)
    ) {
      return false;
    }

    this.attempts.set(input.attempt.id, clone(input.attempt));
    this.deliveries.set(delivery.id, clone({
      ...delivery,
      status: input.status,
      attemptsInCycle: delivery.attemptsInCycle + 1,
      totalAttempts: delivery.totalAttempts + 1,
      nextAttemptAt: input.nextAttemptAt,
      leaseToken: null,
      leaseExpiresAt: null,
      deliveredAt: input.status === "delivered" ? input.attempt.finishedAt : null,
      failedAt: input.status === "failed" ? input.attempt.finishedAt : null,
      lastStatusCode: input.attempt.statusCode,
      lastErrorCode: input.attempt.errorCode,
      updatedAt: input.attempt.finishedAt
    }));
    return true;
  }

  async listWebhookDeliveries(input: ListWebhookDeliveriesInput): Promise<ListedWebhookDelivery[]> {
    return [...this.deliveries.values()]
      .filter((delivery) => !input.status || delivery.status === input.status)
      .filter((delivery) => !input.endpointId || delivery.endpointId === input.endpointId)
      .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime())
      .slice(0, input.limit ?? 50)
      .flatMap((delivery) => {
        const event = this.events.get(delivery.eventId);
        return event ? [{ delivery: clone(delivery), eventType: event.type }] : [];
      });
  }

  async listWebhookAttempts(deliveryIds: readonly string[]): Promise<WebhookAttempt[]> {
    const ids = new Set(deliveryIds);
    return [...this.attempts.values()]
      .filter((attempt) => ids.has(attempt.deliveryId))
      .sort((left, right) => left.attemptNumber - right.attemptNumber)
      .map((attempt) => clone(attempt));
  }

  async retryWebhookDelivery(deliveryId: string, retriedAt: Date): Promise<WebhookDelivery | null> {
    const delivery = this.deliveries.get(deliveryId);
    if (!delivery || delivery.status !== "failed") return null;
    const retried: WebhookDelivery = {
      ...delivery,
      status: "pending",
      attemptsInCycle: 0,
      nextAttemptAt: retriedAt,
      leaseToken: null,
      leaseExpiresAt: null,
      failedAt: null,
      updatedAt: retriedAt
    };
    this.deliveries.set(deliveryId, clone(retried));
    return clone(retried);
  }

  async cleanupWebhookDeliveries(olderThan: Date): Promise<number> {
    const removed = new Set<string>();
    for (const [id, delivery] of this.deliveries) {
      if (
        (delivery.status === "delivered" || delivery.status === "failed") &&
        delivery.updatedAt < olderThan
      ) {
        this.deliveries.delete(id);
        removed.add(id);
      }
    }
    for (const [id, attempt] of this.attempts) {
      if (removed.has(attempt.deliveryId)) this.attempts.delete(id);
    }
    const retainedEventIds = new Set(
      [...this.deliveries.values()].map((delivery) => delivery.eventId)
    );
    for (const eventId of this.events.keys()) {
      if (!retainedEventIds.has(eventId)) this.events.delete(eventId);
    }
    return removed.size;
  }
}

function deliveryFromSeed(seed: WebhookDeliverySeed, eventId: string): WebhookDelivery {
  return {
    ...seed,
    eventId,
    status: "pending",
    attemptsInCycle: 0,
    totalAttempts: 0,
    nextAttemptAt: seed.createdAt,
    leaseToken: null,
    leaseExpiresAt: null,
    deliveredAt: null,
    failedAt: null,
    lastStatusCode: null,
    lastErrorCode: null,
    updatedAt: seed.createdAt
  };
}

function isEligible(delivery: WebhookDelivery, now: Date): boolean {
  return (
    delivery.status === "pending" && delivery.nextAttemptAt <= now
  ) || (
    delivery.status === "processing" && Boolean(delivery.leaseExpiresAt && delivery.leaseExpiresAt <= now)
  );
}
