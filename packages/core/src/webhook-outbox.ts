import { createId } from "./crypto.js";
import type { AuthEngineContext } from "./auth-engine-context.js";
import type { AtomicAuthEventWrite } from "./auth-storage-atomic.js";
import type { AuditEvent } from "./types.js";
import { createStoredWebhookEvent } from "./webhook-events.js";

export function prepareAuthEventWrite(
  ctx: AuthEngineContext,
  auditEvent: AuditEvent
): AtomicAuthEventWrite {
  const webhookEvent = createStoredWebhookEvent(auditEvent);
  const endpoints = webhookEvent && ctx.webhooks
    ? ctx.webhooks.endpoints.filter((endpoint) => endpoint.events.has(webhookEvent.type))
    : [];

  if (webhookEvent && endpoints.length > 0 && !ctx.webhookStorage) {
    throw new Error("WebhookCapableStorage is required when webhooks are configured");
  }

  return {
    auditEvent,
    webhookEvent: endpoints.length > 0 ? webhookEvent : null,
    webhookDeliveries: endpoints.map((endpoint) => ({
      id: createId("whd"),
      endpointId: endpoint.id,
      url: endpoint.url,
      createdAt: auditEvent.createdAt
    }))
  };
}

export async function recordAuthEvent(
  ctx: AuthEngineContext,
  auditEvent: AuditEvent
): Promise<void> {
  const write = prepareAuthEventWrite(ctx, auditEvent);

  if (!write.webhookEvent) {
    await ctx.storage.createAuditEvent(auditEvent);
  } else {
    await ctx.webhookStorage!.recordAuditEventWithWebhooks(
      write.auditEvent,
      write.webhookEvent,
      write.webhookDeliveries
    );
  }
  await recordCommittedAuthEvent(ctx, auditEvent);
}

export function recordCommittedAuthEvent(
  ctx: AuthEngineContext,
  auditEvent: AuditEvent
): Promise<void> {
  return ctx.cloud?.recordAuditEvent(auditEvent) ?? Promise.resolve();
}

export async function recordCommittedAuthEvents(
  ctx: AuthEngineContext,
  auditEvents: readonly AuditEvent[]
): Promise<void> {
  for (const event of auditEvents) await recordCommittedAuthEvent(ctx, event);
}
