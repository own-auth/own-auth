import { resolveFetchImplementation } from "./fetch-implementation.js";
import { coreAuditEventTypes } from "./types.js";
import type { WebhookEventType, WebhookOptions } from "./webhook-types.js";

const knownEventTypes = new Set<string>(coreAuditEventTypes);
const endpointIdPattern = /^[A-Za-z0-9_-]{1,64}$/u;

export interface NormalizedWebhookEndpoint {
  id: string;
  url: string;
  secret: string;
  events: ReadonlySet<WebhookEventType>;
}

export interface WebhookRuntimeConfig {
  endpoints: readonly NormalizedWebhookEndpoint[];
  endpointsById: ReadonlyMap<string, NormalizedWebhookEndpoint>;
  fetch: typeof fetch;
}

export function normalizeWebhookOptions(options?: WebhookOptions): WebhookRuntimeConfig | null {
  if (!options) return null;
  if (!Array.isArray(options.endpoints) || options.endpoints.length === 0) {
    throw new Error("webhooks.endpoints must contain at least one endpoint");
  }

  const ids = new Set<string>();
  const endpoints = options.endpoints.map((endpoint) => {
    if (!endpointIdPattern.test(endpoint.id)) {
      throw new Error("webhook endpoint IDs must contain 1-64 letters, numbers, underscores, or hyphens");
    }
    if (ids.has(endpoint.id)) {
      throw new Error(`Duplicate webhook endpoint ID: ${endpoint.id}`);
    }
    ids.add(endpoint.id);

    if (typeof endpoint.secret !== "string" || utf8Length(endpoint.secret) < 32) {
      throw new Error(`Webhook endpoint ${endpoint.id} requires a secret of at least 32 bytes`);
    }
    if (!Array.isArray(endpoint.events) || endpoint.events.length === 0) {
      throw new Error(`Webhook endpoint ${endpoint.id} must subscribe to at least one event`);
    }

    const events = new Set<WebhookEventType>();
    for (const event of endpoint.events) {
      if (!knownEventTypes.has(event)) {
        throw new Error(`Unknown webhook event for ${endpoint.id}: ${String(event)}`);
      }
      if (events.has(event)) {
        throw new Error(`Duplicate webhook event for ${endpoint.id}: ${event}`);
      }
      events.add(event);
    }

    return {
      id: endpoint.id,
      url: normalizeWebhookUrl(endpoint.url, endpoint.id),
      secret: endpoint.secret,
      events
    };
  });

  const fetchImpl = resolveFetchImplementation(options.fetch);
  if (typeof fetchImpl !== "function") {
    throw new Error("Webhook delivery requires a fetch implementation");
  }

  return {
    endpoints,
    endpointsById: new Map(endpoints.map((endpoint) => [endpoint.id, endpoint])),
    fetch: fetchImpl
  };
}

function normalizeWebhookUrl(value: string | URL, endpointId: string): string {
  let url: URL;
  try {
    url = value instanceof URL ? new URL(value.toString()) : new URL(value);
  } catch {
    throw new Error(`Webhook endpoint ${endpointId} requires a valid URL`);
  }

  if (url.username || url.password || url.hash) {
    throw new Error(`Webhook endpoint ${endpointId} cannot contain credentials or a fragment`);
  }
  if (url.toString().length > 2_048) {
    throw new Error(`Webhook endpoint ${endpointId} URL is too long`);
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback(url.hostname))) {
    throw new Error(`Webhook endpoint ${endpointId} must use HTTPS or an HTTP loopback URL`);
  }

  return url.toString();
}

function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}
