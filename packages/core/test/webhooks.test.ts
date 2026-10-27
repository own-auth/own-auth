import { describe, expect, it, vi } from "vitest";
import {
  createOwnAuth,
  defineOwnAuthPlugin,
  InMemoryAuthStorage,
  type WebhookEvent
} from "../src/index.js";
import {
  createWebhookSignature,
  verifyOwnAuthWebhook,
  webhookIdHeader,
  webhookSignatureHeader,
  webhookTimestampHeader
} from "../src/webhook-signing.js";

const webhookSecret = "webhook-test-secret-that-is-at-least-32-bytes";
const rotatedSecret = "rotated-webhook-secret-that-is-at-least-32-bytes";

describe("Own Auth webhooks", () => {
  it("does not start a claimed delivery after erasure removes its stored event", async () => {
    const storage = new InMemoryAuthStorage();
    const send = vi.fn<typeof fetch>(async () => new Response(null, { status: 204 }));
    const auth = createWebhookAuth(storage, send);
    const signup = await auth.signUpEmailPassword({ email: "claimed-erasure@example.com", password: "correct-horse" });
    const claim = storage.webhookStorage.claimWebhookDeliveries.bind(storage.webhookStorage);
    vi.spyOn(storage.webhookStorage, "claimWebhookDeliveries").mockImplementationOnce(async (input) => {
      const claimed = await claim(input);
      await auth.eraseUser({ operationId: crypto.randomUUID(), confirmation: "erase", sessionToken: signup.sessionToken });
      return claimed;
    });
    expect(await auth.processWebhookDeliveries()).toMatchObject({ claimed: 1, leaseLost: 1, delivered: 0 });
    expect(send).not.toHaveBeenCalled();
    expect(await auth.listWebhookDeliveries()).toEqual([]);
  });

  it("removes a request already in progress and prevents its retry or settlement recreating records", async () => {
    const storage = new InMemoryAuthStorage();
    let started!: () => void;
    const inProgress = new Promise<void>((resolve) => { started = resolve; });
    let finish!: (response: Response) => void;
    const response = new Promise<Response>((resolve) => { finish = resolve; });
    const send = vi.fn<typeof fetch>(async () => { started(); return response; });
    const auth = createWebhookAuth(storage, send);
    const signup = await auth.signUpEmailPassword({ email: "in-progress-erasure@example.com", password: "correct-horse" });
    const queued = await auth.listWebhookDeliveries();
    const processing = auth.processWebhookDeliveries();
    await inProgress;
    await auth.eraseUser({ operationId: crypto.randomUUID(), confirmation: "erase", sessionToken: signup.sessionToken });
    finish(new Response(null, { status: 503 }));
    expect(await processing).toMatchObject({ leaseLost: 1, retried: 0 });
    expect(send).toHaveBeenCalledTimes(1);
    expect(await auth.listWebhookDeliveries()).toEqual([]);
    expect(await storage.webhookStorage.listWebhookAttempts([queued[0]!.id])).toEqual([]);
    await expect(auth.retryWebhookDelivery({ deliveryId: queued[0]!.id })).rejects.toMatchObject({ code: "webhook_delivery_not_retryable" });
  });
  it("validates endpoint configuration synchronously", () => {
    const create = (endpoint: Record<string, unknown>) => () => createOwnAuth({
      storage: new InMemoryAuthStorage(),
      webhooks: {
        endpoints: [endpoint as never]
      }
    });

    expect(create({
      id: "public-events",
      url: "http://example.com/hooks",
      secret: webhookSecret,
      events: ["user.signed_up"]
    })).toThrow("must use HTTPS or an HTTP loopback URL");
    expect(create({
      id: "public-events",
      url: "https://example.com/hooks",
      secret: "too-short",
      events: ["user.signed_up"]
    })).toThrow("requires a secret of at least 32 bytes");
    expect(create({
      id: "public-events",
      url: "https://example.com/hooks",
      secret: webhookSecret,
      events: ["plugin.custom"]
    })).toThrow("Unknown webhook event");
  });

  it("rejects custom storage without the complete webhook capability", () => {
    const storage = new InMemoryAuthStorage();
    Object.defineProperty(storage, "webhookStorage", {
      value: {
        recordAuditEventWithWebhooks: async () => undefined,
        claimWebhookDeliveries: async () => [],
        settleWebhookDelivery: async () => true
      }
    });

    expect(() => createOwnAuth({
      storage,
      webhooks: {
        endpoints: [endpointOptions()]
      }
    })).toThrow(
      "Webhook delivery requires storage that supports WebhookCapableStorage. " +
      "The configured storage adapter does not implement it."
    );
  });

  it("writes the audit event and outbox record before delivering a signed payload", async () => {
    const requests: CapturedRequest[] = [];
    const storage = new InMemoryAuthStorage();
    const auth = createWebhookAuth(storage, async (input, init) => {
      requests.push(captureRequest(input, init));
      return new Response(null, { status: 204 });
    });
    const signup = await auth.signUpEmailPassword({
      email: "webhook@example.com",
      password: "correct-horse"
    });

    const queued = await auth.listWebhookDeliveries();
    const audits = await auth.listAuditEvents({ actorUserId: signup.user.id });

    expect(queued).toHaveLength(1);
    expect(queued[0]).toMatchObject({
      eventType: "user.signed_up",
      endpointId: "public-events",
      status: "pending",
      attempts: []
    });
    expect(queued[0]).not.toHaveProperty("leaseToken");
    expect(audits.some(({ id }) => id === queued[0]?.eventId)).toBe(true);

    const processed = await auth.processWebhookDeliveries();

    expect(processed).toEqual({
      claimed: 1,
      delivered: 1,
      retried: 0,
      failed: 0,
      leaseLost: 0
    });
    expect(requests).toHaveLength(1);

    const event = await verifyCapturedRequest(requests[0]!);
    expect(event).toMatchObject({
      id: queued[0]?.eventId,
      type: "user.signed_up",
      version: 1,
      data: {
        actorUserId: signup.user.id,
        targetUserId: signup.user.id,
        details: { provider: "password" }
      }
    });
  });

  it("allows only one concurrent processor to claim a delivery", async () => {
    const send = vi.fn<typeof fetch>(async () => new Response(null, { status: 204 }));
    const auth = createWebhookAuth(new InMemoryAuthStorage(), send);
    await auth.signUpEmailPassword({
      email: "concurrent-webhook@example.com",
      password: "correct-horse"
    });

    const results = await Promise.all([
      auth.processWebhookDeliveries(),
      auth.processWebhookDeliveries()
    ]);

    expect(results.reduce((sum, result) => sum + result.claimed, 0)).toBe(1);
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("preserves attempt history across a manual retry", async () => {
    let status = 400;
    const auth = createWebhookAuth(new InMemoryAuthStorage(), async () =>
      new Response(null, { status }));
    await auth.signUpEmailPassword({
      email: "retry-webhook@example.com",
      password: "correct-horse"
    });

    await auth.processWebhookDeliveries();
    const [failed] = await auth.listWebhookDeliveries();
    expect(failed).toMatchObject({
      status: "failed",
      attemptsInCycle: 1,
      totalAttempts: 1,
      lastStatusCode: 400,
      lastErrorCode: "http_permanent",
      attempts: [{ attemptNumber: 1, outcome: "failed", statusCode: 400 }]
    });

    status = 204;
    await auth.retryWebhookDelivery({ deliveryId: failed!.id });
    await auth.processWebhookDeliveries();

    const [delivered] = await auth.listWebhookDeliveries();
    expect(delivered).toMatchObject({
      status: "delivered",
      attemptsInCycle: 1,
      totalAttempts: 2,
      attempts: [
        { attemptNumber: 1, outcome: "failed", statusCode: 400 },
        { attemptNumber: 2, outcome: "delivered", statusCode: 204 }
      ]
    });
  });

  it("uses retry eligibility and Retry-After without storing response bodies", async () => {
    const auth = createWebhookAuth(new InMemoryAuthStorage(), async () =>
      new Response("sentinel-response-body", {
        status: 503,
        headers: { "retry-after": "120" }
      }));
    await auth.signUpEmailPassword({
      email: "retry-after@example.com",
      password: "correct-horse"
    });

    const before = Date.now();
    const result = await auth.processWebhookDeliveries();
    const [delivery] = await auth.listWebhookDeliveries();

    expect(result.retried).toBe(1);
    expect(delivery).toMatchObject({
      status: "pending",
      attemptsInCycle: 1,
      lastStatusCode: 503,
      lastErrorCode: "http_retryable",
      attempts: [{ outcome: "retry_scheduled", statusCode: 503 }]
    });
    expect(delivery!.nextAttemptAt.getTime()).toBeGreaterThanOrEqual(before + 119_000);
    expect(JSON.stringify(delivery)).not.toContain("sentinel-response-body");
  });

  it("marks the delivery failed after the initial attempt and five retries", async () => {
    const auth = createWebhookAuth(new InMemoryAuthStorage(), async () =>
      new Response(null, { status: 503 }));
    await auth.signUpEmailPassword({
      email: "retry-limit@example.com",
      password: "correct-horse"
    });
    const expectedDelays = [30_000, 120_000, 600_000, 3_600_000, 21_600_000];
    vi.useFakeTimers({ toFake: ["Date"] });

    try {
      for (const expectedDelay of expectedDelays) {
        const before = Date.now();
        await auth.processWebhookDeliveries();
        const [delivery] = await auth.listWebhookDeliveries();
        expect(delivery?.status).toBe("pending");
        expect(delivery!.nextAttemptAt.getTime() - before).toBe(expectedDelay);
        vi.setSystemTime(delivery!.nextAttemptAt);
      }

      await auth.processWebhookDeliveries();
      const [failed] = await auth.listWebhookDeliveries();
      expect(failed).toMatchObject({
        status: "failed",
        attemptsInCycle: 6,
        totalAttempts: 6
      });
      expect(failed?.attempts).toHaveLength(6);
    } finally {
      vi.useRealTimers();
    }
  });

  it("classifies a ten-second request timeout as retryable", async () => {
    let markRequestStarted: () => void = () => undefined;
    const requestStarted = new Promise<void>((resolve) => {
      markRequestStarted = resolve;
    });
    const auth = createWebhookAuth(new InMemoryAuthStorage(), async (_input, init) => {
      markRequestStarted();
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), {
          once: true
        });
      });
    });
    await auth.signUpEmailPassword({
      email: "timeout-webhook@example.com",
      password: "correct-horse"
    });
    vi.useFakeTimers();

    try {
      const processing = auth.processWebhookDeliveries();
      await requestStarted;
      await vi.advanceTimersByTimeAsync(10_000);
      await expect(processing).resolves.toMatchObject({ retried: 1 });
      await expect(auth.listWebhookDeliveries()).resolves.toEqual([
        expect.objectContaining({
          status: "pending",
          lastErrorCode: "timeout",
          attempts: [expect.objectContaining({ outcome: "retry_scheduled" })]
        })
      ]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("removes attempt history when completed deliveries are cleaned up", async () => {
    const storage = new InMemoryAuthStorage();
    const auth = createWebhookAuth(storage, async () => new Response(null, { status: 204 }));
    await auth.signUpEmailPassword({
      email: "cleanup-webhook@example.com",
      password: "correct-horse"
    });
    await auth.processWebhookDeliveries();
    const [delivery] = await auth.listWebhookDeliveries();

    await expect(auth.cleanupWebhookDeliveries({
      olderThan: new Date(Date.now() + 1_000)
    })).resolves.toBe(1);
    await expect(auth.listWebhookDeliveries()).resolves.toEqual([]);
    await expect(storage.webhookStorage.listWebhookAttempts([delivery!.id])).resolves.toEqual([]);
  });

  it("verifies rotated secrets and rejects stale, tampered, or replayed events", async () => {
    const event = webhookEvent();
    const body = JSON.stringify(event);
    const timestamp = Math.floor(Date.now() / 1_000).toString();
    const signature = await createWebhookSignature({
      body,
      eventId: event.id,
      timestamp,
      secret: webhookSecret
    });
    const headers = signedHeaders(event.id, timestamp, signature);
    const claimed = new Set<string>();
    const claimEvent = async ({ eventId }: { eventId: string }) => {
      if (claimed.has(eventId)) return false;
      claimed.add(eventId);
      return true;
    };

    await expect(verifyOwnAuthWebhook({
      body,
      headers,
      secrets: [rotatedSecret, webhookSecret],
      claimEvent
    })).resolves.toEqual(event);
    await expect(verifyOwnAuthWebhook({
      body,
      headers,
      secrets: [rotatedSecret, webhookSecret],
      claimEvent
    })).rejects.toMatchObject({ code: "webhook_replayed" });
    const tamperedClaim = vi.fn(async () => true);
    await expect(verifyOwnAuthWebhook({
      body: body.replace("user.signed_up", "user.signed_in"),
      headers,
      secrets: [webhookSecret],
      claimEvent: tamperedClaim
    })).rejects.toMatchObject({ code: "webhook_signature_invalid" });
    expect(tamperedClaim).not.toHaveBeenCalled();
    await expect(verifyOwnAuthWebhook({
      body,
      headers,
      secrets: [webhookSecret],
      claimEvent: async () => true,
      now: new Date(Number(timestamp) * 1_000 + 5 * 60_000 + 1)
    })).rejects.toMatchObject({ code: "webhook_timestamp_invalid" });
  });

  it("does not turn plugin audit events into core webhook events", async () => {
    const plugin = defineOwnAuthPlugin({
      id: "webhook-plugin",
      version: "1.0.0",
      auditEvents: ["completed"],
      serverMethods: {
        async run(context) {
          await context.audit("completed", { secret: "sentinel-plugin-secret" });
          return { ok: true };
        }
      }
    });
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "webhook-test-pepper",
      plugins: [plugin],
      webhooks: {
        endpoints: [endpointOptions()],
        fetch: async () => new Response(null, { status: 204 })
      }
    });

    await auth.callPluginMethod("webhook-plugin", "run", {});

    await expect(auth.listWebhookDeliveries()).resolves.toEqual([]);
  });
});

interface CapturedRequest {
  body: string;
  headers: Headers;
}

function endpointOptions() {
  return {
    id: "public-events",
    url: "https://hooks.example.com/own-auth",
    secret: webhookSecret,
    events: ["user.signed_up"] as const
  };
}

function createWebhookAuth(storage: InMemoryAuthStorage, fetchImpl: typeof fetch) {
  return createOwnAuth({
    storage,
    tokenPepper: "webhook-test-pepper",
    webhooks: {
      endpoints: [endpointOptions()],
      fetch: fetchImpl
    }
  });
}

function captureRequest(input: Parameters<typeof fetch>[0], init?: RequestInit): CapturedRequest {
  expect(String(input)).toBe("https://hooks.example.com/own-auth");
  expect(init?.method).toBe("POST");
  expect(init?.redirect).toBe("manual");
  return {
    body: String(init?.body),
    headers: new Headers(init?.headers)
  };
}

async function verifyCapturedRequest(request: CapturedRequest): Promise<WebhookEvent> {
  return verifyOwnAuthWebhook({
    body: request.body,
    headers: request.headers,
    secrets: [webhookSecret],
    claimEvent: async () => true
  });
}

function webhookEvent(): WebhookEvent {
  return {
    id: "evt_AAAAAAAAAAAAAAAAAAAAAA",
    type: "user.signed_up",
    version: 1,
    createdAt: new Date().toISOString(),
    data: {
      actorUserId: "usr_1",
      targetUserId: "usr_1",
      organisationId: null,
      apiKeyId: null,
      details: { provider: "password" }
    }
  };
}

function signedHeaders(eventId: string, timestamp: string, signature: string): Headers {
  return new Headers({
    [webhookIdHeader]: eventId,
    [webhookTimestampHeader]: timestamp,
    [webhookSignatureHeader]: signature
  });
}
