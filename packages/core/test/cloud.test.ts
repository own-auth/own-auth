import { describe, expect, it, vi } from "vitest";
import { createOwnAuthClient } from "../src/client.js";
import { cloud, cloudClient } from "../src/cloud.js";
import { cloudEventContract } from "../src/cloud-event-contract.js";
import { cloudEventTypes, type CloudEntityType } from "../src/cloud-types.js";
import {
  createCloudEvent,
  failedLoginEvent,
  validateCloudEvent
} from "../src/cloud-events.js";
import { hashSecret } from "../src/crypto.js";
import { CloudRuntime } from "../src/cloud-runtime.js";
import {
  createOwnAuth,
  createOwnAuthHandler,
  InMemoryAuthStorage
} from "../src/index.js";

const cloudKey = `oac_sk_${"a".repeat(32)}`;
const webhookSecret = "webhook-secret-that-is-at-least-32-bytes";

describe("Own Auth Cloud", () => {
  it("withholds local completion until security caches on other instances have expired", async () => {
    vi.useFakeTimers();
    try {
      const storage = new InMemoryAuthStorage();
      const auth = createOwnAuth({ storage, plugins: [cloud({ key: cloudKey, flushMode: "manual", onWarning() {},
        fetch: (async (_url, input) => {
          const event = JSON.parse(String(input?.body)) as { id?: string };
          return Response.json({ status: "applied", erasure: { eventId: event.id, status: "complete" } });
        }) as typeof fetch })] });
      const signup = await auth.signUpEmailPassword({ email: "cache-erasure@example.com", password: "correct-horse" });
      const operationId = crypto.randomUUID();
      expect(await auth.eraseUser({ operationId, sessionToken: signup.sessionToken, confirmation: "erase" }))
        .toMatchObject({ status: "pending", local: "pending", cloud: "complete", pendingLocalStores: ["pending_identity_requests"] });
      vi.setSystemTime(Date.now() + 5 * 60_000 + 1);
      expect(await auth.getUserErasure({ operationId })).toMatchObject({ status: "complete", local: "complete", cloud: "complete" });
      expect((await storage.userErasureStorage.get(operationId))?.subject).toBeNull();
    } finally { vi.useRealTimers(); }
  });
  it("distinguishes acceptance from complete erasure and recovers outages and lost acknowledgements", async () => {
    vi.useFakeTimers();
    try {
      const storage = new InMemoryAuthStorage();
      const auth = createOwnAuth({ storage });
      const target = await auth.createUser({ email: "cloud-erasure@example.com" });
      let mode = "outage";
      let remotelyErased = false;
      const fetchImpl = vi.fn<typeof fetch>(async (_url, input) => {
        const event = JSON.parse(String(input?.body)) as { id: string };
        if (mode === "outage") throw new Error("Cloud unavailable");
        if (mode === "accepted") return Response.json({ status: "applied" });
        if (mode === "wrong") return Response.json({ status: "applied", erasure: { eventId: "another-request", status: "complete" } });
        if (mode === "lost") { remotelyErased = true; throw new Error("Acknowledgement lost"); }
        return Response.json({ status: "stale", erasure: { eventId: event.id, status: remotelyErased ? "complete" : "pending" } });
      });
      const runtime = new CloudRuntime({ key: cloudKey, endpoint: "https://cloud.example.com", flushMode: "manual", fetch: fetchImpl, onWarning() {} }, storage.cloudStorage, storage);
      const now = Date.now();
      const operationId = crypto.randomUUID();
      await storage.userErasureStorage.eraseAtomically({ operationId, userId: target.id, expectedUpdatedAt: target.updatedAt,
        now, protectedUntil: now, pendingStores: [], organisations: [], cloudEvent: runtime.prepareUserErasure(target.id) });
      for (const phase of ["outage", "accepted", "wrong", "lost"]) {
        mode = phase;
        expect(await runtime.flushOutbox()).toMatchObject({ sent: 0, failed: 1, remaining: 1 });
        expect(await auth.getUserErasure({ operationId })).toMatchObject({ status: "pending", cloud: "pending" });
        vi.setSystemTime(Date.now() + 60_000);
      }
      mode = "complete";
      expect(await runtime.flushOutbox()).toMatchObject({ sent: 1, failed: 0, remaining: 0 });
      expect(await auth.getUserErasure({ operationId })).toMatchObject({ status: "complete", cloud: "complete" });
      expect((await storage.userErasureStorage.get(operationId))?.subject).toBeNull();
      expect(fetchImpl).toHaveBeenCalledTimes(5);
      expect(JSON.stringify(fetchImpl.mock.calls)).not.toContain(target.email);
    } finally { vi.useRealTimers(); }
  });
  it("publishes the system-only delivery event contract", () => {
    expect(Object.keys(cloudEventContract.systemEvents)).toEqual([
      "email.sent",
      "email.failed",
      "sms.sent",
      "sms.failed"
    ]);
    expect(cloudEventContract.systemEvents["email.failed"].fields.errorCode.values)
      .toContain("quota_exhausted");
  });

  it("validates every event in the package-owned Cloud contract", () => {
    expect(cloudEventTypes).toEqual(Object.keys(cloudEventContract.events));
    for (const type of cloudEventTypes) {
      const definition = cloudEventContract.events[type];
      const data = Object.fromEntries(Object.entries(definition.fields).map(([name, field]) => [
        name,
        cloudFieldValue(field)
      ]));
      const event = createCloudEvent("app_contract", {
        type,
        data,
        ...(definition.requiredMeta?.includes("userId") ? {
          userId: "usr_contract"
        } : {}),
        ...(definition.entity ? {
          entity: {
            type: definition.entity as CloudEntityType,
            id: `entity_${type.replaceAll(".", "_")}`
          }
        } : {})
      });
      if (definition.entity) event.entityVersion = 1;
      expect(() => validateCloudEvent(event, true)).not.toThrow();
    }
  });

  it("validates event fields before they enter the outbox", () => {
    const event = createCloudEvent("app_test", {
      type: "user.created",
      data: {
        userId: "usr_test",
        email: "user@example.com",
        authMethods: ["password"]
      },
      entity: { type: "user", id: "usr_test" }
    });

    expect(event.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
    );

    expect(() => validateCloudEvent({
      ...event,
      data: { ...event.data, password: "never-send-this" }
    })).toThrow("unknown field password");
    expect(() => validateCloudEvent({
      ...event,
      unexpected: true
    } as never)).toThrow("unknown field unexpected");
    expect(() => validateCloudEvent({
      ...event,
      meta: { ...event.meta, token: "never-send-this" }
    } as never)).toThrow("metadata contains unknown field token");
    expect(() => validateCloudEvent({
      ...createCloudEvent("app_test", {
        type: "login.failed",
        data: { reason: "invalid_credentials" }
      }),
      meta: { orgId: "org_not_allowed" }
    } as never)).toThrow("metadata contains unknown field orgId");
    expect(() => validateCloudEvent({
      ...event,
      data: { ...event.data, authMethods: "password" }
    })).toThrow("invalid authMethods");
    expect(() => validateCloudEvent({
      ...event,
      timestamp: "August 24, 2026"
    })).toThrow("invalid timestamp");
    expect(() => validateCloudEvent({
      ...event,
      timestamp: "2026-02-31T12:00:00.000Z"
    })).toThrow("invalid timestamp");
    expect(() => validateCloudEvent({
      ...event,
      timestamp: "0000-01-01T12:00:00.000Z"
    })).toThrow("invalid timestamp");
    expect(() => validateCloudEvent(createCloudEvent("app_test", {
      type: "org.invite.created",
      data: {
        orgId: "org_1",
        invitationId: "invite_1",
        inviteeEmail: "user@example.com",
        role: "member",
        expiresAt: "2026-02-31T12:00:00.000Z"
      },
      entity: { type: "org", id: "org_1" },
      userId: "user_1"
    }))).toThrow("invalid expiresAt");
    expect(() => validateCloudEvent({
      ...createCloudEvent("app_test", {
        type: "session.revoked",
        data: { sessionId: "session_1", userId: "user_1", reason: "logout" },
        userId: "user_1"
      }),
      meta: {}
    })).toThrow("invalid metadata userId");
    expect(() => validateCloudEvent(createCloudEvent("app_test", {
      type: "login.challenged",
      data: { reason: "bot", difficulty: 21 }
    }))).toThrow("invalid difficulty");
  });

  it("enforces regular outbox capacity without dropping priority events", async () => {
    const storage = new InMemoryAuthStorage().cloudStorage;
    const regular = (timestamp: string) => createCloudEvent("app_capacity", {
      type: "login.failed",
      data: { reason: "invalid_credentials" }
    }, new Date(timestamp));

    const first = await storage.enqueueCloudEvent(
      regular("2026-08-22T10:00:00.000Z"),
      null,
      false,
      1
    );
    const rejected = await storage.enqueueCloudEvent(
      regular("2026-08-22T10:00:01.000Z"),
      null,
      false,
      1
    );
    const deletion = createCloudEvent("app_capacity", {
      type: "user.deleted",
      data: { userId: "usr_capacity" },
      userId: "usr_capacity",
      entity: { type: "user", id: "usr_capacity" },
      priority: true
    });
    const priority = await storage.enqueueCloudEvent(
      deletion,
      { type: "user", id: "usr_capacity" },
      true
    );

    expect(first).not.toBeNull();
    expect(rejected).toBeNull();
    expect(priority).toMatchObject({ type: "user.deleted", entityVersion: 1 });
    expect(await storage.countCloudOutbox()).toBe(2);
  });

  it("keeps the first Cloud configuration value", async () => {
    const storage = new InMemoryAuthStorage().cloudStorage;

    await expect(storage.getOrCreateCloudConfig("challenge_keys", "first"))
      .resolves.toBe("first");
    await expect(storage.getOrCreateCloudConfig("challenge_keys", "second"))
      .resolves.toBe("first");
  });

  it("keeps the earliest data-gap timestamp", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-24T12:00:00.000Z"));
    try {
      const storage = new InMemoryAuthStorage();
      const runtime = new CloudRuntime({
        key: cloudKey,
        endpoint: "https://cloud.example.com",
        flushMode: "manual",
        onWarning() {},
        fetch: (async () => Response.json({ accepted: true })) as typeof fetch
      }, storage.cloudStorage, storage);
      const event = (timestamp: string) => createCloudEvent("app_gap", {
        type: "login.failed",
        data: { reason: "invalid_credentials" }
      }, new Date(timestamp));
      await storage.cloudStorage.setCloudConfig(
        "data_gap_started_at",
        "2026-08-17T08:00:00.000Z"
      );
      await storage.cloudStorage.enqueueCloudEvent(
        event("2026-08-16T10:00:00.000Z"), null, false
      );

      await runtime.flushOutbox();

      await expect(storage.cloudStorage.getCloudConfig("data_gap_started_at"))
        .resolves.toBe("2026-08-16T10:00:00.000Z");
    } finally {
      vi.useRealTimers();
    }
  });

  it("flushes explicit large outbox limits in Cloud-sized batches", async () => {
    const storage = new InMemoryAuthStorage();
    const batchSizes: number[] = [];
    const runtime = new CloudRuntime({
      key: cloudKey,
      endpoint: "https://cloud.example.com",
      flushMode: "manual",
      fetch: (async (_input, init) => {
        const body = JSON.parse(String(init?.body)) as { events: unknown[] };
        batchSizes.push(body.events.length);
        return Response.json({ accepted: true });
      }) as typeof fetch
    }, storage.cloudStorage, storage);

    await Promise.all(Array.from({ length: 120 }, () =>
      storage.cloudStorage.enqueueCloudEvent(createCloudEvent("app_batching", {
        type: "login.failed",
        data: { reason: "invalid_credentials" }
      }), null, false)
    ));

    await expect(runtime.flushOutbox({ limit: 120 })).resolves.toEqual({
      sent: 120,
      failed: 0,
      remaining: 0
    });
    expect(batchSizes).toEqual([50, 50, 20]);
  });

  it("reports and clears a persisted data gap after ingestion resumes", async () => {
    const storage = new InMemoryAuthStorage();
    const requests: Array<{ path: string; body: unknown }> = [];
    const runtime = new CloudRuntime({
      key: cloudKey,
      endpoint: "https://cloud.example.com",
      flushMode: "manual",
      fetch: (async (input, init) => {
        requests.push({
          path: new URL(String(input)).pathname,
          body: JSON.parse(String(init?.body)) as unknown
        });
        return Response.json({ accepted: true });
      }) as typeof fetch
    }, storage.cloudStorage, storage);
    await storage.cloudStorage.setCloudConfig(
      "data_gap_started_at",
      "2026-08-24T10:00:00.000Z"
    );
    await storage.cloudStorage.enqueueCloudEvent(createCloudEvent("app_gap", {
      type: "login.failed",
      data: { reason: "invalid_credentials" }
    }), null, false);

    await runtime.flushOutbox();

    expect(requests.map(({ path }) => path)).toEqual([
      "/ingest/events",
      "/ingest/gaps"
    ]);
    expect(requests[1]?.body).toMatchObject({
      startedAt: "2026-08-24T10:00:00.000Z"
    });
    await expect(storage.cloudStorage.getCloudConfig("data_gap_started_at"))
      .resolves.toBe("");
  });

  it("discards expired events without discarding fresh events in the same flush", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-24T12:00:00.000Z"));
    try {
      const storage = new InMemoryAuthStorage();
      const requests: Array<{ path: string; body: unknown }> = [];
      const warnings: string[] = [];
      const runtime = new CloudRuntime({
        key: cloudKey,
        endpoint: "https://cloud.example.com",
        flushMode: "manual",
        onWarning: (message) => warnings.push(message),
        fetch: (async (input, init) => {
          requests.push({
            path: new URL(String(input)).pathname,
            body: JSON.parse(String(init?.body)) as unknown
          });
          return Response.json({ accepted: true });
        }) as typeof fetch
      }, storage.cloudStorage, storage);
      const event = (timestamp: string) => createCloudEvent("app_gap", {
        type: "login.failed",
        data: { reason: "invalid_credentials" }
      }, new Date(timestamp));
      await storage.cloudStorage.enqueueCloudEvent(
        event("2026-08-16T10:00:00.000Z"), null, false
      );
      await storage.cloudStorage.enqueueCloudEvent(
        event("2026-08-24T10:00:00.000Z"), null, false
      );

      await expect(runtime.flushOutbox()).resolves.toEqual({
        sent: 1,
        failed: 0,
        remaining: 0
      });

      expect(requests.map(({ path }) => path)).toEqual([
        "/ingest/events",
        "/ingest/gaps"
      ]);
      expect(requests[0]?.body).toMatchObject({
        events: [{ timestamp: "2026-08-24T10:00:00.000Z" }]
      });
      expect(requests[1]?.body).toMatchObject({
        startedAt: "2026-08-16T10:00:00.000Z"
      });
      expect(warnings).toContain(
        "Cloud events outside the seven-day ingestion window were discarded and recorded as a data gap."
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("purges pending delivery events linked through the recipient user", async () => {
    const authStorage = new InMemoryAuthStorage();
    const target = await createOwnAuth({ storage: authStorage }).createUser({ email: "delivery-recipient@example.com" });
    const storage = authStorage.cloudStorage;
    const delivery = createCloudEvent("app_erasure", {
      type: "email.requested",
      data: {
        messageId: "message_1",
        type: "magic_link",
        recipientUserId: target.id
      }
    });
    const unrelated = createCloudEvent("app_erasure", {
      type: "login.failed",
      data: { reason: "invalid_credentials" }
    });
    await storage.enqueueCloudEvent(delivery, null, false);
    await storage.enqueueCloudEvent(unrelated, null, false);

    expect(await storage.purgeCloudOutboxForUser(target.id)).toBe(1);
    expect(await storage.countCloudOutbox()).toBe(1);
  });

  it("purges pending invitation events linked through the user's email", async () => {
    const authStorage = new InMemoryAuthStorage();
    const inviter = await createOwnAuth({ storage: authStorage }).createUser({ email: "inviter@example.com" });
    const storage = authStorage.cloudStorage;
    const invitation = createCloudEvent("app_erasure", {
      type: "org.invite.created",
      data: {
        orgId: "org_1",
        invitationId: "invite_1",
        inviteeEmail: "User@Example.com",
        role: "member",
        expiresAt: "2026-09-01T00:00:00.000Z"
      },
      userId: inviter.id,
      entity: { type: "org", id: "org_1" }
    });
    await storage.enqueueCloudEvent(invitation, { type: "org", id: "org_1" }, false);

    expect(await storage.purgeCloudOutboxForUser(
      "usr_delete",
      "user@example.com"
    )).toBe(1);
    expect(await storage.countCloudOutbox()).toBe(0);
  });

  it("purges only audit targets that identify the user", async () => {
    const storage = new InMemoryAuthStorage().cloudStorage;
    for (const targetType of ["user", "organisation"] as const) {
      await storage.enqueueCloudEvent(createCloudEvent("app_erasure", {
        type: "audit.entry",
        data: {
          action: "resource.updated",
          targetId: "usr_delete",
          targetType,
          metadata: {}
        }
      }), null, false);
    }

    expect(await storage.purgeCloudOutboxForUser("usr_delete")).toBe(1);
    expect(await storage.countCloudOutbox()).toBe(1);
  });

  it("accepts phone-only users without inventing an email address", async () => {
    const storage = new InMemoryAuthStorage();
    const auth = createOwnAuth({
      storage,
      tokenPepper: "cloud-phone-user-token-pepper",
      plugins: [cloud({ key: cloudKey, flushMode: "manual" })]
    });

    const user = await auth.createUser({ phone: "+14155551234" });
    const records = await storage.cloudStorage.claimCloudOutbox(
      10,
      new Date(),
      new Date(Date.now() + 30_000)
    );

    const created = records.map(({ event }) => event).filter(({ type }) => type === "user.created");
    expect(created).toHaveLength(1);
    expect(created).toContainEqual(expect.objectContaining({
      type: "user.created",
      data: expect.objectContaining({ userId: user.id, email: null })
    }));
  });

  it("records passwordless signups with their complete authentication methods", async () => {
    let magicLink = "";
    const storage = new InMemoryAuthStorage();
    const auth = createOwnAuth({
      storage,
      tokenPepper: "cloud-passwordless-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        flushMode: "manual",
        fetch: (async (input, init) => {
          if (String(input).endsWith("/delivery/email")) {
            const body = JSON.parse(String(init?.body)) as {
              templateData: { url: string };
            };
            magicLink = body.templateData.url;
            return Response.json({ messageId: "msg_magic", status: "queued" });
          }
          return Response.json({ accepted: true });
        }) as typeof fetch
      })]
    });

    await auth.requestMagicLink({ email: "passwordless@example.com" });
    const token = new URL(magicLink).searchParams.get("token");
    expect(token).toBeTruthy();
    await auth.verifyMagicLink({ token: token as string });

    const records = await storage.cloudStorage.claimCloudOutbox(
      50,
      new Date(),
      new Date(Date.now() + 30_000)
    );
    expect(records.map(({ event }) => event)).toContainEqual(expect.objectContaining({
      type: "user.created",
      data: expect.objectContaining({
        email: "passwordless@example.com",
        authMethods: ["magic_link"]
      })
    }));
  });

  it("classifies failed authentication events by flow", () => {
    const request = {};
    const error = (code: string) => ({ code });

    expect(failedLoginEvent({
      operation: "signInEmailPassword",
      input: {},
      error: error("invalid_credentials"),
      request
    })?.data.reason).toBe("user_not_found");
    expect(failedLoginEvent({
      operation: "signInEmailPassword",
      input: {},
      userId: "usr_1",
      error: error("invalid_credentials"),
      request
    })?.data.reason).toBe("invalid_password");
    expect(failedLoginEvent({
      operation: "verifyMagicLink",
      input: {},
      error: error("token_invalid"),
      request
    })?.data.reason).toBe("invalid_credentials");
    expect(failedLoginEvent({
      operation: "completeOAuthSignIn",
      input: {},
      error: error("cloud_access_denied"),
      request
    })?.data.reason).toBe("blocked");
  });

  it("backfills user and session authentication methods", async () => {
    const requests: Array<Record<string, unknown>> = [];
    const storage = new InMemoryAuthStorage();
    const auth = createOwnAuth({
      storage,
      tokenPepper: "cloud-backfill-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        flushMode: "manual",
        fetch: (async (_input, init) => {
          requests.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
          return Response.json({ accepted: true });
        }) as typeof fetch
      })]
    });
    const signup = await auth.signUpEmailPassword({
      email: "backfill@example.com",
      password: "correct-horse"
    });
    const now = new Date();
    await storage.createAccount({
      id: "acc_cloud_google",
      userId: signup.user.id,
      provider: "google",
      providerAccountId: "google-cloud-user",
      providerEmail: signup.user.email,
      providerPhone: null,
      createdAt: now,
      updatedAt: now
    });
    await storage.createTotpFactor({
      id: "mfa_cloud_totp",
      userId: signup.user.id,
      status: "active",
      ciphertext: "ciphertext",
      nonce: "nonce",
      encryptionKeyId: "test-key",
      lastUsedTimestep: null,
      createdAt: now,
      updatedAt: now,
      disabledAt: null
    });
    await storage.createPasskeyCredential({
      id: "pky_cloud",
      userId: signup.user.id,
      credentialId: "cloud-credential",
      publicKey: new Uint8Array([1, 2, 3]),
      counter: 0,
      transports: [],
      deviceType: "multiDevice",
      backedUp: true,
      discoverable: true,
      name: "Cloud passkey",
      metadata: {},
      createdAt: now,
      updatedAt: now,
      lastUsedAt: null
    });
    await auth.createOrganisation({ name: "Backfill Org", ownerUserId: signup.user.id });

    await auth.cloud.backfill();

    const records = requests.flatMap((request) => request.records as Array<{
      type: string;
      data: Record<string, unknown>;
    }> ?? []);
    expect(records).toEqual(expect.arrayContaining([
      expect.objectContaining({
        type: "user",
        data: expect.objectContaining({
          authMethods: ["google", "magic_link", "passkey", "password", "totp"]
        })
      }),
      expect.objectContaining({
        type: "session",
        data: expect.objectContaining({ authMethods: ["password"] })
      }),
      expect.objectContaining({
        type: "org",
        data: expect.objectContaining({ ownerId: signup.user.id })
      }),
      expect.objectContaining({
        type: "member",
        data: expect.objectContaining({
          userId: signup.user.id,
          role: "owner"
        })
      })
    ]));
  });

  it("uses the Cloud delivery contract and maps internal email types", async () => {
    const requests: Array<{ url: string; body: Record<string, unknown> }> = [];
    const storage = new InMemoryAuthStorage();
    const auth = createOwnAuth({
      storage,
      tokenPepper: "cloud-delivery-contract-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        endpoint: "https://cloud.example.com",
        flushMode: "manual",
        fetch: (async (input, init) => {
          requests.push({
            url: String(input),
            body: JSON.parse(String(init?.body)) as Record<string, unknown>
          });
          return Response.json({ messageId: "msg_cloud", status: "queued" });
        }) as typeof fetch
      })]
    });
    await auth.createUser({ email: "verification@example.com" });

    await auth.requestEmailVerification({ email: "verification@example.com" });

    const request = requests.find(({ url }) => url.endsWith("/delivery/email"));
    expect(request?.body).toMatchObject({
      type: "verification",
      to: "verification@example.com",
      recipientUserId: expect.any(String),
      idempotencyKey: expect.any(String),
      templateData: {
        url: expect.any(String),
        expiresAt: expect.any(String)
      }
    });
    expect(request?.body).not.toHaveProperty("token");

    const records = await storage.cloudStorage.claimCloudOutbox(
      50,
      new Date(),
      new Date(Date.now() + 30_000)
    );
    expect(records.map(({ event }) => event)).toContainEqual(expect.objectContaining({
      type: "email.requested",
      data: expect.objectContaining({ messageId: "msg_cloud", type: "verification" })
    }));
  });

  it("keeps explicitly configured delivery providers when Cloud is enabled", async () => {
    const emailSend = vi.fn();
    const smsSend = vi.fn();
    const cloudFetch = vi.fn(async () => Response.json({ accepted: true }));
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "cloud-provider-precedence-token-pepper",
      emailProvider: { send: emailSend },
      smsProvider: { send: smsSend },
      plugins: [cloud({
        key: cloudKey,
        flushMode: "manual",
        fetch: cloudFetch as typeof fetch
      })]
    });
    await auth.createUser({
      email: "provider@example.com",
      phone: "+14155550199"
    });

    await auth.requestMagicLink({ email: "provider@example.com" });
    await auth.requestSmsOtp({ phone: "+14155550199", purpose: "phone_login" });

    expect(emailSend).toHaveBeenCalledOnce();
    expect(smsSend).toHaveBeenCalledOnce();
    expect(cloudFetch).not.toHaveBeenCalled();
  });

  it("records projected audit events through the durable outbox", async () => {
    const storage = new InMemoryAuthStorage();
    const auth = createOwnAuth({
      storage,
      tokenPepper: "cloud-audit-event-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        endpoint: "https://cloud.example.com",
        flushMode: "manual",
        fetch: (async () => Response.json({ accepted: true })) as typeof fetch
      })]
    });

    await auth.signUpEmailPassword({
      email: "audit@example.com",
      password: "correct-horse"
    });
    const records = await storage.cloudStorage.claimCloudOutbox(
      10,
      new Date(),
      new Date(Date.now() + 30_000)
    );

    expect(records.map(({ event }) => event.type)).toEqual(
      expect.arrayContaining(["user.created", "audit.entry"])
    );
  });

  it("does not turn a committed auth operation into a failure when Cloud sync fails", async () => {
    const warnings: string[] = [];
    const storage = new InMemoryAuthStorage();
    storage.listAccountsByUserId = async () => {
      throw new Error("projection unavailable");
    };
    const auth = createOwnAuth({
      storage,
      tokenPepper: "cloud-post-operation-failure-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        flushMode: "manual",
        onWarning: (message) => warnings.push(message)
      })]
    });

    await expect(auth.createUser({ email: "committed@example.com" }))
      .resolves.toMatchObject({ email: "committed@example.com" });
    expect(warnings).toContain(
      "Cloud post-operation sync failed: Error"
    );
  });

  it("warns when Cloud delivery fails without an error callback", async () => {
    const warnings: string[] = [];
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "cloud-delivery-warning-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        flushMode: "manual",
        fetch: (async (input) => String(input).endsWith("/delivery/email")
          ? Response.json({ error: { code: "quota_exhausted" } }, { status: 429 })
          : Response.json({ accepted: true })) as typeof fetch,
        onWarning: (message) => warnings.push(message)
      })]
    });

    const result = await auth.requestMagicLink({ email: "warning@example.com" });

    expect(result.delivery).toEqual({ status: "failed", reason: "quota_exhausted" });
    expect(warnings).toContain(
      "Own Auth Cloud email delivery failed: quota_exhausted"
    );
  });

  it("projects committed SAML and SCIM membership changes", async () => {
    const storage = new InMemoryAuthStorage();
    const auth = createOwnAuth({
      storage,
      tokenPepper: "cloud-federated-membership-token-pepper",
      plugins: [cloud({ key: cloudKey, flushMode: "manual" })]
    });
    const user = await auth.createUser({ email: "federated@example.com" });
    const { organisation, ownerMembership } = await auth.createOrganisation({
      name: "Federated Org",
      ownerUserId: user.id
    });
    await storage.cloudStorage.clearCloudOutbox(true);
    const runtime = new CloudRuntime({
      key: cloudKey,
      endpoint: "https://cloud.example.com",
      flushMode: "manual"
    }, storage.cloudStorage, storage);

    await runtime.recordAuditEvent({
      id: "evt_saml_member",
      eventType: "saml.member_provisioned",
      actorUserId: user.id,
      targetUserId: user.id,
      organisationId: organisation.id,
      apiKeyId: null,
      ipAddress: null,
      userAgent: null,
      metadata: {},
      createdAt: new Date()
    });
    await storage.updateOrganisationMember(ownerMembership.id, {
      status: "removed",
      removedAt: new Date(),
      updatedAt: new Date()
    });
    await runtime.afterOperation({
      operation: "scim.deleteUser",
      input: { organisationId: organisation.id },
      request: {},
      result: {
        membershipId: ownerMembership.id,
        userId: user.id,
        active: false
      }
    });

    const records = await storage.cloudStorage.claimCloudOutbox(
      20,
      new Date(),
      new Date(Date.now() + 30_000)
    );
    expect(records.map(({ event }) => event.type)).toEqual(expect.arrayContaining([
      "audit.entry",
      "org.member.added",
      "org.member.removed"
    ]));
  });

  it("sends the documented security-check request shape", async () => {
    const requests: Record<string, unknown>[] = [];
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "cloud-security-contract-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        flushMode: "manual",
        security: { botDetection: { enabled: true } },
        fetch: (async (input, init) => {
          if (String(input).endsWith("/security/check")) {
            requests.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
            return Response.json({ decision: "allow" });
          }
          return Response.json({ accepted: true });
        }) as typeof fetch
      })]
    });
    await auth.createUser({ email: "security-contract@example.com", password: "correct-horse" });

    await auth.signInEmailPassword({
      email: "security-contract@example.com",
      password: "correct-horse"
    });

    expect(requests).toEqual([{
      action: "login",
      appId: expect.stringMatching(/^app_/),
      config: { botDetection: { enabled: true } },
      userId: expect.any(String)
    }]);
  });

  it("projects session revocation when a user signs out", async () => {
    const storage = new InMemoryAuthStorage();
    const auth = createOwnAuth({
      storage,
      tokenPepper: "cloud-session-revocation-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        endpoint: "https://cloud.example.com",
        flushMode: "manual",
        fetch: (async () => Response.json({ accepted: true })) as typeof fetch
      })]
    });
    const signup = await auth.signUpEmailPassword({
      email: "signout@example.com",
      password: "correct-horse"
    });

    await auth.signOut(signup.sessionToken);

    const records = await storage.cloudStorage.claimCloudOutbox(
      20,
      new Date(),
      new Date(Date.now() + 30_000)
    );
    const revoked = records
      .map(({ event }) => event)
      .filter(({ type }) => type === "session.revoked");
    expect(revoked).toEqual([
      expect.objectContaining({
        data: expect.objectContaining({
          sessionId: signup.session.id,
          userId: signup.user.id,
          reason: "logout"
        })
      })
    ]);
  });

  it("does not expose a command path without a webhook signing secret", () => {
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "cloud-no-webhook-token-pepper",
      plugins: [cloud({ key: cloudKey })]
    });

    expect(auth.cloud.webhookPath).toBeNull();
  });

  it("rejects non-durable Cloud storage in production", () => {
    const previousNodeEnv = process.env.NODE_ENV;
    const previousPepper = process.env.OWN_AUTH_TOKEN_PEPPER;
    process.env.NODE_ENV = "production";
    process.env.OWN_AUTH_TOKEN_PEPPER = "production-cloud-token-pepper-at-least-32-bytes";

    try {
      expect(() => createOwnAuth({
        storage: new InMemoryAuthStorage(),
        plugins: [cloud({ key: cloudKey })]
      })).toThrow(
        "Own Auth Cloud requires durable storage in production. " +
        "Use Postgres, D1, or a durable custom CloudCapableStorage adapter."
      );
    } finally {
      if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previousNodeEnv;
      if (previousPepper === undefined) delete process.env.OWN_AUTH_TOKEN_PEPPER;
      else process.env.OWN_AUTH_TOKEN_PEPPER = previousPepper;
    }
  });

  it("returns a failed delivery result without failing token creation", async () => {
    const onDeliveryError = vi.fn();
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "cloud-test-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        endpoint: "https://cloud.example.com",
        onDeliveryError,
        fetch: (async (input) => {
          const url = String(input);
          return url.endsWith("/delivery/email")
            ? Response.json({ code: "quota_exhausted" }, { status: 429 })
            : Response.json({ accepted: true });
        }) as typeof fetch
      })]
    });
    await auth.createUser({ email: "delivery@example.com" });

    const result = await auth.requestMagicLink({ email: "delivery@example.com" });

    expect(result).toMatchObject({
      sent: false,
      delivery: { status: "failed", reason: "quota_exhausted" }
    });
    expect(onDeliveryError).toHaveBeenCalledWith(expect.objectContaining({
      channel: "email",
      code: "quota_exhausted",
      status: 429
    }));
  });

  it("returns a failed delivery result when a Cloud invitation cannot be sent", async () => {
    const storage = new InMemoryAuthStorage();
    const auth = createOwnAuth({
      storage,
      tokenPepper: "cloud-invitation-delivery-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        endpoint: "https://cloud.example.com",
        flushMode: "manual",
        fetch: (async (input) => String(input).endsWith("/delivery/email")
          ? Response.json({ code: "quota_exhausted" }, { status: 429 })
          : Response.json({ accepted: true })) as typeof fetch
      })]
    });
    const owner = await auth.signUpEmailPassword({
      email: "cloud-invite-owner@example.com",
      password: "correct-horse"
    });
    const { organisation } = await auth.createOrganisation({
      name: "Cloud invitation",
      ownerUserId: owner.user.id
    });

    const result = await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: "cloud-invitee@example.com"
    });

    expect(result.delivery).toEqual({
      status: "failed",
      reason: "quota_exhausted"
    });
    expect(result.invitation.status).toBe("pending");
    const records = await storage.cloudStorage.claimCloudOutbox(
      50,
      new Date(),
      new Date(Date.now() + 30_000)
    );
    expect(records.map(({ event }) => event)).toContainEqual(expect.objectContaining({
      type: "org.invite.created",
      meta: expect.objectContaining({ userId: owner.user.id })
    }));
  });

  it("lets the Cloud client solve a challenge and retry once", async () => {
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "cloud-challenge-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        endpoint: "https://cloud.example.com",
        challengeSecret: "challenge-secret-that-is-at-least-32-bytes",
        security: { botDetection: { enabled: true, minimumDifficulty: 1 } },
        fetch: (async (input) => String(input).endsWith("/security/check")
          ? Response.json({ decision: "challenge", recommendedDifficulty: 1 })
          : Response.json({ accepted: true })) as typeof fetch
      })]
    });
    await auth.createUser({ email: "challenge@example.com", password: "correct-horse" });
    const handler = createOwnAuthHandler(auth);
    const client = createOwnAuthClient({
      baseURL: "http://localhost/api/auth",
      plugins: [cloudClient({ maximumSolveMs: 1_000 })],
      fetch: ((input, init) => {
        const url = input instanceof Request ? input.url : String(input);
        return handler(new Request(url, {
          ...init,
          headers: { ...Object.fromEntries(new Headers(init?.headers)), origin: "http://localhost" }
        }));
      }) as typeof fetch
    });

    await expect(client.signInEmailPassword({
      email: "challenge@example.com",
      password: "correct-horse"
    })).resolves.toMatchObject({ user: { email: "challenge@example.com" } });
  });

  it("lets a denied user appeal through a stronger one-time challenge", async () => {
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "cloud-appeal-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        endpoint: "https://cloud.example.com",
        challengeSecret: "challenge-secret-that-is-at-least-32-bytes",
        security: { botDetection: { enabled: true, minimumDifficulty: 1 } },
        fetch: (async (input) => String(input).endsWith("/security/check")
          ? Response.json({ decision: "deny", reason: "bot", recommendedDifficulty: 1 })
          : Response.json({ accepted: true })) as typeof fetch
      })]
    });
    await auth.createUser({ email: "appeal@example.com", password: "correct-horse" });
    const handler = createOwnAuthHandler(auth);
    const client = createOwnAuthClient({
      baseURL: "http://localhost/api/auth",
      plugins: [cloudClient({ maximumSolveMs: 5_000 })],
      fetch: ((input, init) => {
        const url = input instanceof Request ? input.url : String(input);
        return handler(new Request(url, {
          ...init,
          headers: { ...Object.fromEntries(new Headers(init?.headers)), origin: "http://localhost" }
        }));
      }) as typeof fetch
    });

    await expect(client.signInEmailPassword({
      email: "appeal@example.com",
      password: "correct-horse"
    })).resolves.toMatchObject({ user: { email: "appeal@example.com" } });
  });

  it("allows only one security probe when an open circuit becomes eligible", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    let checks = 0;
    let releaseProbe: (() => void) | undefined;
    const probe = new Promise<void>((resolve) => {
      releaseProbe = resolve;
    });
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "cloud-circuit-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        endpoint: "https://cloud.example.com",
        flushMode: "manual",
        security: { botDetection: { enabled: true } },
        fetch: (async (input) => {
          if (!String(input).endsWith("/security/check")) {
            return Response.json({ accepted: true });
          }
          checks += 1;
          if (checks <= 5) throw new Error("security unavailable");
          await probe;
          return Response.json({ decision: "allow" });
        }) as typeof fetch
      })]
    });
    await auth.createUser({ email: "circuit@example.com", password: "correct-horse" });

    try {
      for (let attempt = 0; attempt < 5; attempt += 1) {
        await auth.signInEmailPassword({
          email: "circuit@example.com",
          password: "correct-horse"
        });
      }
      await auth.signInEmailPassword({
        email: "circuit@example.com",
        password: "correct-horse"
      });
      expect(checks).toBe(5);

      vi.setSystemTime(Date.now() + 30_001);
      const first = auth.signInEmailPassword({
        email: "circuit@example.com",
        password: "correct-horse"
      });
      const second = auth.signInEmailPassword({
        email: "circuit@example.com",
        password: "correct-horse"
      });
      await second;
      expect(checks).toBe(6);
      releaseProbe?.();
      await first;
      expect(checks).toBe(6);
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not cache an unauthenticated deny for a shared IP", async () => {
    let checks = 0;
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "cloud-uncached-deny-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        flushMode: "manual",
        security: { botDetection: { enabled: true } },
        fetch: (async (input) => {
          if (String(input).endsWith("/security/check")) {
            checks += 1;
            return Response.json({ decision: "deny", reason: "bot" });
          }
          return Response.json({ accepted: true });
        }) as typeof fetch
      })]
    });
    const handler = createOwnAuthHandler(auth);

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = await signInRequest(handler, "missing@example.com");
      expect(response.status).toBe(403);
    }
    expect(checks).toBe(2);
  });

  it("uses cached security decisions only when Cloud is unavailable", async () => {
    let checks = 0;
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "cloud-cache-fallback-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        flushMode: "manual",
        security: { botDetection: { enabled: true } },
        fetch: (async (input) => {
          if (!String(input).endsWith("/security/check")) {
            return Response.json({ accepted: true });
          }
          checks += 1;
          if (checks === 1) {
            return Response.json({ decision: "deny", reason: "credential_stuffing" });
          }
          if (checks === 2) throw new Error("security unavailable");
          return Response.json({ decision: "allow" });
        }) as typeof fetch
      })]
    });
    await auth.createUser({ email: "cached-deny@example.com", password: "correct-horse" });

    const signIn = () => auth.signInEmailPassword({
      email: "cached-deny@example.com",
      password: "correct-horse",
      request: { ipAddress: "203.0.113.20" }
    });

    await expect(signIn()).rejects.toMatchObject({ code: "cloud_access_denied" });
    await expect(signIn()).rejects.toMatchObject({ code: "cloud_access_denied" });
    await expect(signIn()).resolves.toMatchObject({ user: { email: "cached-deny@example.com" } });
    expect(checks).toBe(3);
  });

  it("keeps security decision caches isolated between auth instances", async () => {
    let checks = 0;
    const createAuth = () => createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "cloud-cache-isolation-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        flushMode: "manual",
        security: { botDetection: { enabled: true } },
        fetch: (async (input) => {
          if (String(input).endsWith("/security/check")) {
            checks += 1;
            return Response.json({ decision: "challenge", recommendedDifficulty: 1 });
          }
          return Response.json({ accepted: true });
        }) as typeof fetch
      })]
    });

    await signInRequest(createOwnAuthHandler(createAuth()), "missing@example.com");
    await signInRequest(createOwnAuthHandler(createAuth()), "missing@example.com");

    expect(checks).toBe(2);
  });

  it("returns the same Cloud denial response whether an account exists", async () => {
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "cloud-enumeration-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        flushMode: "manual",
        security: { botDetection: { enabled: true } },
        fetch: (async (input) => String(input).endsWith("/security/check")
          ? Response.json({ decision: "deny", reason: "credential_stuffing" })
          : Response.json({ accepted: true })) as typeof fetch
      })]
    });
    await auth.createUser({ email: "known@example.com", password: "correct-horse" });
    const handler = createOwnAuthHandler(auth);

    const known = await signInRequest(handler, "known@example.com");
    const missing = await signInRequest(handler, "missing@example.com");

    expect({ status: known.status, body: await known.json() }).toEqual({
      status: missing.status,
      body: await missing.json()
    });
  });

  it("fails closed without opening the circuit for Cloud 4xx responses", async () => {
    let checks = 0;
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "cloud-client-error-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        flushMode: "manual",
        security: { botDetection: { enabled: true } },
        fetch: (async (input) => {
          if (String(input).endsWith("/security/check")) {
            checks += 1;
            return Response.json({ code: "invalid_request" }, { status: 400 });
          }
          return Response.json({ accepted: true });
        }) as typeof fetch
      })]
    });
    await auth.createUser({ email: "client-error@example.com", password: "correct-horse" });

    for (let attempt = 0; attempt < 6; attempt += 1) {
      await expect(auth.signInEmailPassword({
        email: "client-error@example.com",
        password: "correct-horse"
      })).rejects.toThrow("Own Auth Cloud returned status 400");
    }

    expect(checks).toBe(6);
  });

  it("verifies and deduplicates signed remote mutation commands", async () => {
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "cloud-command-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        endpoint: "https://cloud.example.com",
        webhookSigningSecret: webhookSecret,
        fetch: (async () => Response.json({ accepted: true })) as typeof fetch
      })]
    });
    const user = await auth.createUser({ email: "command@example.com" });
    const handler = createOwnAuthHandler(auth);
    const body = JSON.stringify({
      action: "user.disable",
      userId: user.id,
      initiatedBy: "dashboard:member_1",
      reason: "manual"
    });
    const timestamp = String(Math.floor(Date.now() / 1_000));
    const nonce = "57f1d0de-d4dd-4729-a41f-9a57994fc001";
    const keyId = "current";
    const canonical = [
      "POST",
      "/api/auth/cloud-webhook",
      timestamp,
      nonce,
      keyId,
      hashSecret(body)
    ].join("\n");
    const headers = {
      "content-type": "application/json",
      "x-ownauth-timestamp": timestamp,
      "x-ownauth-nonce": nonce,
      "x-ownauth-idempotency-key": "e35048a0-8c45-4778-8985-8d6cb5a0d501",
      "x-ownauth-key-id": keyId,
      "x-ownauth-signature": hashSecret(canonical, webhookSecret)
    };

    const first = await handler(new Request("http://localhost/api/auth/cloud-webhook", {
      method: "POST",
      headers,
      body
    }));
    const replay = await handler(new Request("http://localhost/api/auth/cloud-webhook", {
      method: "POST",
      headers,
      body
    }));
    const retryNonce = "57f1d0de-d4dd-4729-a41f-9a57994fc002";
    const retryCanonical = [
      "POST",
      "/api/auth/cloud-webhook",
      timestamp,
      retryNonce,
      keyId,
      hashSecret(body)
    ].join("\n");
    const retry = await handler(new Request("http://localhost/api/auth/cloud-webhook", {
      method: "POST",
      headers: {
        ...headers,
        "x-ownauth-nonce": retryNonce,
        "x-ownauth-signature": hashSecret(retryCanonical, webhookSecret)
      },
      body
    }));
    const missingContentType = await handler(new Request(
      "http://localhost/api/auth/cloud-webhook",
      { method: "POST", body }
    ));
    const unknownBody = JSON.stringify({
      action: "user.enable",
      userId: user.id,
      initiatedBy: "dashboard:member_1",
      reason: "manual",
      unexpected: true
    });
    const unknownNonce = "57f1d0de-d4dd-4729-a41f-9a57994fc003";
    const unknownCanonical = [
      "POST",
      "/api/auth/cloud-webhook",
      timestamp,
      unknownNonce,
      keyId,
      hashSecret(unknownBody)
    ].join("\n");
    const unknownField = await handler(new Request(
      "http://localhost/api/auth/cloud-webhook",
      {
        method: "POST",
        headers: {
          ...headers,
          "x-ownauth-nonce": unknownNonce,
          "x-ownauth-idempotency-key": "e35048a0-8c45-4778-8985-8d6cb5a0d502",
          "x-ownauth-signature": hashSecret(unknownCanonical, webhookSecret)
        },
        body: unknownBody
      }
    ));

    expect(first.status).toBe(200);
    expect(replay.status).toBe(400);
    expect(retry.status).toBe(200);
    expect(missingContentType.status).toBe(415);
    expect(unknownField.status).toBe(400);
    await expect(auth.storage.getUserById(user.id)).resolves.toMatchObject({
      disabledAt: expect.any(Date)
    });
    await expect(auth.storage.listAuditEvents({ userId: user.id })).resolves.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          actorUserId: "dashboard:member_1",
          eventType: "user.disabled",
          targetUserId: user.id
        })
      ])
    );
  });

  it("rejects Cloud commands signed with an expired previous webhook secret", async () => {
    const previousSecret = "previous-webhook-signing-secret-value";
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "cloud-expired-command-token-pepper",
      plugins: [cloud({
        key: cloudKey,
        endpoint: "https://cloud.example.com",
        webhookSigningSecret: webhookSecret,
        webhookPreviousSigningSecret: previousSecret,
        webhookPreviousKeyId: "previous",
        webhookPreviousValidUntil: new Date(Date.now() - 1_000),
        fetch: (async () => Response.json({ accepted: true })) as typeof fetch
      })]
    });
    const user = await auth.createUser({ email: "expired-command@example.com" });
    const handler = createOwnAuthHandler(auth);
    const body = JSON.stringify({
      action: "user.disable",
      userId: user.id,
      initiatedBy: "dashboard:member_1",
      reason: "manual"
    });
    const timestamp = String(Math.floor(Date.now() / 1_000));
    const nonce = "57f1d0de-d4dd-4729-a41f-9a57994fc004";
    const canonical = [
      "POST",
      "/api/auth/cloud-webhook",
      timestamp,
      nonce,
      "previous",
      hashSecret(body)
    ].join("\n");

    const response = await handler(new Request("http://localhost/api/auth/cloud-webhook", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-ownauth-timestamp": timestamp,
        "x-ownauth-nonce": nonce,
        "x-ownauth-idempotency-key": "e35048a0-8c45-4778-8985-8d6cb5a0d503",
        "x-ownauth-key-id": "previous",
        "x-ownauth-signature": hashSecret(canonical, previousSecret)
      },
      body
    }));

    expect(response.status).toBe(401);
  });
});

function cloudFieldValue(field: {
  type: string;
  minimum?: number;
  nullable?: boolean;
  values?: readonly string[];
}): unknown {
  if (field.values?.length) return field.values[0];
  if (field.nullable) return null;
  if (field.type === "date") return new Date().toISOString();
  if (field.type === "integer") return field.minimum ?? 1;
  if (field.type === "object") return {};
  if (field.type === "string-array") return ["value"];
  return "value";
}

function signInRequest(
  handler: ReturnType<typeof createOwnAuthHandler>,
  email: string
): Promise<Response> {
  return handler(new Request("http://localhost/api/auth/sign-in/email", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-forwarded-for": "203.0.113.10",
      origin: "http://localhost"
    },
    body: JSON.stringify({ email, password: "wrong-password" })
  }));
}
