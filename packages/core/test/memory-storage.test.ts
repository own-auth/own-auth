import { describe, expect, it } from "vitest";
import {
  InMemoryAuthStorage,
  InMemoryRateLimitStore,
  type AuditEvent,
  type StoredWebhookEvent,
  type User
} from "../src/index.js";
import {
  describeAtomicAdapterConformance
} from "./conformance/atomic-adapter-conformance.js";

describeAtomicAdapterConformance("Memory", async () => {
  const storage = new InMemoryAuthStorage();
  const rateLimits = new InMemoryRateLimitStore();
  return {
    storage: [storage, storage],
    scim: [storage.scimStorage, storage.scimStorage],
    rateLimits: [rateLimits, rateLimits],
    close() {}
  };
});

describe("InMemoryAuthStorage", () => {
  it("keeps entity IDs immutable when applying patches", async () => {
    const storage = new InMemoryAuthStorage();
    const user = memoryUser();
    await storage.createUser(user);

    const updated = await storage.updateUser(user.id, {
      id: "usr_replacement",
      name: "Updated name"
    });

    expect(updated).toMatchObject({ id: user.id, name: "Updated name" });
    await expect(storage.getUserById(user.id)).resolves.toMatchObject({
      id: user.id,
      name: "Updated name"
    });
    await expect(storage.getUserById("usr_replacement")).resolves.toBeNull();
  });

  it("returns all matching users and audit events when no limit is supplied", async () => {
    const storage = new InMemoryAuthStorage();
    const user = memoryUser();
    await storage.createUser(user);
    await storage.createAuditEvent(memoryAuditEvent(user.createdAt));

    await expect(storage.listUsers()).resolves.toEqual([
      expect.objectContaining({ id: user.id })
    ]);
    await expect(storage.listAuditEvents()).resolves.toEqual([
      expect.objectContaining({ id: "whe_memory" })
    ]);
  });

  it("clones webhook delivery seed dates before storing them", async () => {
    const storage = new InMemoryAuthStorage();
    const createdAt = new Date("2026-07-15T12:00:00.000Z");
    const createdAtMs = createdAt.getTime();

    await storage.webhookStorage.recordAuditEventWithWebhooks(
      memoryAuditEvent(createdAt),
      memoryWebhookEvent(createdAt),
      [{
        id: "whd_memory",
        endpointId: "memory-endpoint",
        url: "https://hooks.example.com/own-auth",
        createdAt
      }]
    );

    createdAt.setUTCFullYear(2030);
    const claimed = await storage.webhookStorage.claimWebhookDeliveries({
      now: new Date(createdAtMs + 1),
      leaseToken: "lease_memory",
      leaseExpiresAt: new Date(createdAtMs + 30_000),
      limit: 1
    });

    expect(claimed).toHaveLength(1);
    expect(claimed[0]?.delivery.createdAt.getTime()).toBe(createdAtMs);
    expect(claimed[0]?.delivery.nextAttemptAt.getTime()).toBe(createdAtMs);
  });
});

function memoryUser(): User {
  const now = new Date("2026-07-15T12:00:00.000Z");
  return {
    id: "usr_memory",
    email: "memory@example.com",
    emailVerifiedAt: null,
    phone: null,
    phoneVerifiedAt: null,
    passwordHash: null,
    name: "Memory user",
    imageUrl: null,
    disabledAt: null,
    metadata: {},
    createdAt: now,
    updatedAt: now,
    lastLoginAt: null
  };
}

function memoryAuditEvent(createdAt: Date): AuditEvent {
  return {
    id: "whe_memory",
    eventType: "user.signed_up",
    actorUserId: "usr_memory",
    targetUserId: "usr_memory",
    organisationId: null,
    apiKeyId: null,
    ipAddress: null,
    userAgent: null,
    metadata: { provider: "password" },
    createdAt
  };
}

function memoryWebhookEvent(createdAt: Date): StoredWebhookEvent {
  return {
    id: "whe_memory",
    type: "user.signed_up",
    version: 1,
    payload: "{}",
    createdAt
  };
}
