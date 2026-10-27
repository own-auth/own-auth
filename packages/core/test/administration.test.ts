import { describe, expect, it } from "vitest";
import {
  createOwnAuth,
  InMemoryAuthStorage,
  type AdministrationAuthorizationContext,
  type AuditEvent,
  type RateLimitResult,
  type RateLimitStore,
  type Session,
  type User
} from "../src/index.js";

const tokenPepper = "administration-test-pepper";

describe("Own Auth administration", () => {
  it("requires separate erasure permissions and resolves a disabled sole owner's organisation", async () => {
    const granted = new Set(["users:erase"]);
    const seen: AdministrationAuthorizationContext[] = [];
    const auth = createAdministrationAuth((context) => { seen.push(context); return granted.has(context.action); });
    const actor = await auth.createUser({ email: "erasure-actor@example.com" });
    const target = await auth.createUser({ email: "disabled-owner@example.com" });
    const { organisation } = await auth.createOrganisation({ name: "Owned organisation", ownerUserId: target.id });
    await auth.storage.updateUser(target.id, { disabledAt: new Date() });
    const input = { actorUserId: actor.id, userId: target.id, operationId: crypto.randomUUID(), reason: "requested",
      organisations: [{ organisationId: organisation.id, action: "delete" as const, confirmation: "delete_organisation" as const }] };
    await expect(auth.admin.eraseUser(input)).rejects.toMatchObject({ code: "permission_denied" });
    expect(await auth.storage.getUserById(target.id)).not.toBeNull();
    granted.add("organisations:resolve-erasure");
    expect(await auth.admin.eraseUser(input)).toMatchObject({ status: "complete" });
    await expect(auth.admin.getUserErasure({ actorUserId: actor.id, operationId: input.operationId })).rejects.toMatchObject({ code: "permission_denied" });
    granted.add("erasures:read");
    expect(await auth.admin.getUserErasure({ actorUserId: actor.id, operationId: input.operationId })).toMatchObject({ status: "complete" });
    await expect(auth.admin.resumeUserErasure({ actorUserId: actor.id, operationId: input.operationId })).rejects.toMatchObject({ code: "permission_denied" });
    granted.add("erasures:resume");
    expect(await auth.admin.resumeUserErasure({ actorUserId: actor.id, operationId: input.operationId })).toMatchObject({ status: "complete" });
    await expect(auth.admin.getUserErasure({ actorUserId: actor.id, operationId: crypto.randomUUID() })).rejects.toMatchObject({ code: "erasure_operation_not_found" });
    await expect(auth.admin.eraseUser({ ...input, userId: "missing", operationId: crypto.randomUUID(), organisations: [] })).rejects.toMatchObject({ code: "user_not_found" });
    expect(seen.some((context) => context.action === "organisations:resolve-erasure" && context.organisationId === organisation.id)).toBe(true);
  });
  it("is disabled by default and fails closed when authorization denies or throws", async () => {
    const storage = new InMemoryAuthStorage();
    const unconfigured = createOwnAuth({ storage, tokenPepper });
    const actor = await unconfigured.createUser({ email: "actor@example.com" });

    await expect(unconfigured.admin.listUsers({ actorUserId: actor.id })).rejects.toMatchObject({
      code: "administration_not_configured",
      statusCode: 404
    });

    for (const authorize of [() => false, () => { throw new Error("policy failed"); }]) {
      const auth = createOwnAuth({ storage, tokenPepper, administration: { authorize } });
      await expect(auth.admin.listUsers({ actorUserId: actor.id })).rejects.toMatchObject({
        code: "permission_denied",
        statusCode: 403
      });
    }
  });

  it("requires an administration-capable custom storage adapter only when configured", () => {
    const storage = new InMemoryAuthStorage();
    Object.defineProperty(storage, "listUsers", { value: undefined });

    expect(() => createOwnAuth({ storage, tokenPepper })).not.toThrow();
    expect(() => createOwnAuth({
      storage,
      tokenPepper,
      administration: { authorize: () => true }
    })).toThrow("AdministrationCapableStorage");
  });

  it("passes an immutable actor and an undefined target for list authorization", async () => {
    const seen: AdministrationAuthorizationContext[] = [];
    const auth = createAdministrationAuth((context) => {
      seen.push(context);
      return true;
    });
    const actor = await auth.createUser({ email: "actor@example.com" });

    await auth.admin.listUsers({ actorUserId: actor.id });

    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ action: "users:list", targetUserId: undefined });
    expect(Object.isFrozen(seen[0]?.actor)).toBe(true);
    expect(seen[0]?.actor).not.toHaveProperty("passwordHash");
  });

  it("uses exact ID, exact E.164 phone, then case-insensitive text prefix search", async () => {
    const auth = createAdministrationAuth(() => true);
    const actor = await auth.createUser({ email: "actor@example.com" });
    const alice = await auth.createUser({
      email: "alice@example.com",
      phone: "+14155550101",
      name: "Alice"
    });
    await auth.createUser({ email: `${alice.id}@example.com`, name: "Alice Support" });

    const byId = await auth.admin.listUsers({ actorUserId: actor.id, query: alice.id });
    const byPhone = await auth.admin.listUsers({
      actorUserId: actor.id,
      query: "+14155550101"
    });
    const byFormattedPhone = await auth.admin.listUsers({
      actorUserId: actor.id,
      query: "+1 (415) 555-0101"
    });
    const byPrefix = await auth.admin.listUsers({ actorUserId: actor.id, query: "ALI" });

    expect(byId.items.map(({ id }) => id)).toEqual([alice.id]);
    expect(byPhone.items.map(({ id }) => id)).toEqual([alice.id]);
    expect(byFormattedPhone.items).toEqual([]);
    expect(byPrefix.items).toHaveLength(2);
    expect(byPrefix.items.every(({ email, name }) =>
      email?.startsWith("alice") || name?.startsWith("Alice"))).toBe(true);
  });

  it("paginates deterministically and rejects a modified cursor", async () => {
    const auth = createAdministrationAuth(() => true);
    const actor = await auth.createUser({ email: "actor@example.com" });
    await auth.createUser({ email: "first@example.com" });
    await auth.createUser({ email: "second@example.com" });

    const first = await auth.admin.listUsers({ actorUserId: actor.id, limit: 1 });
    const second = await auth.admin.listUsers({
      actorUserId: actor.id,
      cursor: first.nextCursor ?? undefined,
      limit: 1
    });

    expect(first.nextCursor).toBeTruthy();
    expect(second.items[0]?.id).not.toBe(first.items[0]?.id);
    await expect(auth.admin.listUsers({
      actorUserId: actor.id,
      cursor: `${first.nextCursor}changed`
    })).rejects.toMatchObject({ code: "validation_error" });
  });

  it("disables users before revoking sessions and records secret-free webhook details", async () => {
    const storage = new AdministrationTestStorage();
    const auth = createOwnAuth({
      storage,
      tokenPepper,
      administration: { authorize: () => true },
      webhooks: {
        endpoints: [{
          id: "admin-events",
          url: "https://hooks.example.com/own-auth",
          secret: "administration-webhook-secret-value",
          events: ["user.disabled"]
        }]
      }
    });
    const actor = await auth.signUpEmailPassword({
      email: "actor@example.com",
      password: "correct-horse"
    });
    const target = await auth.signUpEmailPassword({
      email: "target@example.com",
      password: "correct-horse"
    });
    storage.operations.length = 0;

    const disabled = await auth.admin.disableUser({
      actorUserId: actor.user.id,
      userId: target.user.id,
      reason: "Support verified the account takeover report"
    });

    expect(disabled.disabledAt).toBeInstanceOf(Date);
    expect(storage.operations.slice(0, 2)).toEqual(["disable", "revoke"]);
    await expect(auth.getCurrentSession(target.sessionToken)).resolves.toBeNull();
    const audit = (await storage.listAuditEvents({ userId: target.user.id }))
      .find(({ eventType }) => eventType === "user.disabled");
    expect(audit?.metadata).toMatchObject({
      source: "administration",
      reason: "Support verified the account takeover report"
    });

    const claimed = await storage.webhookStorage.claimWebhookDeliveries({
      now: new Date(Date.now() + 1),
      leaseToken: "lease_1",
      leaseExpiresAt: new Date(Date.now() + 60_000),
      limit: 10
    });
    const payload = JSON.parse(claimed[0]?.event.payload ?? "{}") as {
      data?: { details?: Record<string, unknown> };
    };
    expect(payload.data?.details).toEqual({});
    expect(JSON.stringify(payload)).not.toContain("Support verified");
  });

  it("marks stored sessions ineffective when the user is disabled even before cleanup", async () => {
    const auth = createAdministrationAuth(() => true);
    const actor = await auth.createUser({ email: "actor@example.com" });
    const target = await auth.signUpEmailPassword({
      email: "target@example.com",
      password: "correct-horse"
    });
    await auth.storage.updateUser(target.user.id, {
      disabledAt: new Date(),
      updatedAt: new Date()
    });

    const sessions = await auth.admin.listUserSessions({
      actorUserId: actor.id,
      userId: target.user.id
    });

    expect(sessions[0]).toMatchObject({
      id: target.session.id,
      revokedAt: null,
      effectiveStatus: "disabled_user"
    });
  });

  it("revokes sessions even when writing the administrative audit event fails", async () => {
    const storage = new AdministrationTestStorage();
    const auth = createOwnAuth({
      storage,
      tokenPepper,
      administration: { authorize: () => true }
    });
    const actor = await auth.signUpEmailPassword({
      email: "actor@example.com",
      password: "correct-horse"
    });
    const target = await auth.signUpEmailPassword({
      email: "target@example.com",
      password: "correct-horse"
    });
    storage.failAuditWrites = true;

    await expect(auth.admin.disableUser({
      actorUserId: actor.user.id,
      userId: target.user.id,
      reason: "Support request"
    })).rejects.toThrow("audit unavailable");

    await expect(auth.getCurrentSession(target.sessionToken)).resolves.toBeNull();
    await expect(storage.listSessionsByUserId(target.user.id)).resolves.toEqual([
      expect.objectContaining({ revokedAt: expect.any(Date) })
    ]);
  });

  it("uses one shared 120-per-minute rate-limit bucket per actor", async () => {
    const rateLimitStore = new RecordingRateLimitStore();
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      rateLimitStore,
      tokenPepper,
      administration: { authorize: () => true }
    });
    const actor = await auth.createUser({ email: "actor@example.com" });

    await auth.admin.listUsers({ actorUserId: actor.id });

    expect(rateLimitStore.calls.at(-1)).toEqual({
      key: `administration:${actor.id}`,
      windowMs: 60_000,
      limit: 120
    });
  });
});

function createAdministrationAuth(
  authorize: (context: AdministrationAuthorizationContext) => boolean | Promise<boolean>
) {
  return createOwnAuth({
    storage: new InMemoryAuthStorage(),
    tokenPepper,
    administration: { authorize }
  });
}

class RecordingRateLimitStore implements RateLimitStore {
  readonly calls: Array<{ key: string; windowMs: number; limit: number }> = [];

  async hit(key: string, windowMs: number, limit: number): Promise<RateLimitResult> {
    this.calls.push({ key, windowMs, limit });
    return { count: 1, resetAt: new Date(Date.now() + windowMs), allowed: true };
  }

  async reset(): Promise<void> {}
}

class AdministrationTestStorage extends InMemoryAuthStorage {
  readonly operations: string[] = [];
  failAuditWrites = false;

  override updateUser(id: string, patch: Partial<User>): Promise<User | null> {
    if (patch.disabledAt instanceof Date) this.operations.push("disable");
    return super.updateUser(id, patch);
  }

  override updateSession(id: string, patch: Partial<Session>): Promise<Session | null> {
    if (patch.revokedAt instanceof Date) this.operations.push("revoke");
    return super.updateSession(id, patch);
  }

  override createAuditEvent(event: AuditEvent): Promise<AuditEvent> {
    if (this.failAuditWrites) return Promise.reject(new Error("audit unavailable"));
    return super.createAuditEvent(event);
  }
}
