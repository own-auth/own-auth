import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createOwnAuth,
  InMemoryAuthStorage,
  InMemoryRateLimitStore,
  type AtomicUserErasureInput,
  type OwnAuthPluginDefinition,
  type User,
  type UserErasureSubject
} from "../src/index.js";

afterEach(() => vi.restoreAllMocks());

function createErasureAuth(plugins: readonly OwnAuthPluginDefinition[] = []) {
  const storage = new InMemoryAuthStorage();
  const auth = createOwnAuth({ storage, plugins, baseUrl: "http://localhost:3000" });
  return { auth, storage };
}

function erasureInput(user: User, operationId: string = randomUUID()): AtomicUserErasureInput {
  const now = Date.now();
  return {
    userId: user.id, expectedUpdatedAt: user.updatedAt, operationId,
    organisations: [], pendingStores: [], protectedUntil: now, now, cloudEvent: null
  };
}

describe("User erasure cleanup", () => {
  it("erases login and audit records while preserving another account that references the user", async () => {
    const { auth, storage } = createErasureAuth();
    const signup = await auth.signUpEmailPassword({
      email: "erased@example.com", password: "correct-horse"
    });
    const other = await auth.createUser({
      email: "retained@example.com", metadata: { userId: signup.user.id }
    });
    const operationId = randomUUID();

    await expect(auth.eraseUser({
      operationId, sessionToken: signup.sessionToken, confirmation: "erase"
    })).resolves.toEqual({
      operationId, status: "complete", local: "complete",
      cloud: "not_configured", pendingLocalStores: []
    });

    await expect(storage.getUserById(signup.user.id)).resolves.toBeNull();
    await expect(storage.listAccountsByUserId(signup.user.id)).resolves.toEqual([]);
    await expect(auth.getCurrentSession(signup.sessionToken)).resolves.toBeNull();
    await expect(storage.listAuditEvents()).resolves.toEqual([]);
    await expect(storage.getUserById(other.id)).resolves.toEqual(other);
    await expect(storage.userErasureStorage.get(operationId)).resolves.toMatchObject({ subject: null });
  });

  it("keeps failed plugin cleanup pending and resumes it without the deleted login", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const personalRecords = new Map<string, string>();
    let allowCleanup = false;
    const cleanup = vi.fn(async (subject: Readonly<UserErasureSubject>) => {
      if (!allowCleanup) throw new Error("private provider failure");
      personalRecords.delete(subject.userId);
    });
    const { auth, storage } = createErasureAuth([{
      id: "profile-store", version: "1", userErasure: { personalData: true, erase: cleanup }
    }]);
    const signup = await auth.signUpEmailPassword({
      email: "retry@example.com", password: "correct-horse"
    });
    personalRecords.set(signup.user.id, "personal profile");
    const operationId = randomUUID();

    await expect(auth.eraseUser({
      operationId, sessionToken: signup.sessionToken, confirmation: "erase"
    })).resolves.toMatchObject({
      status: "pending", local: "pending", pendingLocalStores: ["plugin:profile-store@1"]
    });
    await expect(storage.getUserById(signup.user.id)).resolves.toBeNull();
    expect(personalRecords.has(signup.user.id)).toBe(true);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(warn.mock.calls)).not.toContain("private provider failure");
    expect(JSON.stringify(warn.mock.calls)).not.toContain(signup.user.id);

    allowCleanup = true;
    await expect(auth.resumeUserErasure({ operationId })).resolves.toMatchObject({
      status: "complete", local: "complete", pendingLocalStores: []
    });
    expect(personalRecords.size).toBe(0);
    expect(cleanup).toHaveBeenCalledTimes(2);
    await expect(storage.userErasureStorage.get(operationId)).resolves.toMatchObject({ subject: null });
  });

  it("rejects delayed sessions and accounts after completion removes the target from the receipt", async () => {
    const { auth, storage } = createErasureAuth();
    const signup = await auth.signUpEmailPassword({
      email: "late-writes@example.com", password: "correct-horse"
    });
    const accounts = await storage.listAccountsByUserId(signup.user.id);
    const operationId = randomUUID();
    await auth.eraseUser({ operationId, sessionToken: signup.sessionToken, confirmation: "erase" });
    await expect(storage.userErasureStorage.get(operationId)).resolves.toMatchObject({ subject: null });

    await expect(storage.createSession(signup.session)).rejects.toMatchObject({ code: "invalid_credentials" });
    await expect(storage.createAccount(accounts[0]!)).rejects.toMatchObject({ code: "invalid_credentials" });
    await expect(storage.listSessionsByUserId(signup.user.id)).resolves.toEqual([]);
    await expect(storage.listAccountsByUserId(signup.user.id)).resolves.toEqual([]);
  });

  it("requires cleanup support from the same immutable plugin definitions used at runtime", async () => {
    const plugin: OwnAuthPluginDefinition = { id: "undeclared-store", version: "1" };
    const { auth, storage } = createErasureAuth([plugin]);
    plugin.userErasure = { personalData: false };
    const signup = await auth.signUpEmailPassword({
      email: "unsupported@example.com", password: "correct-horse"
    });

    await expect(auth.eraseUser({
      operationId: randomUUID(), sessionToken: signup.sessionToken, confirmation: "erase"
    })).rejects.toMatchObject({
      code: "user_erasure_unsupported", details: { stores: ["plugin:undeclared-store"] }
    });
    await expect(storage.getUserById(signup.user.id)).resolves.not.toBeNull();
    await expect(auth.getCurrentSession(signup.sessionToken)).resolves.not.toBeNull();
  });

  it("rejects a plugin cleanup declaration without a callable eraser during configuration", () => {
    expect(() => createErasureAuth([{
      id: "invalid-store", version: "1",
      userErasure: { personalData: true, erase: undefined }
    } as unknown as OwnAuthPluginDefinition])).toThrow("must declare valid user erasure support");
  });

  it("joins pending deletion for the same target and rejects another target using that operation", async () => {
    const { auth, storage } = createErasureAuth();
    const first = await auth.createUser({ email: "first@example.com" });
    const second = await auth.createUser({ email: "second@example.com" });
    const input = { ...erasureInput(first), pendingStores: ["external-store"] };
    await storage.userErasureStorage.eraseAtomically(input);

    await expect(storage.userErasureStorage.eraseAtomically(erasureInput(first))).resolves.toMatchObject({
      operationId: input.operationId
    });
    await expect(storage.userErasureStorage.eraseAtomically(
      erasureInput(second, input.operationId)
    )).rejects.toMatchObject({ code: "erasure_operation_conflict" });
    await expect(storage.getUserById(second.id)).resolves.toEqual(second);
  });

  it("reserves a completed operation without retaining its target or erasing a later account", async () => {
    const { auth, storage } = createErasureAuth();
    const first = await auth.createUser({ email: "reused@example.com" });
    const input = erasureInput(first);
    await storage.userErasureStorage.eraseAtomically(input);
    await auth.getUserErasure({ operationId: input.operationId });
    const replacement = await auth.createUser({ email: first.email! });

    await expect(storage.userErasureStorage.eraseAtomically(
      erasureInput(replacement, input.operationId)
    )).rejects.toMatchObject({ code: "erasure_operation_closed" });
    await expect(storage.getUserById(replacement.id)).resolves.toEqual(replacement);
    await expect(storage.userErasureStorage.get(input.operationId)).resolves.toMatchObject({ subject: null });
  });

  it("removes personal rate limit keys without resetting similar unrelated keys", async () => {
    const store = new InMemoryRateLimitStore();
    const subject: UserErasureSubject = {
      userId: "usr_erased", email: "erased@example.com", phone: "+447700900123",
      references: ["usr_erased", "session_erased", "usr_erased"],
      identities: [{ provider: "google", providerAccountId: "provider_erased" }]
    };
    const personalKeys = [
      "signin:usr_erased", "signin:erased@example.com", "sms:+447700900123",
      "session:session_erased", "oauth:provider_erased"
    ];
    const unrelatedKeys = ["signin:other_usr_erased", "signin:erased@example.com.other"];
    for (const key of [...personalKeys, ...unrelatedKeys]) await store.hit(key, 60_000, 10);

    await store.eraseUser(subject);

    for (const key of personalKeys) expect((await store.hit(key, 60_000, 10)).count).toBe(1);
    for (const key of unrelatedKeys) expect((await store.hit(key, 60_000, 10)).count).toBe(2);
  });
});
