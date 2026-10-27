import { afterEach, describe, expect, it, vi } from "vitest";
import { createOwnAuth, createOwnAuthHandler, InMemoryAuthStorage,
  type OwnAuthOptions, type AdministrationAuthorizationContext } from "../src/index.js";
import { jsonRequest } from "./http-test-helpers.js";

afterEach(() => vi.restoreAllMocks());

function harness(options: OwnAuthOptions = {}) {
  const storage = new InMemoryAuthStorage();
  const auth = createOwnAuth({ storage, baseUrl: "http://localhost", tokenPepper: "erasure-http-pepper", ...options });
  return { auth, storage, handler: createOwnAuthHandler(auth) };
}
function input() { return { operationId: crypto.randomUUID(), confirmation: "erase" as const }; }
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

describe("User erasure HTTP security", () => {
  it("requires MFA for an account whose passkey requires a second factor", async () => {
    const { auth, handler, storage } = harness();
    const signup = await auth.signUpEmailPassword({ email: "passkey-erasure@example.com", password: "correct-horse" });
    const now = new Date();
    await storage.createPasskeyCredential({ id: crypto.randomUUID(), userId: signup.user.id, credentialId: crypto.randomUUID(),
      publicKey: new Uint8Array([1]), counter: 0, transports: [], deviceType: "singleDevice", backedUp: false, discoverable: true,
      name: "Personal passkey", metadata: {}, createdAt: now, updatedAt: now, lastUsedAt: null });
    const response = await handler(jsonRequest("/api/auth/user/erase", input(), bearer(signup.sessionToken)));
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: { code: "reauthentication_required" } });
    expect(await storage.getUserById(signup.user.id)).not.toBeNull();
  });
  it("returns pending and clears cookies if completion storage fails after database deletion", async () => {
    const warning = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { auth, handler, storage } = harness();
    const signup = await auth.signUpEmailPassword({ email: "completion-failure@example.com", password: "correct-horse" });
    vi.spyOn(storage.userErasureStorage, "finish").mockRejectedValueOnce(new Error("private database failure"));
    const request = input();
    const response = await handler(jsonRequest("/api/auth/user/erase", request, bearer(signup.sessionToken)));
    expect(response.status).toBe(202);
    expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
    expect(await response.json()).toMatchObject({ operationId: request.operationId, status: "pending" });
    expect(await storage.getUserById(signup.user.id)).toBeNull();
    expect(await auth.resumeUserErasure({ operationId: request.operationId })).toMatchObject({ status: "complete" });
    expect(JSON.stringify(warning.mock.calls)).not.toContain("private database failure");
  });
  it("erases the authenticated account, clears cookies, and returns a nonpersonal receipt", async () => {
    const { auth, handler, storage } = harness();
    const signup = await auth.signUpEmailPassword({ email: "erase@example.com", password: "correct-horse" });
    const request = input();
    const response = await handler(jsonRequest("/api/auth/user/erase", request, bearer(signup.sessionToken)));
    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
    const body = await response.json();
    expect(body).toEqual({ ...{ operationId: request.operationId }, status: "complete", local: "complete",
      cloud: "not_configured", pendingLocalStores: [] });
    expect(JSON.stringify(body)).not.toContain(signup.user.id);
    expect(JSON.stringify(body)).not.toContain(signup.user.email);
    expect(await storage.getUserById(signup.user.id)).toBeNull();
    expect(await auth.getCurrentSession(signup.sessionToken)).toBeNull();
  });

  it("clears cookies for pending cleanup while preserving durable recovery", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const { auth, handler, storage } = harness({ plugins: [{ id: "private-store", version: "1",
      userErasure: { personalData: true, async erase() { throw new Error("unavailable"); } } }] });
    const signup = await auth.signUpEmailPassword({ email: "pending@example.com", password: "correct-horse" });
    const request = input();
    const response = await handler(jsonRequest("/api/auth/user/erase", request, bearer(signup.sessionToken)));
    expect(response.status).toBe(202);
    expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
    expect(await response.json()).toMatchObject({ status: "pending", pendingLocalStores: ["plugin:private-store@1"] });
    expect(await storage.getUserById(signup.user.id)).toBeNull();
    expect((await storage.userErasureStorage.get(request.operationId))?.pendingStores).toEqual(["plugin:private-store@1"]);
  });

  it("requires a session and refuses another user or actor supplied in the body", async () => {
    const { auth, handler, storage } = harness();
    const signup = await auth.signUpEmailPassword({ email: "caller@example.com", password: "correct-horse" });
    const other = await auth.createUser({ email: "other@example.com" });
    expect((await handler(jsonRequest("/api/auth/user/erase", input()))).status).toBe(401);
    for (const forged of [{ userId: other.id }, { actorUserId: other.id }]) {
      expect((await handler(jsonRequest("/api/auth/user/erase", { ...input(), ...forged }, bearer(signup.sessionToken)))).status).toBe(400);
    }
    expect(await storage.getUserById(signup.user.id)).not.toBeNull();
    expect(await storage.getUserById(other.id)).not.toBeNull();
  });

  it("requires recent authentication and rejects future authentication dates without clearing the session", async () => {
    const { auth, handler, storage } = harness();
    const signup = await auth.signUpEmailPassword({ email: "fresh@example.com", password: "correct-horse" });
    for (const authenticatedAt of [new Date(Date.now() - 6 * 60_000), new Date(Date.now() + 60_000)]) {
      await storage.updateSession(signup.session.id, { authenticatedAt });
      const response = await handler(jsonRequest("/api/auth/user/erase", input(), bearer(signup.sessionToken)));
      expect(response.status).toBe(401);
      expect(await response.json()).toMatchObject({ error: { code: "reauthentication_required" } });
      expect(response.headers.get("set-cookie")).toBeNull();
      expect(await storage.getUserById(signup.user.id)).not.toBeNull();
    }
  });

  it("requires MFA when an active factor exists", async () => {
    const { auth, handler, storage } = harness();
    const signup = await auth.signUpEmailPassword({ email: "mfa@example.com", password: "correct-horse" });
    const now = new Date();
    await storage.createTotpFactor({ id: "factor", userId: signup.user.id, status: "active", ciphertext: "encrypted",
      nonce: "nonce", encryptionKeyId: "key", lastUsedTimestep: null, createdAt: now, updatedAt: now, disabledAt: null });
    const denied = await handler(jsonRequest("/api/auth/user/erase", input(), bearer(signup.sessionToken)));
    expect(denied.status).toBe(401);
    expect(await denied.json()).toMatchObject({ error: { code: "reauthentication_required" } });
    await storage.updateSession(signup.session.id, { assuranceLevel: "aal2", authenticatedAt: new Date() });
    expect((await handler(jsonRequest("/api/auth/user/erase", input(), bearer(signup.sessionToken)))).status).toBe(200);
  });

  it("enforces explicit confirmation, CSRF, and trusted origins before deletion", async () => {
    const { auth, handler, storage } = harness();
    const signup = await auth.signUpEmailPassword({ email: "csrf@example.com", password: "correct-horse" });
    expect((await handler(jsonRequest("/api/auth/user/erase", { ...input(), confirmation: "yes" }, bearer(signup.sessionToken)))).status).toBe(400);
    const noOrigin = new Request("http://localhost/api/auth/user/erase", { method: "POST",
      headers: { "content-type": "application/json", cookie: `own_auth_session=${signup.sessionToken}` }, body: JSON.stringify(input()) });
    expect((await handler(noOrigin)).status).toBe(403);
    expect((await handler(jsonRequest("/api/auth/user/erase", input(), {
      ...bearer(signup.sessionToken), origin: "https://untrusted.example"
    }))).status).toBe(403);
    expect(await storage.getUserById(signup.user.id)).not.toBeNull();
  });

  it("rate limits repeated valid requests that need an ownership decision", async () => {
    const { auth, handler, storage } = harness();
    const signup = await auth.signUpEmailPassword({ email: "limited@example.com", password: "correct-horse" });
    const { organisation } = await auth.createOrganisation({ name: "Sole ownership", ownerUserId: signup.user.id });
    for (let attempt = 0; attempt < 5; attempt++) {
      const response = await handler(jsonRequest("/api/auth/user/erase", input(), bearer(signup.sessionToken)));
      expect(response.status).toBe(409);
      expect(await response.json()).toMatchObject({ error: { code: "user_erasure_ownership_required",
        details: { organisationIds: [organisation.id] } } });
    }
    expect((await handler(jsonRequest("/api/auth/user/erase", input(), bearer(signup.sessionToken)))).status).toBe(429);
    expect(await storage.getUserById(signup.user.id)).not.toBeNull();
  });
});

describe("Administration erasure HTTP authorization", () => {
  it("erases a disabled target and authorizes read and resume independently", async () => {
    const decisions: AdministrationAuthorizationContext[] = [];
    const { auth, handler, storage } = harness({ administration: { authorize(context) {
      decisions.push(context); return context.action === "users:erase";
    } } });
    const actor = await auth.signUpEmailPassword({ email: "admin@example.com", password: "correct-horse" });
    const target = await auth.createUser({ email: "disabled@example.com" });
    await storage.updateUser(target.id, { disabledAt: new Date() });
    const operationId = crypto.randomUUID();
    const erased = await handler(jsonRequest("/api/auth/admin/user/erase", { userId: target.id, operationId, reason: "requested" }, bearer(actor.sessionToken)));
    expect(erased.status).toBe(200);
    expect(decisions[0]).toMatchObject({ actor: { id: actor.user.id }, action: "users:erase", targetUserId: target.id });
    const read = await handler(new Request(`http://localhost/api/auth/admin/user-erasure?operationId=${operationId}`, { headers: bearer(actor.sessionToken) }));
    expect(read.status).toBe(403);
    const resume = await handler(jsonRequest("/api/auth/admin/user-erasure/resume", { operationId }, bearer(actor.sessionToken)));
    expect(resume.status).toBe(403);
    expect(decisions.slice(1).map((decision) => decision.action)).toEqual(["erasures:read", "erasures:resume"]);
    expect(await storage.getUserById(target.id)).toBeNull();
  });

  it("denies unapproved deletion before disclosing whether a target exists", async () => {
    const { auth, handler } = harness({ administration: { authorize: () => false } });
    const actor = await auth.signUpEmailPassword({ email: "denied@example.com", password: "correct-horse" });
    const response = await handler(jsonRequest("/api/auth/admin/user/erase", { userId: "absent", operationId: crypto.randomUUID(), reason: "requested" }, bearer(actor.sessionToken)));
    expect(response.status).toBe(403);
  });

  it("clears cookies for administration self erasure and rejects forged actor IDs", async () => {
    const { auth, handler, storage } = harness({ administration: { authorize: () => true } });
    const actor = await auth.signUpEmailPassword({ email: "self-admin@example.com", password: "correct-horse" });
    const request = { userId: actor.user.id, operationId: crypto.randomUUID(), reason: "requested" };
    expect((await handler(jsonRequest("/api/auth/admin/user/erase", { ...request, actorUserId: "forged" }, bearer(actor.sessionToken)))).status).toBe(400);
    const erased = await handler(jsonRequest("/api/auth/admin/user/erase", request, bearer(actor.sessionToken)));
    expect(erased.status).toBe(200);
    expect(erased.headers.get("set-cookie")).toContain("Max-Age=0");
    expect(await storage.getUserById(actor.user.id)).toBeNull();
  });
});
