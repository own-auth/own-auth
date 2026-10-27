import { describe, expect, it } from "vitest";
import {
  createOwnAuth,
  createOwnAuthHandler,
  InMemoryAuthStorage,
  type AdministrationAuthorizationContext,
  type AdministrationOptions
} from "../src/index.js";
import { jsonRequest } from "./http-test-helpers.js";

describe("administration HTTP endpoints", () => {
  it("reads and resumes complete erasures and returns typed missing target and operation errors", async () => {
    const { auth, handler } = createAdministrationHttpAuth();
    const actor = await auth.signUpEmailPassword({ email: "erasure-admin@example.com", password: "correct-horse" });
    const target = await auth.createUser({ email: "erasure-target@example.com" });
    const headers = { authorization: `Bearer ${actor.sessionToken}` };
    const operationId = crypto.randomUUID();
    expect((await handler(jsonRequest("/api/auth/admin/user/erase", { userId: target.id, reason: "requested", operationId }, headers))).status).toBe(200);
    const status = await handler(new Request(`http://localhost/api/auth/admin/user-erasure?operationId=${operationId}`, { headers }));
    expect(status.status).toBe(200);
    expect(await status.json()).toMatchObject({ operationId, status: "complete" });
    const resumed = await handler(jsonRequest("/api/auth/admin/user-erasure/resume", { operationId }, headers));
    expect(resumed.status).toBe(200);
    expect(await resumed.json()).toMatchObject({ operationId, status: "complete" });
    const missing = await handler(new Request(`http://localhost/api/auth/admin/user-erasure?operationId=${crypto.randomUUID()}`, { headers }));
    expect(missing.status).toBe(404);
    expect(await missing.json()).toMatchObject({ error: { code: "erasure_operation_not_found" } });
    const missingUser = await handler(jsonRequest("/api/auth/admin/user/erase", { userId: "missing", reason: "requested", operationId: crypto.randomUUID() }, headers));
    expect(missingUser.status).toBe(404);
    expect(await missingUser.json()).toMatchObject({ error: { code: "user_not_found" } });
  });
  it("returns 404 when administration is not configured", async () => {
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "administration-http-test-pepper"
    });
    const handler = createOwnAuthHandler(auth);

    const response = await handler(new Request("http://localhost/api/auth/admin/users"));

    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toMatchObject({ error: { code: "not_found" } });
  });

  it("derives the actor from the session and returns safe user records", async () => {
    const authorization: AdministrationAuthorizationContext[] = [];
    const { auth, handler } = createAdministrationHttpAuth({
      authorize(context) {
        authorization.push(context);
        return true;
      }
    });
    const actor = await auth.signUpEmailPassword({
      email: "actor@example.com",
      password: "correct-horse"
    });
    await auth.signUpEmailPassword({
      email: "target@example.com",
      password: "correct-horse"
    });

    const response = await handler(new Request(
      "http://localhost/api/auth/admin/users?query=target",
      { headers: { authorization: `Bearer ${actor.sessionToken}` } }
    ));
    const body = await response.json() as {
      users: Array<Record<string, unknown>>;
      nextCursor: string | null;
    };

    expect(response.status).toBe(200);
    expect(body.users).toHaveLength(1);
    expect(body.users[0]).not.toHaveProperty("passwordHash");
    expect(authorization[0]).toMatchObject({
      actor: { id: actor.user.id },
      action: "users:list",
      targetUserId: undefined
    });
  });

  it("applies normal CSRF protection to administration mutations", async () => {
    const { auth, handler } = createAdministrationHttpAuth();
    const actor = await auth.signUpEmailPassword({
      email: "actor@example.com",
      password: "correct-horse"
    });
    const target = await auth.createUser({ email: "target@example.com" });

    const response = await handler(new Request(
      "http://localhost/api/auth/admin/user/disable",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: `own_auth_session=${actor.sessionToken}`
        },
        body: JSON.stringify({ userId: target.id, reason: "Support request" })
      }
    ));

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "csrf_failed" }
    });
  });

  it("does not accept an actor ID supplied by the caller", async () => {
    const { auth, handler } = createAdministrationHttpAuth();
    const actor = await auth.signUpEmailPassword({
      email: "actor@example.com",
      password: "correct-horse"
    });
    const target = await auth.createUser({ email: "target@example.com" });

    const response = await handler(jsonRequest(
      "/api/auth/admin/user/disable",
      { userId: target.id, actorUserId: target.id, reason: "Support request" },
      { authorization: `Bearer ${actor.sessionToken}` }
    ));

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "validation_error" }
    });
  });
});

function createAdministrationHttpAuth(
  administration: AdministrationOptions = { authorize: () => true }
) {
  const auth = createOwnAuth({
    storage: new InMemoryAuthStorage(),
    tokenPepper: "administration-http-test-pepper",
    administration
  });
  return { auth, handler: createOwnAuthHandler(auth) };
}
