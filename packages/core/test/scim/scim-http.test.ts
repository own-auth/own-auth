import { describe, expect, it } from "vitest";
import {
  createOwnAuth,
  InMemoryAuthStorage
} from "../../src/index.js";
import { createOwnAuthScimHandler } from "../../src/scim-http.js";

const origin = "https://app.example.com";
const userSchema = "urn:ietf:params:scim:schemas:core:2.0:User";
const patchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

describe("SCIM HTTP contract", () => {
  it("does not expose SCIM routes unless SCIM is configured", async () => {
    const handler = createOwnAuthScimHandler(createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "scim-disabled"
    }));

    const response = await handler(new Request(`${origin}/scim/v2/Users`));

    expect(response.status).toBe(404);
  });

  it("provisions, updates, tombstones, and explicitly restores a user", async () => {
    const harness = await createHarness();
    const created = await harness.request("/Users", {
      method: "POST",
      body: userBody({
        externalId: "workforce-123",
        userName: "Alice@Example.com",
        displayName: "Alice Example",
        emails: [{ value: "ALICE@example.com", primary: true }]
      })
    });
    const createdBody = await created.json() as { id: string; userName: string };

    expect(created.status).toBe(201);
    expect(created.headers.get("etag")).toBe('W/"1"');
    expect(createdBody.userName).toBe("Alice@Example.com");
    const storedUser = await harness.storage.getUserByEmail("alice@example.com");
    expect(storedUser).toMatchObject({ emailVerifiedAt: null });
    expect(await harness.storage.getOrganisationMember(
      harness.organisationId,
      required(storedUser).id
    )).toMatchObject({ role: "member", status: "active" });

    const listed = await harness.request(
      `/Users?filter=${encodeURIComponent('userName eq "ALICE@EXAMPLE.COM"')}`
    );
    const listedBody = await listed.json() as { totalResults: number; Resources: unknown[] };
    expect(listedBody).toMatchObject({ totalResults: 1 });
    expect(listedBody.Resources).toHaveLength(1);

    const patched = await harness.request(`/Users/${createdBody.id}`, {
      method: "PATCH",
      headers: { "if-match": 'W/"1"' },
      body: {
        schemas: [patchSchema],
        Operations: [{ op: "replace", path: "displayName", value: "Alice Updated" }]
      }
    });
    expect(patched.status).toBe(200);
    expect(patched.headers.get("etag")).toBe('W/"2"');

    const stale = await harness.request(`/Users/${createdBody.id}`, {
      method: "PATCH",
      headers: { "if-match": 'W/"1"' },
      body: {
        schemas: [patchSchema],
        Operations: [{ op: "replace", path: "active", value: false }]
      }
    });
    expect(stale.status).toBe(412);

    const deleted = await harness.request(`/Users/${createdBody.id}`, {
      method: "DELETE",
      headers: { "if-match": 'W/"2"' }
    });
    expect(deleted.status).toBe(204);
    expect(await harness.storage.getUserById(required(storedUser).id)).not.toBeNull();
    expect(await harness.storage.getOrganisationMember(
      harness.organisationId,
      required(storedUser).id
    )).toMatchObject({ status: "removed" });

    const reused = await harness.request("/Users", {
      method: "POST",
      body: userBody({
        externalId: "workforce-123",
        userName: "alice@example.com"
      })
    });
    expect(reused.status).toBe(409);

    const restored = await harness.auth.scim.restoreUser({
      connectionId: harness.connectionId,
      actorUserId: harness.ownerId,
      scimUserId: createdBody.id
    });
    expect(restored).toMatchObject({ active: true, deletedAt: null, version: 4 });
    expect(await harness.storage.getOrganisationMember(
      harness.organisationId,
      required(storedUser).id
    )).toMatchObject({ status: "active" });
  });

  it("requires explicit linking unless verified-email linking is enabled", async () => {
    const harness = await createHarness();
    const existing = await harness.auth.signUpEmailPassword({
      email: "existing@example.com",
      password: "secure-password"
    });
    await harness.storage.updateUser(existing.user.id, {
      emailVerifiedAt: new Date("2026-07-18T12:00:00.000Z")
    });
    const body = userBody({
      externalId: "existing-123",
      userName: "existing@example.com",
      emails: [{ value: "existing@example.com", primary: true }]
    });

    expect((await harness.request("/Users", { method: "POST", body })).status).toBe(409);

    await harness.auth.scim.updateConnection({
      connectionId: harness.connectionId,
      actorUserId: harness.ownerId,
      accountLinking: "email"
    });
    const linked = await harness.request("/Users", { method: "POST", body });
    expect(linked.status).toBe(201);
    const resource = await harness.storage.scimStorage.getUserByUserName(
      harness.connectionId,
      "existing@example.com"
    );
    expect(resource?.userId).toBe(existing.user.id);
  });

  it("stores only a token hash and rejects revoked or disabled access", async () => {
    const harness = await createHarness();
    const [stored] = await harness.storage.scimStorage.listTokensByConnectionId(
      harness.connectionId
    );
    expect(stored?.tokenHash).not.toContain(harness.rawToken);
    expect(JSON.stringify(await harness.auth.scim.listTokens({
      connectionId: harness.connectionId,
      actorUserId: harness.ownerId
    }))).not.toContain(stored?.tokenHash);

    await harness.auth.scim.revokeToken({
      connectionId: harness.connectionId,
      actorUserId: harness.ownerId,
      tokenId: required(stored).id
    });
    expect((await harness.request("/Users")).status).toBe(401);

    const replacement = await harness.auth.scim.createToken({
      connectionId: harness.connectionId,
      actorUserId: harness.ownerId,
      name: "Replacement"
    });
    await harness.auth.scim.disableConnection({
      connectionId: harness.connectionId,
      actorUserId: harness.ownerId
    });
    expect((await scimRequest(harness.handler, replacement.rawToken, "/Users")).status).toBe(403);
  });

  it("rejects a SCIM token revoked while its usage timestamp is updated", async () => {
    const harness = await createHarness();
    const storage = harness.storage.scimStorage;
    const updateToken = storage.updateToken.bind(storage);
    let revokeOnUse = true;
    storage.updateToken = async (id, patch) => {
      if (revokeOnUse && patch.lastUsedAt) {
        revokeOnUse = false;
        await updateToken(id, { revokedAt: new Date() });
      }
      return updateToken(id, patch);
    };

    expect((await harness.request("/Users")).status).toBe(401);
  });

  it("serves discovery resources and enforces the request body limit", async () => {
    const harness = await createHarness({ maxRequestBodyBytes: 128 });
    for (const path of [
      "/ServiceProviderConfig",
      "/ResourceTypes",
      "/ResourceTypes/User",
      "/Schemas",
      `/Schemas/${encodeURIComponent(userSchema)}`
    ]) {
      expect((await harness.request(path)).status).toBe(200);
    }

    const oversized = await harness.request("/Users", {
      method: "POST",
      body: userBody({ userName: "a".repeat(200) })
    });
    expect(oversized.status).toBe(413);
  });
});

interface HarnessOptions {
  maxRequestBodyBytes?: number;
}

async function createHarness(options: HarnessOptions = {}) {
  const storage = new InMemoryAuthStorage();
  const auth = createOwnAuth({
    storage,
    tokenPepper: "scim-test-pepper",
    scim: {}
  });
  const owner = await auth.signUpEmailPassword({
    email: `owner-${crypto.randomUUID()}@example.com`,
    password: "secure-password"
  });
  const { organisation } = await auth.createOrganisation({
    name: "Acme",
    ownerUserId: owner.user.id
  });
  const connection = await auth.scim.createConnection({
    organisationId: organisation.id,
    actorUserId: owner.user.id,
    name: "Acme workforce"
  });
  const createdToken = await auth.scim.createToken({
    connectionId: connection.id,
    actorUserId: owner.user.id,
    name: "Identity provider"
  });
  const handler = createOwnAuthScimHandler(auth, {
    maxRequestBodyBytes: options.maxRequestBodyBytes
  });
  return {
    auth,
    storage,
    handler,
    ownerId: owner.user.id,
    organisationId: organisation.id,
    connectionId: connection.id,
    rawToken: createdToken.rawToken,
    request: (path: string, init: ScimRequestInit = {}) =>
      scimRequest(handler, createdToken.rawToken, path, init)
  };
}

interface ScimRequestInit {
  method?: string;
  headers?: Record<string, string>;
  body?: unknown;
}

function scimRequest(
  handler: ReturnType<typeof createOwnAuthScimHandler>,
  token: string,
  path: string,
  init: ScimRequestInit = {}
) {
  const headers = new Headers(init.headers);
  headers.set("authorization", `Bearer ${token}`);
  if (init.body !== undefined) headers.set("content-type", "application/scim+json");
  return handler(new Request(`${origin}/scim/v2${path}`, {
    method: init.method,
    headers,
    body: init.body === undefined ? undefined : JSON.stringify(init.body)
  }));
}

function userBody(attributes: Record<string, unknown>) {
  return { schemas: [userSchema], ...attributes };
}

function required<Value>(value: Value | null | undefined): Value {
  if (value === null || value === undefined) throw new Error("Expected value");
  return value;
}
