import { describe, expect, it } from "vitest";
import { createOwnAuthClient, OwnAuthClientError } from "../src/client.js";
import {
  createOwnAuth,
  createOwnAuthHandler,
  createOwnAuthPluginClientConfiguration,
  defineOwnAuthPlugin,
  InMemoryAuthStorage,
  MemoryEmailProvider,
  MemorySmsProvider
} from "../src/index.js";

function createClientHarness() {
  const auth = createOwnAuth({
    storage: new InMemoryAuthStorage(),
    emailProvider: new MemoryEmailProvider(),
    smsProvider: new MemorySmsProvider(),
    tokenPepper: "client-test-pepper"
  });
  const handler = createOwnAuthHandler(auth);
  let cookie = "";
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    headers.set("origin", "http://localhost");
    if (cookie) {
      headers.set("cookie", cookie);
    }
    const url = input instanceof Request
      ? input.url
      : new URL(input.toString(), "http://localhost").toString();
    const response = await handler(new Request(url, { ...init, headers }));
    const setCookie = response.headers.get("set-cookie");
    if (setCookie) {
      cookie = setCookie.split(";", 1)[0] ?? "";
    }
    return response;
  }) as typeof fetch;

  return createOwnAuthClient({
    baseURL: "http://localhost/api/auth",
    fetch: fetchImpl
  });
}

describe("OwnAuthClient", () => {
  it("clears a cached account when another session has erased it", async () => {
    const client = createOwnAuthClient({ baseURL: "http://localhost/api/auth", fetch: (async (url) =>
      String(url).endsWith("/session") ? Response.json({ session: publicSession("erased-elsewhere@example.com") }) :
        Response.json({ error: { code: "invalid_session", message: "Session is no longer valid" } }, { status: 401 })) as typeof fetch });
    await client.getSession();
    await expect(client.eraseUser({ operationId: crypto.randomUUID(), confirmation: "erase" })).rejects.toMatchObject({ code: "invalid_session" });
    expect(client.getSessionSnapshot().data).toBeNull();
  });

  it("preserves a newer login when an older request returns an invalid session error", async () => {
    let rejectOld!: (response: Response) => void;
    const oldResponse = new Promise<Response>((resolve) => { rejectOld = resolve; });
    const client = createOwnAuthClient({ baseURL: "http://localhost/api/auth", fetch: (async (url) => {
      if (String(url).endsWith("/user/erase")) return oldResponse;
      if (String(url).endsWith("/session")) return Response.json({ session: publicSession("old@example.com") });
      return Response.json(publicSession("new@example.com"));
    }) as typeof fetch });
    await client.getSession();
    const old = client.eraseUser({ operationId: crypto.randomUUID(), confirmation: "erase" });
    await client.signUpEmailPassword({ email: "new@example.com", password: "correct-horse" });
    rejectOld(Response.json({ error: { code: "invalid_session", message: "Old session expired" } }, { status: 401 }));
    await expect(old).rejects.toMatchObject({ code: "invalid_session" });
    expect(client.getSessionSnapshot().data?.user.email).toBe("new@example.com");
  });
  it("clears the erased account through the real client and HTTP handler", async () => {
    const client = createClientHarness();
    await client.signUpEmailPassword({ email: "erased-client@example.com", password: "correct-horse" });
    expect(await client.eraseUser({ operationId: crypto.randomUUID(), confirmation: "erase" })).toMatchObject({ status: "complete" });
    expect(client.getSessionSnapshot().data).toBeNull();
    expect(await client.getSession()).toBeNull();
  });

  it("does not let an older session response restore state after pending erasure", async () => {
    let resolveSession!: (response: Response) => void;
    const pending = new Promise<Response>((resolve) => { resolveSession = resolve; });
    const client = createOwnAuthClient({ baseURL: "http://localhost/api/auth", fetch: (async (url) =>
      String(url).endsWith("/session") ? pending : Response.json({ operationId: "opaque", status: "pending", local: "pending", cloud: "pending", pendingLocalStores: [] }, { status: 202 })) as typeof fetch });
    const session = client.getSession();
    await client.eraseUser({ operationId: crypto.randomUUID(), confirmation: "erase" });
    resolveSession(Response.json({ session: publicSession("erased@example.com") }));
    expect(await session).toBeNull();
    expect(client.getSessionSnapshot().data).toBeNull();
  });

  it("refreshes session state after a lost erasure response without claiming completion", async () => {
    let erased = false;
    const client = createOwnAuthClient({ baseURL: "http://localhost/api/auth", fetch: (async (url) => {
      if (String(url).endsWith("/user/erase")) { erased = true; throw new Error("connection lost"); }
      return Response.json({ session: erased ? null : publicSession("lost@example.com") });
    }) as typeof fetch });
    await client.getSession();
    await expect(client.eraseUser({ operationId: crypto.randomUUID(), confirmation: "erase" })).rejects.toBeInstanceOf(OwnAuthClientError);
    expect(client.getSessionSnapshot().data).toBeNull();
  });
  it("shares one initial session request between subscribers", async () => {
    let requestCount = 0;
    const client = createOwnAuthClient({
      baseURL: "http://localhost/api/auth",
      fetch: (async () => {
        requestCount += 1;
        await Promise.resolve();
        return Response.json({ session: null });
      }) as typeof fetch
    });

    const [first, second] = await Promise.all([
      client.ensureSession(),
      client.ensureSession()
    ]);

    expect(first).toBeNull();
    expect(second).toBeNull();
    expect(requestCount).toBe(1);
    expect(client.getSessionSnapshot()).toEqual({
      data: null,
      isPending: false,
      error: null
    });
  });

  it("keeps its current-session state in sync with auth mutations", async () => {
    const client = createClientHarness();
    const updates: Array<string | null> = [];
    const unsubscribe = client.subscribe(() => {
      updates.push(client.getSessionSnapshot().data?.user.email ?? null);
    });

    const signup = await client.signUpEmailPassword({
      email: "client@example.com",
      password: "correct-horse"
    });
    const session = await client.getSession();

    expect(signup.user.email).toBe("client@example.com");
    expect(session?.user.email).toBe("client@example.com");
    expect(client.getSessionSnapshot()).toMatchObject({
      data: { user: { email: "client@example.com" } },
      isPending: false,
      error: null
    });

    await client.signOut();
    expect(client.getSessionSnapshot().data).toBeNull();
    expect(updates).toContain("client@example.com");
    expect(updates.at(-1)).toBeNull();
    unsubscribe();
  });

  it("does not let an older session request restore state after sign-out", async () => {
    let resolveSession!: (response: Response) => void;
    const sessionResponse = new Promise<Response>((resolve) => {
      resolveSession = resolve;
    });
    const client = createOwnAuthClient({
      baseURL: "http://localhost/api/auth",
      fetch: (async (input, init) => {
        const url = input instanceof Request ? input.url : input.toString();
        if (url.endsWith("/session") && init?.method === "GET") {
          return sessionResponse;
        }
        return Response.json({ success: true });
      }) as typeof fetch
    });

    const pendingSession = client.getSession();
    await client.signOut();
    resolveSession(Response.json({ session: publicSession("stale@example.com") }));
    await expect(pendingSession).resolves.toBeNull();

    expect(client.getSessionSnapshot()).toEqual({
      data: null,
      isPending: false,
      error: null
    });
  });

  it("keeps the cached user in sync after phone verification", async () => {
    const session = publicSession("client@example.com");
    const verifiedUser = {
      ...session.user,
      phone: "+14155550123",
      phoneVerifiedAt: "2026-07-30T00:01:00.000Z"
    };
    const client = createOwnAuthClient({
      baseURL: "http://localhost/api/auth",
      fetch: (async (input) => {
        const url = input instanceof Request ? input.url : input.toString();
        return url.endsWith("/sms/verify")
          ? Response.json({ status: "verified", user: verifiedUser })
          : Response.json(session);
      }) as typeof fetch
    });
    await client.signUpEmailPassword({
      email: "client@example.com",
      password: "correct-horse"
    });

    await client.verifySmsOtp({
      phone: "+14155550123",
      code: "123456",
      purpose: "phone_verification"
    });

    expect(client.getSessionSnapshot().data?.user).toMatchObject({
      email: "client@example.com",
      phone: "+14155550123"
    });
  });

  it("throws typed client errors from the shared error envelope", async () => {
    const client = createClientHarness();

    await expect(client.signInEmailPassword({
      email: "missing@example.com",
      password: "wrong-password"
    })).rejects.toEqual(expect.objectContaining({
      name: "OwnAuthClientError",
      code: "invalid_credentials",
      status: 401
    }));

    try {
      await client.signInEmailPassword({
        email: "missing@example.com",
        password: "wrong-password"
      });
    } catch (error) {
      expect(error).toBeInstanceOf(OwnAuthClientError);
    }
  });

  it("converts network failures into typed client errors", async () => {
    const client = createOwnAuthClient({
      baseURL: "http://localhost/api/auth",
      fetch: (async () => {
        throw new TypeError("network unavailable");
      }) as typeof fetch
    });

    await expect(client.signInEmailPassword({
      email: "user@example.com",
      password: "correct-horse"
    })).rejects.toEqual(expect.objectContaining({
      name: "OwnAuthClientError",
      code: "internal_error",
      status: 0,
      message: "Authentication request failed"
    }));
  });

  it("converts plugin network failures into typed client errors", async () => {
    const client = createOwnAuthClient({
      baseURL: "http://localhost/api/auth",
      plugins: [{
        id: "network",
        methods: {
          ping: { method: "POST", path: "/plugins/network/ping" }
        }
      }],
      fetch: (async () => {
        throw new TypeError("network unavailable");
      }) as typeof fetch
    });

    await expect(client.plugin("network").call("ping")).rejects.toEqual(
      expect.objectContaining({
        name: "OwnAuthClientError",
        code: "internal_error",
        status: 0
      })
    );
  });

  it.each([null, "different-fingerprint"])(
    "rejects plugin responses with an absent or stale contract fingerprint: %s",
    async (serverFingerprint) => {
      const client = createOwnAuthClient({
        baseURL: "http://localhost/api/auth",
        pluginFingerprint: "expected-fingerprint",
        plugins: [{
          id: "example",
          methods: {
            ping: { method: "POST", path: "/plugins/example/ping" }
          }
        }],
        fetch: (async () => Response.json(
          { ok: true },
          serverFingerprint
            ? { headers: { "x-own-auth-plugin-fingerprint": serverFingerprint } }
            : undefined
        )) as typeof fetch
      });

      await expect(client.plugin("example").call("ping")).rejects.toMatchObject({
        code: "internal_error",
        status: 409
      });
    }
  );

  it("round-trips repeated GET plugin inputs as arrays", async () => {
    const plugin = defineOwnAuthPlugin({
      id: "query-array",
      version: "1.0.0",
      clientMethods: { read: { endpoint: "read" } },
      endpoints: [{
        id: "read",
        method: "GET",
        summary: "Read repeated query values",
        input: {
          type: "object",
          properties: { tags: { type: "array", items: { type: "string" } } },
          required: ["tags"],
          additionalProperties: false
        },
        output: {
          type: "object",
          properties: { tags: { type: "array", items: { type: "string" } } },
          required: ["tags"],
          additionalProperties: false
        },
        handler: ({ input }) => input
      }]
    });
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "query-array-plugin",
      plugins: [plugin]
    });
    const handler = createOwnAuthHandler(auth);
    const configuration = createOwnAuthPluginClientConfiguration([plugin]);
    const client = createOwnAuthClient({
      baseURL: "http://localhost/api/auth",
      pluginFingerprint: configuration.fingerprint,
      plugins: configuration.plugins,
      fetch: (async (
        input: string | URL | Request,
        init?: RequestInit
      ) => handler(new Request(input, init))) as typeof fetch
    });

    await expect(client.plugin("query-array").call("read", {
      tags: ["security", "portability"]
    })).resolves.toEqual({ tags: ["security", "portability"] });
  });
});

function publicSession(email: string) {
  const timestamp = "2026-07-30T00:00:00.000Z";
  return {
    status: "complete",
    user: {
      id: "usr_stale",
      email,
      emailVerifiedAt: null,
      phone: null,
      phoneVerifiedAt: null,
      name: null,
      imageUrl: null,
      metadata: {},
      createdAt: timestamp,
      updatedAt: timestamp,
      lastLoginAt: timestamp
    },
    session: {
      id: "ses_stale",
      userId: "usr_stale",
      createdAt: timestamp,
      lastActiveAt: timestamp,
      expiresAt: timestamp,
      idleExpiresAt: timestamp,
      ipAddress: null,
      userAgent: null,
      authenticationMethods: ["password"],
      assuranceLevel: "aal1",
      authenticatedAt: timestamp
    }
  };
}
