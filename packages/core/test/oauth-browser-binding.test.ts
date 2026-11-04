import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AuthError,
  InMemoryAuthStorage,
  createOAuthBrowserCookie,
  createOwnAuth,
  createOwnAuthHandler,
  readOAuthBrowserToken,
  type ExternalAccountProvider,
  type OAuthAuthorizationResult,
  type OAuthProviderAdapter
} from "../src/index.js";
import { jsonRequest } from "./http-test-helpers.js";
import { createTotpCode } from "./identity-test-helpers.js";

const origin = "https://auth.example.com";

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

function harness(
  provider: ExternalAccountProvider = "google",
  accountLinking: "explicit" | "verified_email" = "explicit"
) {
  const storage = new InMemoryAuthStorage();
  const adapter: OAuthProviderAdapter = {
    provider,
    redirectUri: `${origin}/api/auth/oauth/${provider}/callback`,
    offlineAccess: false,
    async createAuthorizationUrl({ state }) {
      const url = new URL("https://provider.example/authorize");
      url.searchParams.set("state", state);
      return url;
    },
    async exchangeCode({ callbackParameters }) {
      if (callbackParameters.has("error")) {
        throw new AuthError("oauth_provider_error", "OAuth sign-in failed", 400);
      }
      return {
        identity: {
          provider,
          providerAccountId: "browser-bound-user",
          email: "browser-bound@example.com",
          emailVerified: true,
          name: null,
          imageUrl: null
        },
        refreshToken: null,
        scopes: []
      };
    }
  };
  const exchange = vi.spyOn(adapter, "exchangeCode");
  const auth = createOwnAuth({
    storage,
    tokenPepper: "oauth-browser-test-pepper",
    encryption: { current: { id: "current", key: new Uint8Array(32).fill(4) } },
    oauth: { adapters: [adapter], accountLinking },
    redirectAllowlist: ["https://app.example.com"]
  });
  return { auth, storage, adapter, exchange, handler: createOwnAuthHandler(auth), provider };
}

function callbackParameters(authorization: OAuthAuthorizationResult) {
  return new URLSearchParams({ state: authorization.state, code: "provider-code" });
}

function cookiePair(value: string): string {
  return value.split(";", 1)[0]!;
}

async function start(
  handler: ReturnType<typeof createOwnAuthHandler>,
  provider: ExternalAccountProvider,
  input: Record<string, string> = {},
  cookie?: string
) {
  const response = await handler(jsonRequest(
    "/api/auth/oauth/start",
    { provider, ...input },
    cookie ? { cookie } : {},
    origin
  ));
  expect(response.status).toBe(200);
  const body = await response.json() as { url: string; expiresAt: string };
  expect(Object.keys(body).sort()).toEqual(["expiresAt", "url"]);
  const state = new URL(body.url).searchParams.get("state")!;
  const setCookie = response.headers.get("set-cookie")!;
  const browserCookie = cookiePair(setCookie);
  expect(setCookie).toContain("HttpOnly");
  expect(setCookie).toContain("Secure");
  expect(setCookie).toContain("SameSite=None");
  expect(setCookie).toContain("Path=/");
  expect(setCookie).toContain("Expires=");
  expect(setCookie).toContain("Max-Age=");
  expect(setCookie).toMatch(/^__Host-own_auth_oauth_/);
  expect(setCookie).not.toContain("Domain=");
  expect(JSON.stringify(body)).not.toContain(browserCookie.split("=")[1]);
  return { state, browserCookie };
}

function callback(
  provider: ExternalAccountProvider,
  state: string,
  cookie?: string,
  method = "GET",
  parameters: Record<string, string> = { code: "provider-code" }
) {
  const url = new URL(`${origin}/api/auth/oauth/${provider}/callback`);
  const values = new URLSearchParams({ state, ...parameters });
  const headers = new Headers(cookie ? { cookie } : {});
  if (method === "POST") {
    headers.set("content-type", "application/x-www-form-urlencoded");
    headers.set("origin", "https://appleid.apple.com");
    return new Request(url, { method, headers, body: values });
  }
  url.search = values.toString();
  return new Request(url, { headers });
}

describe("OAuth browser binding in the core API", () => {
  it.each(["redirect", "one_tap"] as const)(
    "requires boolean true for custom adapter email claims through %s",
    async (entry) => {
      const { auth, storage, adapter, exchange } = harness("google", "verified_email");
      const victim = await auth.createUser({ email: "browser-bound@example.com" });
      await storage.updateUser(victim.id, { emailVerifiedAt: new Date() });
      for (const claim of [false, "false", "true", 1, {}, [], null, undefined]) {
        const identity = { provider: "google" as const, providerAccountId: "attacker-provider-account",
          email: victim.email, emailVerified: claim as unknown as boolean, name: null, imageUrl: null };
        if (entry === "redirect") exchange.mockResolvedValueOnce({ identity, refreshToken: null, scopes: [] });
        adapter.verifyCredential = async () => identity;
        if (entry === "redirect") {
          const started = await auth.createOAuthAuthorizationUrl({ provider: "google" });
          await expect(auth.completeOAuthSignIn({
            provider: "google", callbackParameters: callbackParameters(started),
            browserBindingToken: started.browserBindingToken
          })).rejects.toMatchObject({ code: "oauth_verified_email_required" });
        } else {
          const { nonce } = await auth.prepareGoogleOneTap();
          await expect(auth.signInWithGoogleOneTap({ nonce, credential: "synthetic-credential" }))
            .rejects.toMatchObject({ code: "oauth_verified_email_required" });
        }
      }
      expect(await storage.getAccountByProvider("google", "attacker-provider-account")).toBeNull();
      expect(await storage.listSessionsByUserId(victim.id)).toEqual([]);
      expect((await storage.getUserById(victim.id))?.email).toBe(victim.email);
    }
  );

  it("rejects missing, copied, malformed, and mismatched proof before consuming state", async () => {
    const { auth, storage, exchange } = harness();
    const write = vi.spyOn(storage, "createOAuthTransaction");
    const first = await auth.createOAuthAuthorizationUrl({ provider: "google" });
    const second = await auth.createOAuthAuthorizationUrl({ provider: "google" });
    const consume = vi.spyOn(storage, "consumeOAuthTransaction");
    expect(JSON.stringify(write.mock.calls)).not.toContain(first.browserBindingToken);
    expect(first.url).not.toContain(first.browserBindingToken);

    for (const proof of [undefined, "", "malformed", first.state, second.browserBindingToken]) {
      await expect(auth.completeOAuthSignIn({
        provider: "google",
        callbackParameters: callbackParameters(first),
        browserBindingToken: proof as string
      })).rejects.toMatchObject({ code: "oauth_transaction_invalid" });
    }
    expect(consume).not.toHaveBeenCalled();
    expect(exchange).not.toHaveBeenCalled();
    expect(await storage.listUsers()).toEqual([]);
    expect(JSON.stringify(await storage.listAuditEvents())).not.toContain(first.browserBindingToken);

    const result = await auth.completeOAuthSignIn({
      provider: "google",
      callbackParameters: callbackParameters(first),
      browserBindingToken: first.browserBindingToken
    });
    expect(result.status).toBe("complete");
    expect(exchange).toHaveBeenCalledTimes(1);
    await expect(auth.completeOAuthSignIn({
      provider: "google",
      callbackParameters: callbackParameters(first),
      browserBindingToken: first.browserBindingToken
    })).rejects.toMatchObject({ code: "oauth_transaction_invalid" });
    expect(exchange).toHaveBeenCalledTimes(1);
  });

  it("keeps expiry and atomic replay protection with the correct proof", async () => {
    vi.useFakeTimers();
    const { auth, exchange } = harness();
    const expired = await auth.createOAuthAuthorizationUrl({ provider: "google" });
    vi.setSystemTime(expired.expiresAt);
    await expect(auth.completeOAuthSignIn({
      provider: "google",
      callbackParameters: callbackParameters(expired),
      browserBindingToken: expired.browserBindingToken
    })).rejects.toMatchObject({ code: "oauth_transaction_invalid" });
    expect(exchange).not.toHaveBeenCalled();

    const current = await auth.createOAuthAuthorizationUrl({ provider: "google" });
    const input = {
      provider: "google" as const,
      callbackParameters: callbackParameters(current),
      browserBindingToken: current.browserBindingToken
    };
    const results = await Promise.allSettled([
      auth.completeOAuthSignIn(input), auth.completeOAuthSignIn(input)
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(exchange).toHaveBeenCalledTimes(1);
  });

  it("rejects a provider verification that finishes after the initiating request expires", async () => {
    const { auth, storage, exchange } = harness();
    const authorization = await auth.createOAuthAuthorizationUrl({ provider: "google" });
    exchange.mockImplementationOnce(async () => {
      vi.spyOn(Date, "now").mockReturnValue(authorization.expiresAt.getTime() + 1);
      return { identity: { provider: "google", providerAccountId: "browser-bound-user", email: "browser-bound@example.com",
        emailVerified: true, name: null, imageUrl: null }, refreshToken: null, scopes: [] };
    });
    await expect(auth.completeOAuthSignIn({ provider: "google", callbackParameters: callbackParameters(authorization),
      browserBindingToken: authorization.browserBindingToken })).rejects.toMatchObject({ code: "oauth_transaction_invalid" });
    expect(await storage.getUserByEmail("browser-bound@example.com")).toBeNull();
  });
});

describe("OAuth browser binding in the HTTP handler", () => {
  it("rejects OAuth state at the magic link endpoint and preserves the real callback", async () => {
    const { handler, exchange } = harness();
    const started = await start(handler, "google");
    const response = await handler(jsonRequest("/api/auth/magic-link/verify", {
      token: started.state
    }, {}, origin));
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: { code: "invalid_token" } });
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(exchange).not.toHaveBeenCalled();
    const completed = await handler(callback("google", started.state, started.browserCookie));
    expect(completed.status).toBe(302);
    expect(completed.headers.get("set-cookie")).toContain("own_auth_session=");
    expect(exchange).toHaveBeenCalledTimes(1);
  });

  it.each(["state", "browserBindingToken", "authorizationURL"])(
    "rejects caller supplied %s without issuing an OAuth cookie",
    async (field) => {
      const { handler, storage, exchange } = harness();
      const create = vi.spyOn(storage, "createOAuthTransaction");
      const response = await handler(jsonRequest("/api/auth/oauth/start", {
        provider: "google", [field]: "caller-selected-authentication-proof"
      }, {}, origin));
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: { code: "validation_error" } });
      expect(response.headers.get("set-cookie")).toBeNull();
      expect(create).not.toHaveBeenCalled();
      expect(exchange).not.toHaveBeenCalled();
    }
  );

  it.each([
    "https://app.example.com.attacker.test/",
    "https://app.example.com@attacker.test/",
    "https://attacker.test/",
    "javascript:alert(1)",
    "//attacker.test/"
  ])("rejects OAuth destination %s before issuing state or cookies", async (destination) => {
    const { handler, storage } = harness();
    const create = vi.spyOn(storage, "createOAuthTransaction");
    const response = await handler(jsonRequest("/api/auth/oauth/start", {
      provider: "google", destination
    }, {}, origin));
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: { code: "redirect_not_allowed" } });
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(response.headers.get("location")).toBeNull();
    expect(create).not.toHaveBeenCalled();
  });

  it.each([
    ["google", "GET"], ["github", "GET"], ["apple", "GET"], ["apple", "POST"]
  ] as const)("requires the initiating cookie for %s %s callbacks", async (provider, method) => {
    const { handler, exchange } = harness(provider);
    const first = await start(handler, provider);
    const other = await start(handler, provider);
    const correctName = first.browserCookie.split("=", 1)[0];
    const wrongValue = other.browserCookie.split("=")[1];
    for (const cookie of [
      undefined,
      other.browserCookie,
      `${correctName}=${wrongValue}`,
      `${first.browserCookie}; ${first.browserCookie}`
    ]) {
      const rejected = await handler(callback(provider, first.state, cookie, method));
      expect(rejected.status).toBe(400);
      expect(await rejected.json()).toMatchObject({ error: { code: "oauth_transaction_invalid" } });
      expect(rejected.headers.get("set-cookie")).toBeNull();
    }
    expect(exchange).not.toHaveBeenCalled();
    const response = await handler(callback(provider, first.state, first.browserCookie, method));
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toContain("own_auth_status=complete");
    expect(response.headers.get("set-cookie")).toContain("own_auth_session=");
    expect(response.headers.get("set-cookie")).toContain(`${correctName}=;`);
    expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
    expect(exchange).toHaveBeenCalledTimes(1);
  });

  it("keeps parallel transactions independent, including starts after a successful login", async () => {
    const { handler, exchange } = harness();
    const first = await start(handler, "google");
    const second = await start(handler, "google");
    const cookies = `${first.browserCookie}; ${second.browserCookie}`;
    for (const transaction of [second, first]) {
      const response = await handler(callback("google", transaction.state, cookies));
      expect(response.status).toBe(302);
      const clearedCookies = response.headers.getSetCookie();
      expect(clearedCookies.some((cookie) => cookie.startsWith(
        `${transaction.browserCookie.split("=", 1)[0]}=;`
      ))).toBe(true);
    }
    const later = await start(handler, "google");
    expect((await handler(callback("google", later.state, later.browserCookie))).status).toBe(302);
    expect(exchange).toHaveBeenCalledTimes(3);
  });

  it("rejects a popup callback from another browser before returning popup content", async () => {
    const { handler, exchange } = harness();
    const transaction = await start(handler, "google", {
      mode: "popup", openerOrigin: "https://app.example.com"
    });
    const rejected = await handler(callback("google", transaction.state));
    expect(rejected.status).toBe(400);
    expect(await rejected.text()).not.toContain("postMessage");
    expect(exchange).not.toHaveBeenCalled();
    const completed = await handler(callback("google", transaction.state, transaction.browserCookie));
    expect(completed.status).toBe(200);
    const html = await completed.text();
    expect(html).toContain('"status":"complete"');
    expect(html).toContain("https://app.example.com");
    expect(html).not.toContain(transaction.browserCookie.split("=")[1]);
    expect(completed.headers.get("set-cookie")).toContain("Max-Age=0");
  });

  it("sets only the MFA challenge after a browser bound first factor for an enrolled user", async () => {
    const { auth, handler, exchange } = harness();
    const first = await auth.createOAuthAuthorizationUrl({ provider: "google" });
    const signedIn = await auth.completeOAuthSignIn({
      provider: "google",
      callbackParameters: callbackParameters(first),
      browserBindingToken: first.browserBindingToken
    });
    if (signedIn.status !== "complete") throw new Error("Expected a completed first sign in");
    const enrollment = await auth.beginTotpEnrollment({ sessionToken: signedIn.sessionToken });
    await auth.confirmTotpEnrollment({
      sessionToken: signedIn.sessionToken,
      factorId: enrollment.factorId,
      code: createTotpCode(enrollment.secret)
    });
    const transaction = await start(handler, "google");
    const rejected = await handler(callback("google", transaction.state));
    expect(rejected.status).toBe(400);
    expect(rejected.headers.get("set-cookie")).toBeNull();
    expect(exchange).toHaveBeenCalledTimes(1);
    const completed = await handler(callback("google", transaction.state, transaction.browserCookie));
    expect(completed.headers.get("location")).toContain("own_auth_status=mfa_required");
    expect(completed.headers.get("set-cookie")).toContain("own_auth_mfa=");
    expect(completed.headers.get("set-cookie")).not.toContain("own_auth_session=");
    expect(completed.headers.get("set-cookie")).toContain("Max-Age=0");
  });

  it("requires browser proof for linking and does not link on a rejected callback", async () => {
    const { auth, handler, storage, exchange } = harness();
    const actor = await auth.signUpEmailPassword({
      email: "link-owner@example.com", password: "correct-horse"
    });
    const transaction = await start(handler, "google", { intent: "link" },
      `own_auth_session=${actor.sessionToken}`);
    expect((await handler(callback("google", transaction.state))).status).toBe(400);
    expect(exchange).not.toHaveBeenCalled();
    expect(await storage.getAccountByProvider("google", "browser-bound-user")).toBeNull();
    const linked = await handler(callback("google", transaction.state, transaction.browserCookie));
    expect(linked.headers.get("location")).toContain("own_auth_status=linked");
    expect((await storage.getAccountByProvider("google", "browser-bound-user"))?.userId)
      .toBe(actor.user.id);
  });

  it.each(["redirect", "popup"] as const)("clears consumed %s cookies on provider failure", async (mode) => {
    const { handler } = harness();
    const transaction = await start(handler, "google", {
      mode,
      ...(mode === "popup" ? { openerOrigin: "https://app.example.com" } : {})
    });
    const response = await handler(callback("google", transaction.state, transaction.browserCookie,
      "GET", { error: "access_denied" }));
    expect(response.status).toBe(mode === "popup" ? 200 : 302);
    const cookies = response.headers.get("set-cookie")!;
    expect(cookies).toContain("Max-Age=0");
    expect(cookies).not.toContain("own_auth_session=");
    expect(cookies).not.toContain("own_auth_mfa=");
    if (mode === "popup") {
      const html = await response.text();
      expect(html).toContain('"status":"failure"');
      expect(html).toContain("https://app.example.com");
      expect(html).not.toContain(transaction.browserCookie.split("=")[1]);
    }
  });

  it("uses the local development cookie only for HTTP localhost", async () => {
    const state = "a".repeat(64);
    const cookie = createOAuthBrowserCookie(state, "proof", new Date(Date.now() + 60_000),
      new URL("http://localhost"));
    expect(cookie).toMatch(/^own_auth_oauth_/);
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).not.toContain("Secure");
    expect(readOAuthBrowserToken(new Request(`http://localhost/?state=${state}`, {
      headers: { cookie: cookiePair(cookie) }
    }), state)).toBe("proof");
    expect(() => createOAuthBrowserCookie(state, "proof", new Date(),
      new URL("http://auth.example.com"))).toThrow("HTTPS");
  });
});
