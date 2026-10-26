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

function harness(provider: ExternalAccountProvider = "google") {
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
    oauth: { adapters: [adapter] },
    redirectAllowlist: ["https://app.example.com"]
  });
  return { auth, storage, exchange, handler: createOwnAuthHandler(auth), provider };
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
});

describe("OAuth browser binding in the HTTP handler", () => {
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
