import { describe, expect, it } from "vitest";
import {
  InMemoryAuthStorage,
  createOwnAuth,
  createOwnAuthHandler,
  createOAuthBrowserCookie,
  defineOwnAuthPlugin,
  type OAuthProviderAdapter
} from "../src/index.js";
import { jsonRequest } from "./http-test-helpers.js";
import {
  createTotpCode,
  requireCompleteSignIn
} from "./identity-test-helpers.js";

describe("identity HTTP contract", () => {
  it("keeps the MFA challenge token in an HttpOnly temporary cookie", async () => {
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "http-mfa-pepper",
      encryption: {
        current: { id: "current", key: new Uint8Array(32).fill(9) }
      }
    });
    const signup = requireCompleteSignIn(await auth.signUpEmailPassword({
      email: "http-mfa@example.com",
      password: "correct-horse"
    }));
    const enrollment = await auth.beginTotpEnrollment({ sessionToken: signup.sessionToken });
    const recoveryCodes = (await auth.confirmTotpEnrollment({
      sessionToken: signup.sessionToken,
      factorId: enrollment.factorId,
      code: createTotpCode(enrollment.secret)
    })).recoveryCodes;
    await auth.signOut(signup.sessionToken);
    const handler = createOwnAuthHandler(auth);

    const signIn = await handler(jsonRequest("/api/auth/sign-in/email", {
      email: "http-mfa@example.com",
      password: "correct-horse"
    }));
    const signInBody = await signIn.json() as Record<string, unknown>;
    const mfaCookie = signIn.headers.get("set-cookie") ?? "";

    expect(signInBody).toMatchObject({
      status: "mfa_required",
      methods: ["totp", "recovery_code"]
    });
    expect(signInBody).not.toHaveProperty("challengeToken");
    expect(mfaCookie).toContain("own_auth_mfa=");
    expect(mfaCookie).toContain("HttpOnly");
    expect(mfaCookie).not.toContain("own_auth_session=");

    const completed = await handler(jsonRequest(
      "/api/auth/mfa/recovery/complete",
      { code: recoveryCodes[0] },
      { cookie: mfaCookie.split(";", 1)[0] ?? "" }
    ));
    const completedBody = await completed.json() as Record<string, unknown>;
    const completedCookies = completed.headers.get("set-cookie") ?? "";

    expect(completedBody).toMatchObject({
      status: "complete",
      session: { assuranceLevel: "aal2" }
    });
    expect(completedCookies).toContain("own_auth_session=");
    expect(completedCookies).toContain("own_auth_mfa=");
    expect(completedCookies).toContain("Max-Age=0");
  });

  it("accepts Apple form-post callbacks only as bounded form data", async () => {
    const handler = createOwnAuthHandler(createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "apple-form-post"
    }));
    const wrongType = await handler(new Request(
      "http://localhost/api/auth/oauth/apple/callback",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ state: "state", code: "code" })
      }
    ));
    expect(wrongType.status).toBe(415);

    const oversized = await handler(new Request(
      "http://localhost/api/auth/oauth/apple/callback",
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ state: "s".repeat(70 * 1024), code: "code" })
      }
    ));
    expect(oversized.status).toBe(413);
  });

  it("returns a token-free popup message to the exact opener origin", async () => {
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "popup-oauth",
      redirectAllowlist: ["https://app.example.com"],
      oauth: { adapters: [fakePopupProvider()] }
    });
    const authorization = await auth.createOAuthAuthorizationUrl({
      provider: "google",
      mode: "popup",
      openerOrigin: "https://app.example.com"
    });
    const state = new URL(authorization.url).searchParams.get("state") ?? "";
    const handler = createOwnAuthHandler(auth);
    const response = await handler(new Request(
      `https://api.example.com/api/auth/oauth/google/callback?state=${encodeURIComponent(state)}&code=provider-code`,
      {
        headers: {
          cookie: createOAuthBrowserCookie(
            authorization.state,
            authorization.browserBindingToken,
            authorization.expiresAt,
            new URL("https://api.example.com")
          ).split(";", 1)[0]!
        }
      }
    ));
    const html = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(html).toContain("https://app.example.com");
    expect(html).toContain('"status":"complete"');
    expect(html).not.toContain("provider-code");
    expect(html).not.toContain("provider-access-token");
    expect(html).not.toContain("sessionToken");
  });

  it("audits an invalid OAuth callback without recording callback secrets", async () => {
    const storage = new InMemoryAuthStorage();
    const auth = createOwnAuth({
      storage,
      tokenPepper: "oauth-failure-audit",
      oauth: { adapters: [fakePopupProvider()] }
    });

    await expect(auth.completeOAuthSignIn({
      provider: "google",
      browserBindingToken: "",
      callbackParameters: new URLSearchParams({ code: "secret-provider-code" })
    })).rejects.toMatchObject({ code: "oauth_transaction_invalid" });

    const events = await storage.listAuditEvents();
    expect(events).toEqual(expect.arrayContaining([
      expect.objectContaining({
        eventType: "oauth.failed",
        metadata: {
          provider: "google",
          error: "oauth_transaction_invalid"
        }
      })
    ]));
    expect(JSON.stringify(events)).not.toContain("secret-provider-code");
  });

  it("scopes plugin trusted origins to that plugin's endpoints", async () => {
    const plugin = defineOwnAuthPlugin({
      id: "trusted-widget",
      version: "1.0.0",
      trustedOrigins: ["https://widget.example.com"],
      endpoints: [{
        id: "ping",
        method: "POST",
        summary: "Ping the widget",
        output: {
          type: "object",
          properties: { ok: { const: true } },
          required: ["ok"],
          additionalProperties: false
        },
        handler: () => ({ ok: true })
      }]
    });
    const handler = createOwnAuthHandler(createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "plugin-origin-scope",
      plugins: [plugin]
    }));
    const headers = {
      "content-type": "application/json",
      origin: "https://widget.example.com"
    };

    const pluginResponse = await handler(new Request(
      "https://api.example.com/api/auth/plugins/trusted-widget/ping",
      { method: "POST", headers, body: "{}" }
    ));
    const coreResponse = await handler(new Request(
      "https://api.example.com/api/auth/sign-up/email",
      {
        method: "POST",
        headers,
        body: JSON.stringify({
          email: "plugin-origin@example.com",
          password: "correct-horse"
        })
      }
    ));

    expect(pluginResponse.status).toBe(200);
    expect(coreResponse.status).toBe(403);
  });
});

function fakePopupProvider(): OAuthProviderAdapter {
  return {
    provider: "google",
    redirectUri: "https://api.example.com/api/auth/oauth/google/callback",
    offlineAccess: false,
    async createAuthorizationUrl(input) {
      const url = new URL("https://accounts.example.test/authorize");
      url.searchParams.set("state", input.state);
      return url;
    },
    async exchangeCode() {
      return {
        identity: {
          provider: "google",
          providerAccountId: "popup-user",
          email: "popup@example.com",
          emailVerified: true,
          name: null,
          imageUrl: null
        },
        refreshToken: null,
        scopes: []
      };
    }
  };
}
