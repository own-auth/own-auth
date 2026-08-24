import { afterEach, describe, expect, it } from "vitest";
import { createOwnAuthClient } from "../src/client.js";
import { createDeviceFlowClient } from "../src/device-authorization.js";
import { resolveFetchImplementation } from "../src/fetch-implementation.js";
import { createOAuthProviderRegistry } from "../src/oauth-registry.js";
import { createOwnAuthProtectedResource } from "../src/protected-resource.js";
import { normalizeWebhookOptions } from "../src/webhook-config.js";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("default fetch handling", () => {
  it("binds every package-owned default fetch to the global receiver", async () => {
    const requests: string[] = [];
    globalThis.fetch = (async function (
      this: unknown,
      input: string | URL | Request
    ) {
      if (this !== globalThis) {
        throw new TypeError("Illegal invocation");
      }

      const url = input.toString();
      requests.push(url);
      if (url === "https://auth.example.com/oauth/device/authorize") {
        return Response.json({
          device_code: "oa_dc_example",
          user_code: "BCDF-GHJK",
          verification_uri: "https://auth.example.com/device",
          expires_in: 600,
          interval: 5
        });
      }
      if (url === "https://auth.example.com/oauth/introspect") {
        return Response.json({ active: false });
      }
      if (url === "https://github.com/login/oauth/access_token") {
        return Response.json({
          access_token: "github-access-token",
          token_type: "bearer",
          scope: "read:user user:email"
        });
      }
      if (url === "https://api.github.com/user") {
        return Response.json({ id: 42, login: "octocat", name: "Octo Cat" });
      }
      if (url === "https://api.github.com/user/emails") {
        return Response.json([{
          email: "user@example.com",
          verified: true,
          primary: true
        }]);
      }
      if (url === "https://hooks.example.com/") {
        return new Response(null, { status: 204 });
      }
      return Response.json({ session: null });
    }) as typeof fetch;

    const client = createOwnAuthClient({
      baseURL: "https://app.example.com/api/auth"
    });
    await expect(client.getSession()).resolves.toBeNull();

    const deviceClient = createDeviceFlowClient({
      deviceAuthorizationEndpoint: "https://auth.example.com/oauth/device/authorize",
      tokenEndpoint: "https://auth.example.com/oauth/token",
      clientId: "oa_client_example"
    });
    await expect(deviceClient.start({ scope: "openid" })).resolves.toMatchObject({
      deviceCode: "oa_dc_example"
    });

    const protectedResource = createOwnAuthProtectedResource({
      introspectionUrl: "https://auth.example.com/oauth/introspect",
      resource: "https://api.example.com",
      resourceSecret: "resource-secret"
    });
    await expect(protectedResource.verifyAccessToken({
      accessToken: "oa_at_example"
    })).resolves.toEqual({
      active: false,
      error: "invalid_token"
    });

    const webhookConfig = normalizeWebhookOptions({
      endpoints: [{
        id: "primary",
        url: "https://hooks.example.com",
        secret: "webhook-secret-that-is-at-least-32-bytes",
        events: ["user.signed_up"]
      }]
    });
    await expect(webhookConfig?.fetch("https://hooks.example.com/")).resolves.toMatchObject({
      status: 204
    });

    const github = createOAuthProviderRegistry({
      providers: {
        github: {
          clientId: "github-client",
          clientSecret: "github-secret",
          redirectUri: "https://app.example.com/oauth/callback"
        }
      }
    }).get("github");
    await expect(github?.exchangeCode({
      callbackParameters: new URLSearchParams({
        code: "github-code",
        state: "oauth-state"
      }),
      state: "oauth-state",
      codeVerifier: "pkce-verifier",
      nonce: "oidc-nonce"
    })).resolves.toMatchObject({
      identity: {
        provider: "github",
        providerAccountId: "42",
        email: "user@example.com"
      }
    });

    expect(requests).toEqual(expect.arrayContaining([
      "https://app.example.com/api/auth/session",
      "https://auth.example.com/oauth/device/authorize",
      "https://auth.example.com/oauth/introspect",
      "https://github.com/login/oauth/access_token",
      "https://api.github.com/user",
      "https://api.github.com/user/emails",
      "https://hooks.example.com/"
    ]));
  });

  it("preserves custom fetch implementations", () => {
    const customFetch = (async () => new Response(null, { status: 204 })) as typeof fetch;

    expect(resolveFetchImplementation(customFetch)).toBe(customFetch);
  });

  it("binds an explicitly supplied native global fetch", async () => {
    let receiver: unknown;
    globalThis.fetch = (async function (this: unknown) {
      receiver = this;
      if (this !== globalThis) {
        throw new TypeError("Illegal invocation");
      }
      return new Response(null, { status: 204 });
    }) as typeof fetch;

    const fetchImpl = resolveFetchImplementation(globalThis.fetch);
    await fetchImpl?.("https://example.com");

    expect(receiver).toBe(globalThis);
  });
});
