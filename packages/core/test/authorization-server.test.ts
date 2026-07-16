import {
  createLocalJWKSet,
  exportPKCS8,
  generateKeyPair,
  jwtVerify
} from "jose";
import { describe, expect, it } from "vitest";
import {
  createOwnAuth,
  createOwnAuthAuthorizationServerHandler,
  InMemoryAuthStorage
} from "../src/index.js";

const issuer = "http://localhost";
const redirectUri = "https://client.example.com/callback";
const codeVerifier = "v".repeat(43);

describe("OAuth/OIDC authorization server", () => {
  it("completes authorization code and OIDC userinfo flows without exposing interaction details", async () => {
    const { auth, handler } = await createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "alice@example.com",
      password: "correct-horse",
      name: "Alice"
    });
    const { client } = await auth.authorizationServer.createClient({
      name: "Example client",
      clientType: "public",
      applicationType: "web",
      redirectUris: [redirectUri],
      allowedScopes: ["openid", "profile", "email", "offline_access"]
    });
    const started = await startAuthorization(handler, {
      clientId: client.clientId,
      sessionToken: signup.sessionToken,
      scopes: ["openid", "profile", "email"]
    });

    await expect(auth.authorizationServer.getInteraction({
      interactionToken: started.interactionToken
    })).resolves.toMatchObject({
      action: "sign_in",
      client: null,
      scopes: []
    });
    await expect(auth.authorizationServer.getInteraction({
      interactionToken: started.interactionToken,
      sessionToken: signup.sessionToken
    })).resolves.toMatchObject({
      action: "consent",
      client: { clientId: client.clientId, name: "Example client" }
    });

    const approved = await auth.authorizationServer.approveInteraction({
      interactionToken: started.interactionToken,
      sessionToken: signup.sessionToken,
      approvedScopes: ["openid", "profile", "email"]
    });
    const code = new URL(approved.redirectUrl).searchParams.get("code") ?? "";
    const tokenResponse = await exchangeCode(handler, client.clientId, code);
    expect(tokenResponse.status).toBe(200);
    const tokens = await tokenResponse.json() as {
      access_token: string;
      id_token: string;
      scope: string;
    };
    expect(tokens.access_token).toMatch(/^oa_at_/);
    expect(tokens.id_token).toBeTruthy();
    expect(tokens.scope).toBe("openid profile email");

    const verified = await auth.authorizationServer.verifyAccessToken({
      accessToken: tokens.access_token,
      requiredScopes: ["email"]
    });
    expect(verified.userId).toBe(signup.user.id);

    const userInfoResponse = await handler(new Request(`${issuer}/oauth/userinfo`, {
      headers: { authorization: `Bearer ${tokens.access_token}` }
    }));
    await expect(userInfoResponse.json()).resolves.toMatchObject({
      sub: expect.stringMatching(/^oa_sub_/),
      name: "Alice",
      email: "alice@example.com",
      email_verified: false
    });

    const jwks = await (
      await handler(new Request(`${issuer}/oauth/jwks`))
    ).json() as Parameters<typeof createLocalJWKSet>[0];
    const idClaims = await jwtVerify(tokens.id_token, createLocalJWKSet(jwks), {
      issuer,
      audience: client.clientId
    });
    expect(idClaims.payload.sub).toMatch(/^oa_sub_/);
    expect(idClaims.payload.email).toBe("alice@example.com");

    const replay = await exchangeCode(handler, client.clientId, code);
    expect(replay.status).toBe(400);
    await expect(replay.json()).resolves.toMatchObject({ error: "invalid_grant" });
  });

  it("always presents select_account even when only one signed-in account exists", async () => {
    const { auth, handler } = await createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "select@example.com",
      password: "correct-horse"
    });
    const { client } = await auth.authorizationServer.createClient({
      name: "Select account client",
      clientType: "public",
      applicationType: "web",
      redirectUris: [redirectUri],
      allowedScopes: ["openid"]
    });
    const first = await startAuthorization(handler, {
      clientId: client.clientId,
      sessionToken: signup.sessionToken,
      scopes: ["openid"]
    });
    await auth.authorizationServer.approveInteraction({
      interactionToken: first.interactionToken,
      sessionToken: signup.sessionToken,
      approvedScopes: ["openid"]
    });

    const second = await startAuthorization(handler, {
      clientId: client.clientId,
      sessionToken: signup.sessionToken,
      scopes: ["openid"],
      prompt: "select_account"
    });
    await expect(auth.authorizationServer.getInteraction({
      interactionToken: second.interactionToken,
      sessionToken: signup.sessionToken
    })).resolves.toMatchObject({ action: "select_account" });
  });

  it("requires reauthentication whenever max_age is zero", async () => {
    const { auth, handler } = await createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "max-age@example.com",
      password: "correct-horse"
    });
    await auth.storage.updateSession(signup.session.id, {
      authenticatedAt: new Date(Date.now() + 60_000)
    });
    const { client } = await auth.authorizationServer.createClient({
      name: "Max age client",
      clientType: "public",
      applicationType: "web",
      redirectUris: [redirectUri],
      allowedScopes: ["openid"]
    });
    const started = await startAuthorization(handler, {
      clientId: client.clientId,
      sessionToken: signup.sessionToken,
      scopes: ["openid"],
      maxAge: "0"
    });

    await expect(auth.authorizationServer.getInteraction({
      interactionToken: started.interactionToken,
      sessionToken: signup.sessionToken
    })).resolves.toMatchObject({ action: "reauthenticate" });
  });

  it("allows an interaction to finish only once under concurrent approval", async () => {
    const { auth, handler } = await createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "interaction-race@example.com",
      password: "correct-horse"
    });
    const { client } = await auth.authorizationServer.createClient({
      name: "Interaction race client",
      clientType: "public",
      applicationType: "web",
      redirectUris: [redirectUri],
      allowedScopes: ["openid"]
    });
    const started = await startAuthorization(handler, {
      clientId: client.clientId,
      sessionToken: signup.sessionToken,
      scopes: ["openid"]
    });
    const attempts = await Promise.allSettled([
      auth.authorizationServer.approveInteraction({
        interactionToken: started.interactionToken,
        sessionToken: signup.sessionToken,
        approvedScopes: ["openid"]
      }),
      auth.authorizationServer.approveInteraction({
        interactionToken: started.interactionToken,
        sessionToken: signup.sessionToken,
        approvedScopes: ["openid"]
      })
    ]);

    expect(attempts.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
    expect(attempts.filter(({ status }) => status === "rejected")).toHaveLength(1);
  });

  it("revokes the whole grant including the concurrent refresh winner", async () => {
    const { auth, handler } = await createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "refresh@example.com",
      password: "correct-horse"
    });
    const { client } = await auth.authorizationServer.createClient({
      name: "Refresh client",
      clientType: "public",
      applicationType: "web",
      redirectUris: [redirectUri],
      allowedScopes: ["openid", "offline_access"]
    });
    const started = await startAuthorization(handler, {
      clientId: client.clientId,
      sessionToken: signup.sessionToken,
      scopes: ["openid", "offline_access"]
    });
    const approved = await auth.authorizationServer.approveInteraction({
      interactionToken: started.interactionToken,
      sessionToken: signup.sessionToken,
      approvedScopes: ["openid", "offline_access"]
    });
    const code = new URL(approved.redirectUrl).searchParams.get("code") ?? "";
    const initial = await (await exchangeCode(handler, client.clientId, code)).json() as {
      refresh_token: string;
    };

    const attempts = await Promise.all([
      refresh(handler, client.clientId, initial.refresh_token),
      refresh(handler, client.clientId, initial.refresh_token)
    ]);
    expect(attempts.map(({ status }) => status).sort()).toEqual([200, 400]);
    const winner = attempts.find(({ status }) => status === 200);
    const winnerTokens = await winner?.json() as { access_token: string };
    await expect(auth.authorizationServer.verifyAccessToken({
      accessToken: winnerTokens.access_token
    })).rejects.toMatchObject({ code: "invalid_token" });
  });

  it("allows confidential clients to introspect only their own tokens", async () => {
    const { auth, handler } = await createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "introspection@example.com",
      password: "correct-horse"
    });
    const first = await auth.authorizationServer.createClient({
      name: "First confidential client",
      clientType: "confidential",
      applicationType: "web",
      tokenEndpointAuthMethod: "client_secret_post",
      redirectUris: [redirectUri],
      allowedScopes: ["openid"]
    });
    const second = await auth.authorizationServer.createClient({
      name: "Second confidential client",
      clientType: "confidential",
      applicationType: "web",
      tokenEndpointAuthMethod: "client_secret_post",
      redirectUris: ["https://second.example.com/callback"],
      allowedScopes: ["openid"]
    });
    const started = await startAuthorization(handler, {
      clientId: first.client.clientId,
      sessionToken: signup.sessionToken,
      scopes: ["openid"]
    });
    const approved = await auth.authorizationServer.approveInteraction({
      interactionToken: started.interactionToken,
      sessionToken: signup.sessionToken,
      approvedScopes: ["openid"]
    });
    const code = new URL(approved.redirectUrl).searchParams.get("code") ?? "";
    const exchanged = await exchangeCode(
      handler,
      first.client.clientId,
      code,
      first.clientSecret ?? ""
    );
    const token = (await exchanged.json() as { access_token: string }).access_token;

    const own = await introspect(
      handler,
      first.client.clientId,
      first.clientSecret ?? "",
      token
    );
    await expect(own.json()).resolves.toMatchObject({
      active: true,
      client_id: first.client.clientId
    });

    const other = await introspect(
      handler,
      second.client.clientId,
      second.clientSecret ?? "",
      token
    );
    await expect(other.json()).resolves.toEqual({ active: false });
  });
});

async function createHarness() {
  const { privateKey } = await generateKeyPair("RS256", { extractable: true });
  const auth = createOwnAuth({
    storage: new InMemoryAuthStorage(),
    tokenPepper: "authorization-server-test-pepper",
    encryption: {
      current: {
        id: "test-key",
        key: new Uint8Array(32).fill(7)
      }
    },
    authorizationServer: {
      issuer,
      interactionUrl: `${issuer}/authorize/interaction`,
      signingKeys: {
        current: {
          id: "signing-key",
          privateKey: await exportPKCS8(privateKey)
        }
      }
    }
  });
  return {
    auth,
    handler: createOwnAuthAuthorizationServerHandler(auth)
  };
}

async function startAuthorization(
  handler: ReturnType<typeof createOwnAuthAuthorizationServerHandler>,
  input: {
    clientId: string;
    sessionToken: string;
    scopes: string[];
    prompt?: string;
    maxAge?: string;
  }
): Promise<{ interactionToken: string }> {
  const url = new URL(`${issuer}/oauth/authorize`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", input.clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", input.scopes.join(" "));
  url.searchParams.set("state", "state-value");
  url.searchParams.set("code_challenge", await pkceChallenge(codeVerifier));
  url.searchParams.set("code_challenge_method", "S256");
  if (input.prompt) url.searchParams.set("prompt", input.prompt);
  if (input.maxAge) url.searchParams.set("max_age", input.maxAge);
  const response = await handler(new Request(url, {
    headers: { cookie: `own_auth_session=${input.sessionToken}` }
  }));
  expect(response.status).toBe(302);
  const location = new URL(response.headers.get("location") ?? "");
  return {
    interactionToken: location.searchParams.get("interaction") ?? ""
  };
}

function exchangeCode(
  handler: ReturnType<typeof createOwnAuthAuthorizationServerHandler>,
  clientId: string,
  code: string,
  clientSecret?: string
): Promise<Response> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
    ...(clientSecret ? { client_secret: clientSecret } : {})
  });
  return handler(formRequest("/oauth/token", body));
}

function refresh(
  handler: ReturnType<typeof createOwnAuthAuthorizationServerHandler>,
  clientId: string,
  refreshToken: string
): Promise<Response> {
  return handler(formRequest("/oauth/token", new URLSearchParams({
    grant_type: "refresh_token",
    client_id: clientId,
    refresh_token: refreshToken
  })));
}

function introspect(
  handler: ReturnType<typeof createOwnAuthAuthorizationServerHandler>,
  clientId: string,
  clientSecret: string,
  token: string
): Promise<Response> {
  return handler(formRequest("/oauth/introspect", new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    token
  })));
}

function formRequest(path: string, body: URLSearchParams): Request {
  return new Request(`${issuer}${path}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body
  });
}

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))
  );
  let binary = "";
  for (const byte of digest) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}
