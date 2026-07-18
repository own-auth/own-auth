import { beforeAll, describe, expect, it } from "vitest";
import {
  createOwnAuth,
  createOwnAuthAuthorizationServerHandler,
  deviceAuthorizationGrantType,
  InMemoryAuthStorage
} from "../src/index.js";
import { createDpopProof, generateDpopKeyPair } from "../src/dpop.js";
import {
  createAuthorizationFormRequest,
  createSigningPrivateKey
} from "./helpers/authorization-server.js";

const issuer = "http://localhost";
const verificationUrl = `${issuer}/device`;
const formRequest = createAuthorizationFormRequest(issuer);
let signingPrivateKey = "";

beforeAll(async () => {
  signingPrivateKey = await createSigningPrivateKey();
});

describe("OAuth device authorization", () => {
  it("advertises device authorization only when configured", async () => {
    const enabled = createHarness();
    await expect(enabled.auth.authorizationServer.metadata()).resolves.toMatchObject({
      device_authorization_endpoint: `${issuer}/oauth/device/authorize`,
      grant_types_supported: expect.arrayContaining([deviceAuthorizationGrantType])
    });

    const disabled = createHarness(false, false);
    const metadata = await disabled.auth.authorizationServer.metadata();
    expect(metadata).not.toHaveProperty("device_authorization_endpoint");
    expect(metadata.grant_types_supported).not.toContain(deviceAuthorizationGrantType);
    const response = await disabled.handler(formRequest("/oauth/device/authorize", {
      client_id: "unknown-client",
      scope: "openid"
    }));
    expect(response.status).toBe(404);
  });

  it("completes a hash-only, normalized, single-use device flow", async () => {
    const { auth, handler, storage } = createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "device@example.com",
      password: "correct-horse"
    });
    const client = await createDeviceClient(auth);
    const started = await startDeviceFlow(handler, client.clientId, [
      "openid",
      "offline_access"
    ]);

    expect(started).toMatchObject({
      device_code: expect.stringMatching(/^oa_dc_/),
      user_code: expect.stringMatching(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/),
      verification_uri: verificationUrl,
      interval: 5
    });
    expect(started.verification_uri_complete).toContain(
      `user_code=${encodeURIComponent(started.user_code)}`
    );
    await expect(
      storage.authorizationServerStorage.deviceAuthorizationStorage
        .getDeviceAuthorizationByDeviceCodeHash(started.device_code)
    ).resolves.toBeNull();
    await expect(
      storage.authorizationServerStorage.deviceAuthorizationStorage
        .getDeviceAuthorizationByUserCodeHash(started.user_code)
    ).resolves.toBeNull();

    const typedCode = started.user_code.toLowerCase().replace("-", " ");
    const signedOutRequest = await auth.authorizationServer.getDeviceAuthorization({
      userCode: typedCode
    });
    expect(signedOutRequest).toMatchObject({
      action: "sign_in",
      client: { name: "Device client", applicationType: "native" },
      resource: null,
      scopes: [
        expect.objectContaining({ name: "openid" }),
        expect.objectContaining({ name: "offline_access" })
      ]
    });
    expect(signedOutRequest).not.toHaveProperty("deviceCode");
    expect(signedOutRequest.client).not.toHaveProperty("clientId");
    await expect(auth.authorizationServer.getDeviceAuthorization({
      userCode: typedCode,
      sessionToken: signup.sessionToken
    })).resolves.toMatchObject({
      action: "consent",
      client: { name: "Device client", applicationType: "native" },
      scopes: [
        expect.objectContaining({ name: "openid" }),
        expect.objectContaining({ name: "offline_access" })
      ]
    });

    await auth.authorizationServer.approveDeviceAuthorization({
      userCode: typedCode,
      sessionToken: signup.sessionToken,
      approvedScopes: ["openid", "offline_access"]
    });
    const exchanged = await pollDeviceFlow(handler, client.clientId, started.device_code);
    expect(exchanged.status).toBe(200);
    const tokens = await exchanged.json() as {
      access_token: string;
      refresh_token: string;
      token_type: string;
    };
    expect(tokens).toMatchObject({
      access_token: expect.stringMatching(/^oa_at_/),
      refresh_token: expect.stringMatching(/^oa_rt_/),
      token_type: "Bearer"
    });
    await expect(auth.authorizationServer.verifyAccessToken({
      accessToken: tokens.access_token
    })).resolves.toMatchObject({ userId: signup.user.id });

    const replay = await pollDeviceFlow(handler, client.clientId, started.device_code);
    expect(replay.status).toBe(400);
    await expect(replay.json()).resolves.toMatchObject({ error: "invalid_grant" });

    const audit = await storage.listAuditEvents();
    expect(audit.map(({ eventType }) => eventType)).toEqual(expect.arrayContaining([
      "authorization_server.device_authorization_started",
      "authorization_server.device_authorization_approved",
      "authorization_server.device_token_exchanged"
    ]));
    const auditJson = JSON.stringify(audit);
    expect(auditJson).not.toContain(started.device_code);
    expect(auditJson).not.toContain(started.user_code);
  });

  it("keeps page errors separate from RFC polling errors", async () => {
    const { auth, handler } = createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "denied@example.com",
      password: "correct-horse"
    });
    const client = await createDeviceClient(auth);
    const started = await startDeviceFlow(handler, client.clientId, ["openid"]);

    const earlyPoll = await pollDeviceFlow(handler, client.clientId, started.device_code);
    expect(earlyPoll.status).toBe(400);
    await expect(earlyPoll.json()).resolves.toMatchObject({ error: "slow_down" });

    await auth.authorizationServer.denyDeviceAuthorization({
      userCode: started.user_code,
      sessionToken: signup.sessionToken
    });
    await expect(auth.authorizationServer.approveDeviceAuthorization({
      userCode: started.user_code,
      sessionToken: signup.sessionToken
    })).rejects.toMatchObject({ code: "device_authorization_already_decided" });

    const denied = await pollDeviceFlow(handler, client.clientId, started.device_code);
    const deniedBody = await denied.json() as { error: string };
    expect(denied.status).toBe(400);
    expect(deniedBody).toEqual(expect.objectContaining({ error: "access_denied" }));
    expect(JSON.stringify(deniedBody)).not.toContain("device_authorization_");
  });

  it("does not disclose a valid device code to another client", async () => {
    const { auth, handler } = createHarness();
    const owner = await createDeviceClient(auth, "Owner client");
    const other = await createDeviceClient(auth, "Other client");
    const started = await startDeviceFlow(handler, owner.clientId, ["openid"]);

    const wrongClient = await pollDeviceFlow(
      handler,
      other.clientId,
      started.device_code
    );
    const unknownCode = await pollDeviceFlow(handler, other.clientId, "oa_dc_unknown");
    expect(wrongClient.status).toBe(400);
    expect(unknownCode.status).toBe(400);
    await expect(wrongClient.json()).resolves.toMatchObject({ error: "invalid_grant" });
    await expect(unknownCode.json()).resolves.toMatchObject({ error: "invalid_grant" });
  });

  it("atomically accepts only the first user decision", async () => {
    const { auth, handler } = createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "decision@example.com",
      password: "correct-horse"
    });
    const client = await createDeviceClient(auth);
    const started = await startDeviceFlow(handler, client.clientId, ["openid"]);
    const decision = {
      userCode: started.user_code,
      sessionToken: signup.sessionToken
    };

    const attempts = await Promise.allSettled([
      auth.authorizationServer.approveDeviceAuthorization(decision),
      auth.authorizationServer.denyDeviceAuthorization(decision)
    ]);
    expect(attempts.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
    const rejected = attempts.find(({ status }) => status === "rejected");
    expect(rejected).toMatchObject({
      status: "rejected",
      reason: { code: "device_authorization_already_decided" }
    });
  });

  it("pins every device poll to the DPoP key supplied at start", async () => {
    const { auth, handler } = createHarness(true);
    const signup = await auth.signUpEmailPassword({
      email: "device-dpop@example.com",
      password: "correct-horse"
    });
    const client = await createDeviceClient(auth, "DPoP device", true);
    const keyPair = await generateDpopKeyPair();
    const wrongPair = await generateDpopKeyPair();
    const started = await startDeviceFlow(
      handler,
      client.clientId,
      ["openid"],
      keyPair.jwkThumbprint
    );
    await auth.authorizationServer.approveDeviceAuthorization({
      userCode: started.user_code,
      sessionToken: signup.sessionToken
    });

    const wrongProof = await createDpopProof({
      keyPair: wrongPair,
      method: "POST",
      url: `${issuer}/oauth/token`
    });
    const rejected = await pollDeviceFlow(
      handler,
      client.clientId,
      started.device_code,
      wrongProof
    );
    await expect(rejected.json()).resolves.toMatchObject({
      error: "invalid_dpop_proof"
    });

    const proof = await createDpopProof({
      keyPair,
      method: "POST",
      url: `${issuer}/oauth/token`
    });
    const accepted = await pollDeviceFlow(
      handler,
      client.clientId,
      started.device_code,
      proof
    );
    await expect(accepted.json()).resolves.toMatchObject({ token_type: "DPoP" });
  });

  it("cleans expired device records on an application-owned schedule", async () => {
    const { auth, handler } = createHarness();
    const client = await createDeviceClient(auth);
    const started = await startDeviceFlow(handler, client.clientId, ["openid"]);

    await expect(auth.authorizationServer.cleanupDeviceAuthorizations({
      olderThan: new Date(Date.now() + 11 * 60 * 1_000)
    })).resolves.toBe(1);
    await expect(auth.authorizationServer.getDeviceAuthorization({
      userCode: started.user_code
    })).rejects.toMatchObject({ code: "device_authorization_invalid" });
  });
});

function createHarness(dpop = false, deviceAuthorization = true) {
  const storage = new InMemoryAuthStorage();
  const auth = createOwnAuth({
    storage,
    tokenPepper: "device-authorization-test-pepper",
    encryption: {
      current: { id: "test-key", key: new Uint8Array(32).fill(7) }
    },
    authorizationServer: {
      issuer,
      interactionUrl: `${issuer}/authorize/interaction`,
      signingKeys: {
        current: { id: "signing-key", privateKey: signingPrivateKey }
      },
      ...(deviceAuthorization
        ? { deviceAuthorization: { verificationUrl } }
        : {}),
      ...(dpop ? { dpop: {} } : {})
    }
  });
  return {
    auth,
    handler: createOwnAuthAuthorizationServerHandler(auth, {
      getRequestContext: () => ({ ipAddress: "203.0.113.42" })
    }),
    storage
  };
}

async function createDeviceClient(
  auth: ReturnType<typeof createOwnAuth>,
  name = "Device client",
  dpopBoundAccessTokens = false
) {
  const { client } = await auth.authorizationServer.createClient({
    name,
    clientType: "public",
    applicationType: "native",
    allowedScopes: ["openid", "offline_access"],
    grantTypes: [deviceAuthorizationGrantType, "refresh_token"],
    dpopBoundAccessTokens
  });
  return client;
}

async function startDeviceFlow(
  handler: ReturnType<typeof createOwnAuthAuthorizationServerHandler>,
  clientId: string,
  scopes: string[],
  dpopJkt?: string
) {
  const response = await handler(formRequest("/oauth/device/authorize", {
    client_id: clientId,
    scope: scopes.join(" "),
    ...(dpopJkt ? { dpop_jkt: dpopJkt } : {})
  }));
  expect(response.status).toBe(200);
  return response.json() as Promise<{
    device_code: string;
    user_code: string;
    verification_uri: string;
    verification_uri_complete: string;
    expires_in: number;
    interval: number;
  }>;
}

function pollDeviceFlow(
  handler: ReturnType<typeof createOwnAuthAuthorizationServerHandler>,
  clientId: string,
  deviceCode: string,
  dpopProof?: string
): Promise<Response> {
  return handler(formRequest("/oauth/token", {
    grant_type: deviceAuthorizationGrantType,
    client_id: clientId,
    device_code: deviceCode
  }, dpopProof));
}
