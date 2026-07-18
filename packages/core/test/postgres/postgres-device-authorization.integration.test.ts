import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { deviceAuthorizationGrantType } from "../../src/index.js";
import { PostgresAuthStorage } from "../../src/postgres/index.js";
import {
  deviceAccessToken,
  deviceAuthorization,
  deviceGrant,
  deviceSession,
  deviceUser
} from "../helpers/device-authorization.js";
import {
  createPostgresTestDatabase,
  hasPostgresTestDatabase,
  type PostgresTestDatabase
} from "./postgres-test-database.js";

const describeWithDatabase = hasPostgresTestDatabase ? describe : describe.skip;

describeWithDatabase("Postgres device authorization integration", () => {
  let database: PostgresTestDatabase;

  beforeAll(async () => {
    database = await createPostgresTestDatabase();
  });

  afterAll(async () => {
    await database?.close();
  });

  it("allows only one approval or denial across separate connections", async () => {
    const fixture = await createFixture(database);
    try {
      const results = await Promise.all([
        fixture.deviceStorage[0].approveDeviceAuthorization({
          userCodeHash: fixture.userCodeHash,
          userId: fixture.userId,
          sessionId: fixture.sessionId,
          approvedScopes: ["openid"],
          grant: fixture.grant,
          decidedAt: new Date()
        }),
        fixture.deviceStorage[1].denyDeviceAuthorization({
          userCodeHash: fixture.userCodeHash,
          userId: fixture.userId,
          sessionId: fixture.sessionId,
          decidedAt: new Date()
        })
      ]);

      expect(results.filter(({ status }) => status === "already_decided"))
        .toHaveLength(1);
      expect(results.filter(({ status }) => status === "approved" || status === "denied"))
        .toHaveLength(1);
    } finally {
      fixture.close();
    }
  });

  it("issues tokens exactly once across separate connections", async () => {
    const fixture = await createFixture(database);
    try {
      const approval = await fixture.deviceStorage[0].approveDeviceAuthorization({
        userCodeHash: fixture.userCodeHash,
        userId: fixture.userId,
        sessionId: fixture.sessionId,
        approvedScopes: ["openid"],
        grant: fixture.grant,
        decidedAt: new Date()
      });
      expect(approval.status).toBe("approved");
      const attempts = [0, 1].map((index) => ({
        ...deviceAccessToken(),
        id: `oat_${fixture.id}_${index}`,
        tokenHash: `access_${fixture.id}_${index}`,
        prefix: `oa_at_${fixture.id}_${index}`,
        grantId: fixture.grant.id,
        authorizationClientId: fixture.clientId,
        userId: fixture.userId,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000)
      }));
      const results = await Promise.all(attempts.map((accessToken, index) =>
        fixture.deviceStorage[index as 0 | 1].consumeDeviceAuthorization({
          id: fixture.authorizationId,
          deviceCodeHash: fixture.deviceCodeHash,
          authorizationClientId: fixture.clientId,
          consumedAt: new Date(),
          accessToken,
          refreshToken: null
        })
      ));

      expect(results.sort()).toEqual([false, true]);
      const stored = await Promise.all(attempts.map(({ tokenHash }) =>
        fixture.storage[0].authorizationServerStorage
          .getAuthorizationAccessTokenByHash(tokenHash)
      ));
      expect(stored.filter(Boolean)).toHaveLength(1);
    } finally {
      fixture.close();
    }
  });
});

async function createFixture(database: PostgresTestDatabase) {
  const [first, second] = await database.connectPair();
  const storage = [new PostgresAuthStorage(first), new PostgresAuthStorage(second)] as const;
  const deviceStorage = [
    storage[0].authorizationServerStorage.deviceAuthorizationStorage,
    storage[1].authorizationServerStorage.deviceAuthorizationStorage
  ] as const;
  const id = crypto.randomUUID();
  const now = new Date();
  const userId = `usr_device_${id}`;
  const sessionId = `ses_device_${id}`;
  const clientId = `ocli_device_${id}`;
  const authorizationId = `oda_${id}`;
  const userCodeHash = `user_code_${id}`;
  const deviceCodeHash = `device_code_${id}`;
  const grant = {
    ...deviceGrant(),
    id: `ogrant_device_${id}`,
    authorizationClientId: clientId,
    userId,
    createdAt: now,
    updatedAt: now
  };

  await storage[0].createUser({ ...deviceUser(userId), createdAt: now, updatedAt: now });
  await storage[0].createSession({
    ...deviceSession(userId),
    id: sessionId,
    tokenHash: `session_token_${id}`,
    createdAt: now,
    lastActiveAt: now,
    authenticatedAt: now,
    expiresAt: new Date(now.getTime() + 60_000),
    idleExpiresAt: new Date(now.getTime() + 60_000)
  });
  await storage[0].authorizationServerStorage.createAuthorizationClient({
    id: clientId,
    clientId: `oa_client_${id}`,
    name: "Concurrent device client",
    clientType: "public",
    applicationType: "native",
    tokenEndpointAuthMethod: "none",
    redirectUris: [],
    allowedScopes: ["openid"],
    grantTypes: [deviceAuthorizationGrantType],
    dpopBoundAccessTokens: false,
    status: "active",
    createdAt: now,
    updatedAt: now,
    revokedAt: null
  }, null);
  await deviceStorage[0].createDeviceAuthorization(deviceAuthorization({
    id: authorizationId,
    deviceCodeHash,
    userCodeHash,
    authorizationClientId: clientId,
    nextPollAt: new Date(now.getTime() + 5_000),
    expiresAt: new Date(now.getTime() + 60_000),
    createdAt: now
  }));

  return {
    id,
    storage,
    deviceStorage,
    userId,
    sessionId,
    clientId,
    authorizationId,
    userCodeHash,
    deviceCodeHash,
    grant,
    close() {
      first.release();
      second.release();
    }
  };
}
