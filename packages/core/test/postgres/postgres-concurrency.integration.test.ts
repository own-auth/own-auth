import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  createOwnAuth,
  MemoryEmailProvider,
  MemorySmsProvider
} from "../../src/index.js";
import {
  PostgresAuthStorage,
  PostgresRateLimitStore
} from "../../src/postgres/index.js";
import type { AuthStorage } from "../../src/storage.js";
import {
  describeAtomicAdapterConformance,
  type AtomicAdapterHarness
} from "../conformance/atomic-adapter-conformance.js";
import {
  authConcurrencyCases,
  type AuthConcurrencyHarness,
  type StorageBarrierMethod
} from "../conformance/auth-concurrency-cases.js";
import {
  createPostgresTestDatabase,
  hasPostgresTestDatabase,
  type PostgresTestDatabase
} from "./postgres-test-database.js";

const describeWithDatabase = hasPostgresTestDatabase ? describe : describe.skip;

describeWithDatabase("Postgres concurrency integration", () => {
  let database: PostgresTestDatabase;

  beforeAll(async () => {
    database = await createPostgresTestDatabase();
  });

  afterAll(async () => {
    await database?.close();
  });

  describeAtomicAdapterConformance("Postgres", async () => {
    const [first, second] = await database.connectPair();
    return {
      storage: [new PostgresAuthStorage(first), new PostgresAuthStorage(second)],
      rateLimits: [
        new PostgresRateLimitStore(database.queryable),
        new PostgresRateLimitStore(database.queryable)
      ],
      close() {
        first.release();
        second.release();
      }
    } satisfies AtomicAdapterHarness;
  });

  for (const testCase of authConcurrencyCases) {
    it(testCase.name, async () => {
      await withConcurrentAuth(
        database,
        testCase.barrierMethod,
        testCase.run,
        testCase.sms
      );
    });
  }

  it("revokes the refresh-token winner when the original token is reused concurrently", async () => {
    const [first, second] = await database.connectPair();
    const storage = [
      new PostgresAuthStorage(first),
      new PostgresAuthStorage(second)
    ] as const;
    const id = crypto.randomUUID();
    const now = new Date();
    const future = new Date(now.getTime() + 60_000);
    const userId = `usr_${id}`;
    const clientId = `ocli_${id}`;
    const grantId = `ogrant_${id}`;

    try {
      await storage[0].createUser({
        id: userId,
        email: `${id}@example.com`,
        emailVerifiedAt: now,
        phone: null,
        phoneVerifiedAt: null,
        passwordHash: null,
        name: null,
        imageUrl: null,
        disabledAt: null,
        metadata: {},
        createdAt: now,
        updatedAt: now,
        lastLoginAt: null
      });
      await storage[0].authorizationServerStorage.createAuthorizationClient({
        id: clientId,
        clientId: `oa_client_${id}`,
        name: "Concurrent client",
        clientType: "public",
        applicationType: "web",
        tokenEndpointAuthMethod: "none",
        redirectUris: ["https://client.example.com/callback"],
        allowedScopes: ["openid", "offline_access"],
        grantTypes: ["authorization_code", "refresh_token"],
        dpopBoundAccessTokens: false,
        status: "active",
        createdAt: now,
        updatedAt: now,
        revokedAt: null
      }, null);
      await storage[0].authorizationServerStorage.upsertAuthorizationGrant({
        id: grantId,
        authorizationClientId: clientId,
        userId,
        protectedResourceId: null,
        scopes: ["openid", "offline_access"],
        createdAt: now,
        updatedAt: now,
        revokedAt: null
      });
      await storage[0].authorizationServerStorage.createAuthorizationTokens(
        accessToken(`initial_${id}`, grantId, clientId, userId, now, future),
        refreshToken(`initial_${id}`, grantId, clientId, userId, now, future, 0)
      );

      const attempts = [0, 1].map((index) => ({
        access: accessToken(
          `winner_${index}_${id}`,
          grantId,
          clientId,
          userId,
          now,
          future
        ),
        refresh: refreshToken(
          `winner_${index}_${id}`,
          grantId,
          clientId,
          userId,
          now,
          future,
          1
        )
      }));
      const results = await Promise.all(attempts.map((attempt, index) =>
        storage[index as 0 | 1].authorizationServerStorage.rotateAuthorizationRefreshToken({
          tokenHash: `refresh_hash_initial_${id}`,
          authorizationClientId: clientId,
          replacementRefreshToken: attempt.refresh,
          accessToken: attempt.access,
          rotatedAt: new Date()
        })
      ));

      expect(results.sort()).toEqual(["reused", "rotated"]);
      await expect(
        storage[0].authorizationServerStorage.getAuthorizationGrant(clientId, userId, null)
      ).resolves.toMatchObject({ revokedAt: expect.any(Date) });
      const accessTokens = await Promise.all(attempts.map(({ access }) =>
        storage[0].authorizationServerStorage.getAuthorizationAccessTokenByHash(
          access.tokenHash
        )
      ));
      const refreshTokens = await Promise.all(attempts.map(({ refresh }) =>
        storage[0].authorizationServerStorage.getAuthorizationRefreshTokenByHash(
          refresh.tokenHash
        )
      ));
      expect(accessTokens.filter(Boolean)).toHaveLength(1);
      expect(accessTokens.filter(Boolean)[0]?.revokedAt).toBeInstanceOf(Date);
      expect(refreshTokens.filter(Boolean)).toHaveLength(1);
      expect(refreshTokens.filter(Boolean)[0]?.revokedAt).toBeInstanceOf(Date);
    } finally {
      first.release();
      second.release();
    }
  });

  it("consumes a DPoP proof exactly once across separate connections", async () => {
    const [first, second] = await database.connectPair();
    const storage = [
      new PostgresAuthStorage(first).authorizationServerStorage.dpopStorage,
      new PostgresAuthStorage(second).authorizationServerStorage.dpopStorage
    ] as const;
    const now = new Date();
    const input = {
      proofHash: `dpop_${crypto.randomUUID()}`,
      consumedAt: now,
      expiresAt: new Date(now.getTime() + 6 * 60 * 1_000)
    };

    try {
      const results = await Promise.all([
        storage[0].consumeDpopProof(input),
        storage[1].consumeDpopProof(input)
      ]);
      expect(results.sort()).toEqual([false, true]);
    } finally {
      first.release();
      second.release();
    }
  });

  it("consumes a SAML response exactly once across separate connections", async () => {
    const [first, second] = await database.connectPair();
    const storage = [
      new PostgresAuthStorage(first),
      new PostgresAuthStorage(second)
    ] as const;
    const id = crypto.randomUUID();
    const now = new Date();
    const userId = `usr_saml_${id}`;
    const organisationId = `org_saml_${id}`;
    const connectionId = `samlc_${id}`;

    try {
      await storage[0].createUser({
        id: userId,
        email: `saml-race-${id}@example.com`,
        emailVerifiedAt: now,
        phone: null,
        phoneVerifiedAt: null,
        passwordHash: null,
        name: null,
        imageUrl: null,
        disabledAt: null,
        metadata: {},
        createdAt: now,
        updatedAt: now,
        lastLoginAt: null
      });
      await storage[0].createOrganisation({
        id: organisationId,
        name: "SAML race",
        slug: `saml-race-${id}`,
        ownerUserId: userId,
        metadata: {},
        createdAt: now,
        updatedAt: now,
        disabledAt: null
      });
      await storage[0].samlStorage.createConnection({
        id: connectionId,
        organisationId,
        key: `saml_${id}`,
        name: "Race identity",
        idpEntityId: `https://idp.example.com/${id}`,
        ssoUrl: "https://idp.example.com/sso",
        idpCertificates: ["certificate"],
        attributeMapping: { email: "email" },
        accountLinking: "explicit",
        jitProvisioningEnabled: false,
        jitDefaultRole: "member",
        requestSigningCertificate: null,
        requestSigningKeyCiphertext: null,
        requestSigningKeyNonce: null,
        requestSigningEncryptionKeyId: null,
        disabledAt: null,
        createdAt: now,
        updatedAt: now
      });
      await storage[0].samlStorage.createTransaction({
        id: `samt_${id}`,
        connectionId,
        requestIdHash: `request_${id}`,
        relayStateHash: `relay_${id}`,
        intent: "sign_in",
        userId: null,
        destination: null,
        expiresAt: new Date(now.getTime() + 300_000),
        consumedAt: null,
        createdAt: now
      });
      const input = {
        relayStateHash: `relay_${id}`,
        requestIdHash: `request_${id}`,
        assertion: {
          assertionHash: `assertion_${id}`,
          connectionId,
          consumedAt: now,
          expiresAt: new Date(now.getTime() + 420_000)
        },
        consumedAt: now
      };

      const results = await Promise.all([
        storage[0].samlStorage.consumeResponse(input),
        storage[1].samlStorage.consumeResponse(input)
      ]);
      expect(results.filter(Boolean)).toHaveLength(1);
    } finally {
      first.release();
      second.release();
    }
  });
});

type Auth = ReturnType<typeof createOwnAuth>;

async function withConcurrentAuth(
  database: PostgresTestDatabase,
  barrierMethod: StorageBarrierMethod,
  run: (harness: AuthConcurrencyHarness) => Promise<void>,
  sms: { maxAttempts?: number } = {}
): Promise<void> {
  const [first, second] = await database.connectPair();
  const wait = createTwoPartyBarrier();
  const emailProvider = new MemoryEmailProvider();
  const smsProvider = new MemorySmsProvider();
  const storage = [
    withMethodBarrier(new PostgresAuthStorage(first), barrierMethod, wait),
    withMethodBarrier(new PostgresAuthStorage(second), barrierMethod, wait)
  ] as const;
  const rateLimits = [
    new PostgresRateLimitStore(first),
    new PostgresRateLimitStore(second)
  ] as const;
  const tokenPepper = `concurrency-${crypto.randomUUID()}`;
  const createAuth = (index: 0 | 1): Auth => createOwnAuth({
    storage: storage[index],
    rateLimitStore: rateLimits[index],
    emailProvider,
    smsProvider,
    exposeRawTokens: true,
    baseUrl: "http://localhost:3000",
    tokenPepper,
    sms
  });
  const auth = [createAuth(0), createAuth(1)] as const;

  try {
    await run({ auth, storage });
  } finally {
    first.release();
    second.release();
  }
}

function withMethodBarrier(
  storage: AuthStorage,
  method: StorageBarrierMethod,
  wait: () => Promise<void>
): AuthStorage {
  // Hold both flows immediately before the atomic write so Postgres resolves the race.
  return new Proxy(storage as object, {
    get(target, property) {
      const value = Reflect.get(target, property, target);
      if (typeof value !== "function") {
        return value;
      }
      if (property === method) {
        return async (...args: unknown[]) => {
          await wait();
          return value.apply(target, args);
        };
      }
      return value.bind(target);
    }
  }) as AuthStorage;
}

function createTwoPartyBarrier(): () => Promise<void> {
  let arrivals = 0;
  let release: (() => void) | undefined;
  const ready = new Promise<void>((resolve) => {
    release = resolve;
  });

  return async () => {
    arrivals += 1;
    if (arrivals === 2) {
      release?.();
    }
    await ready;
  };
}

function accessToken(
  suffix: string,
  grantId: string,
  authorizationClientId: string,
  userId: string,
  createdAt: Date,
  expiresAt: Date
) {
  return {
    id: `oat_${suffix}`,
    tokenHash: `access_hash_${suffix}`,
    prefix: `oa_at_${suffix}`,
    grantId,
    authorizationClientId,
    userId,
    protectedResourceId: null,
    scopes: ["openid", "offline_access"],
    dpopJkt: null,
    expiresAt,
    revokedAt: null,
    createdAt
  };
}

function refreshToken(
  suffix: string,
  grantId: string,
  authorizationClientId: string,
  userId: string,
  createdAt: Date,
  expiresAt: Date,
  generation: number
) {
  return {
    id: `ort_${suffix}`,
    tokenHash: `refresh_hash_${suffix}`,
    prefix: `oa_rt_${suffix}`,
    grantId,
    authorizationClientId,
    userId,
    protectedResourceId: null,
    scopes: ["openid", "offline_access"],
    generation,
    replacedByTokenId: null,
    dpopJkt: null,
    expiresAt,
    consumedAt: null,
    revokedAt: null,
    createdAt
  };
}
