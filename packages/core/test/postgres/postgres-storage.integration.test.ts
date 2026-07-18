import { afterAll, beforeAll, describe, expect, it } from "vitest";
import pg from "pg";
import {
  createOwnAuth,
  MemoryEmailProvider,
  MemorySmsProvider
} from "../../src/index.js";
import { PostgresAuthStorage, PostgresRateLimitStore } from "../../src/postgres/index.js";
import { createConformanceGoogleProvider } from "../conformance/conformance-oauth-provider.js";
import {
  evaluatePersistenceChecks,
  persistenceSecrets,
  type PersistenceConformanceArtifacts
} from "../conformance/persistence-conformance-contract.js";
import { runPersistenceConformance } from "../conformance/persistence-conformance.js";
import {
  createPostgresTestDatabase,
  hasPostgresTestDatabase,
  type PostgresTestDatabase
} from "./postgres-test-database.js";

const describeWithDatabase = hasPostgresTestDatabase ? describe : describe.skip;

describeWithDatabase("PostgresAuthStorage integration", () => {
  let database: PostgresTestDatabase;
  let client: pg.PoolClient;

  beforeAll(async () => {
    database = await createPostgresTestDatabase();
    client = database.client;
  });

  afterAll(async () => {
    await database?.close();
  });

  it("runs real auth flows against migrated Postgres tables without storing raw secrets", async () => {
    const auth = createOwnAuth({
      storage: new PostgresAuthStorage(client),
      rateLimitStore: new PostgresRateLimitStore(client),
      emailProvider: new MemoryEmailProvider(),
      smsProvider: new MemorySmsProvider(),
      exposeRawTokens: true,
      baseUrl: "http://localhost:3000",
      tokenPepper: "integration-test-pepper",
      encryption: {
        current: { id: "integration", key: new Uint8Array(32).fill(7) }
      },
      oauth: { adapters: [createConformanceGoogleProvider()] },
      passkeys: {
        rpId: "localhost",
        rpName: "Own Auth integration",
        origins: ["http://localhost:3000"]
      }
    });

    await runPersistenceConformance({
      auth,
      inspect: (artifacts) => inspectPostgres(client, artifacts)
    });
  }, 20_000);

  it("uses and closes the default lazy Postgres pool", async () => {
    const previousNodeEnv = process.env.NODE_ENV;
    const previousDatabaseUrl = process.env.DATABASE_URL;
    process.env.NODE_ENV = "development";
    process.env.DATABASE_URL = database.connectionString;
    const auth = createOwnAuth({ tokenPepper: "lazy-integration-test-pepper" });

    try {
      const signup = await auth.signUpEmailPassword({
        email: "lazy-pool@example.com",
        password: "correct-horse"
      });
      const session = await auth.requireCurrentSession(signup.sessionToken);

      expect(session.user.id).toBe(signup.user.id);
      await auth.close();
      await expect(auth.getCurrentSession(signup.sessionToken)).rejects.toMatchObject({
        code: "auth_closed",
        message: "Own Auth has been closed"
      });
      await expect(auth.close()).resolves.toBeUndefined();
    } finally {
      await auth.close().catch(() => undefined);
      process.env.NODE_ENV = previousNodeEnv;
      if (previousDatabaseUrl === undefined) {
        delete process.env.DATABASE_URL;
      } else {
        process.env.DATABASE_URL = previousDatabaseUrl;
      }
    }
  });

  it("invalidates only tokens that carry removed protected-resource scopes", async () => {
    const storage = new PostgresAuthStorage(client);
    const authorization = storage.authorizationServerStorage;
    const suffix = crypto.randomUUID();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 60_000);
    const userId = `usr_${suffix}`;
    const clientId = `ocli_${suffix}`;
    const resourceId = `opres_${suffix}`;
    const grantId = `ogrant_${suffix}`;
    const readTokenHash = `read_${suffix}`;
    const broadTokenHash = `broad_${suffix}`;
    const refreshTokenHash = `refresh_${suffix}`;

    await storage.createUser({
      id: userId,
      email: `${suffix}@example.com`,
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
    await authorization.createAuthorizationClient({
      id: clientId,
      clientId: `oa_client_${suffix}`,
      name: "Protected resource client",
      clientType: "public",
      applicationType: "web",
      tokenEndpointAuthMethod: "none",
      redirectUris: ["https://client.example.com/callback"],
      allowedScopes: ["documents:read", "documents:write", "offline_access"],
      grantTypes: ["authorization_code", "refresh_token"],
      dpopBoundAccessTokens: false,
      status: "active",
      createdAt: now,
      updatedAt: now,
      revokedAt: null
    }, null);
    await authorization.createProtectedResource({
      id: resourceId,
      identifier: `https://api-${suffix}.example.com/`,
      name: "Documents API",
      allowedScopes: ["documents:read", "documents:write", "offline_access"],
      requireDpop: false,
      status: "active",
      createdAt: now,
      updatedAt: now,
      revokedAt: null
    }, {
      id: `oprsec_${suffix}`,
      protectedResourceId: resourceId,
      prefix: `oa_rs_${suffix}`,
      secretHash: `secret_hash_${suffix}`,
      createdAt: now,
      expiresAt: null,
      revokedAt: null
    });
    await authorization.upsertAuthorizationGrant({
      id: grantId,
      authorizationClientId: clientId,
      userId,
      protectedResourceId: resourceId,
      scopes: ["documents:read", "documents:write", "offline_access"],
      createdAt: now,
      updatedAt: now,
      revokedAt: null
    });
    await authorization.createAuthorizationTokens({
      id: `oat_read_${suffix}`,
      tokenHash: readTokenHash,
      prefix: `oa_at_read_${suffix}`,
      grantId,
      authorizationClientId: clientId,
      userId,
      protectedResourceId: resourceId,
      scopes: ["documents:read"],
      dpopJkt: null,
      expiresAt,
      revokedAt: null,
      createdAt: now
    }, null);
    await authorization.createAuthorizationTokens({
      id: `oat_broad_${suffix}`,
      tokenHash: broadTokenHash,
      prefix: `oa_at_broad_${suffix}`,
      grantId,
      authorizationClientId: clientId,
      userId,
      protectedResourceId: resourceId,
      scopes: ["documents:read", "documents:write"],
      dpopJkt: null,
      expiresAt,
      revokedAt: null,
      createdAt: now
    }, {
      id: `ort_${suffix}`,
      tokenHash: refreshTokenHash,
      prefix: `oa_rt_${suffix}`,
      grantId,
      authorizationClientId: clientId,
      userId,
      protectedResourceId: resourceId,
      scopes: ["documents:read", "documents:write", "offline_access"],
      generation: 0,
      replacedByTokenId: null,
      dpopJkt: null,
      expiresAt,
      consumedAt: null,
      revokedAt: null,
      createdAt: now
    });

    await authorization.updateProtectedResource(resourceId, {
      allowedScopes: ["documents:read"],
      updatedAt: new Date()
    });

    await expect(authorization.getAuthorizationGrant(clientId, userId, resourceId))
      .resolves.toMatchObject({ scopes: ["documents:read"], revokedAt: null });
    await expect(authorization.getAuthorizationAccessTokenByHash(readTokenHash))
      .resolves.toMatchObject({ revokedAt: null });
    await expect(authorization.getAuthorizationAccessTokenByHash(broadTokenHash))
      .resolves.toMatchObject({ revokedAt: expect.any(Date) });
    await expect(authorization.getAuthorizationRefreshTokenByHash(refreshTokenHash))
      .resolves.toMatchObject({ revokedAt: expect.any(Date) });

    await authorization.updateProtectedResource(resourceId, {
      allowedScopes: ["documents:read", "documents:write", "offline_access"],
      updatedAt: new Date()
    });
    await expect(authorization.getAuthorizationAccessTokenByHash(broadTokenHash))
      .resolves.toMatchObject({ revokedAt: expect.any(Date) });

    await authorization.revokeProtectedResource(resourceId, new Date());
    await expect(authorization.getProtectedResourceByIdentifier(
      `https://api-${suffix}.example.com/`
    )).resolves.toMatchObject({ status: "revoked", revokedAt: expect.any(Date) });
  });
});

async function inspectPostgres(
  client: pg.PoolClient,
  artifacts: PersistenceConformanceArtifacts
): Promise<Record<string, boolean>> {
  const checks = await evaluatePersistenceChecks(artifacts, {
    countExact: (table, column, values) => countExact(client, table, column, values),
    countWhere: (table, column, value) => countWhere(client, table, column, value)
  });

  const allSecrets = persistenceSecrets(artifacts);
  const auditRows = await client.query<{ metadata: Record<string, unknown> }>(
    "select metadata from own_auth_audit_events"
  );
  const rateLimitRows = await client.query<{ count: number }>(
    "select count(*)::int as count from own_auth_rate_limits"
  );
  const deletionAuditRows = await client.query<{ count: number }>(
    "select count(*)::int as count from own_auth_audit_events " +
    "where event_type = 'organisation.deleted' and metadata->>'organisationId' = $1",
    [artifacts.organisationId]
  );

  return {
    ...checks,
    auditMetadataExcludesSecrets: auditRows.rows.every(({ metadata }) => {
      const serialized = JSON.stringify(metadata);
      return allSecrets.every((secret) => !serialized.includes(secret));
    }),
    rateLimitsWerePersisted: (rateLimitRows.rows[0]?.count ?? 0) > 0,
    organisationDeletionWasAudited: (deletionAuditRows.rows[0]?.count ?? 0) === 1
  };
}

async function countExact(
  client: pg.PoolClient,
  table: string,
  column: string,
  values: readonly string[]
): Promise<number> {
  if (values.length === 0) return 0;
  const result = await client.query<{ count: number }>(
    `select count(*)::int as count from ${identifier(table)} ` +
    `where ${identifier(column)} = any($1::text[])`,
    [values]
  );
  return result.rows[0]?.count ?? 0;
}

async function countWhere(
  client: pg.PoolClient,
  table: string,
  column: string,
  value: string
): Promise<number> {
  const result = await client.query<{ count: number }>(
    `select count(*)::int as count from ${identifier(table)} where ${identifier(column)} = $1`,
    [value]
  );
  return result.rows[0]?.count ?? 0;
}

function identifier(value: string): string {
  if (!/^[a-z_][a-z0-9_]*$/.test(value)) {
    throw new Error(`Unsafe Postgres identifier: ${value}`);
  }
  return `"${value}"`;
}
