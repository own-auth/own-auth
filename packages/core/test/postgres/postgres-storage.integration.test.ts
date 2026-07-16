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
