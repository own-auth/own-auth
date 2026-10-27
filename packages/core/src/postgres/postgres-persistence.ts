import { createAuthClosedError } from "../errors.js";
import { PostgresRateLimitStore } from "./postgres-rate-limit-store.js";
import { PostgresAuthStorage } from "./postgres-storage.js";
import type { PostgresQueryable, PostgresQueryResult } from "./postgres-types.js";
import { postgresTransaction } from "./postgres-transactions.js";

interface OwnedPostgresPool extends PostgresQueryable {
  end(): Promise<void>;
}

type PostgresPoolLoader = (connectionString: string) => Promise<OwnedPostgresPool>;

type PersistenceState = "open" | "closing" | "closed";

class LazyPostgresQueryable implements PostgresQueryable {
  private state: PersistenceState = "open";
  private poolPromise: Promise<OwnedPostgresPool> | null = null;
  private closePromise: Promise<void> | null = null;

  constructor(
    private readonly connectionString: string,
    private readonly loadPool: PostgresPoolLoader = loadPostgresPool
  ) {}

  async query<Row = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[]
  ): Promise<PostgresQueryResult<Row>> {
    this.assertOpen();
    const pool = await this.getPool();
    this.assertOpen();
    return pool.query<Row>(sql, params);
  }

  async transaction<T>(work: (client: PostgresQueryable) => Promise<T>): Promise<T> {
    this.assertOpen();
    const pool = await this.getPool();
    this.assertOpen();
    if (!pool.transaction) throw new Error("Postgres pool does not provide transaction support");
    return pool.transaction(work);
  }

  close(): Promise<void> {
    if (this.closePromise) {
      return this.closePromise;
    }

    this.state = "closing";
    const poolPromise = this.poolPromise;
    this.closePromise = (async () => {
      try {
        if (poolPromise) {
          const pool = await poolPromise;
          await pool.end();
        }
      } finally {
        this.state = "closed";
      }
    })();
    return this.closePromise;
  }

  private getPool(): Promise<OwnedPostgresPool> {
    this.poolPromise ??= this.loadPool(this.connectionString);
    return this.poolPromise;
  }

  private assertOpen(): void {
    if (this.state !== "open") {
      throw createAuthClosedError();
    }
  }
}

export function createPostgresPersistence(
  connectionString: string,
  loadPool: PostgresPoolLoader = loadPostgresPool
): {
  storage: PostgresAuthStorage;
  rateLimitStore: PostgresRateLimitStore;
  close(): Promise<void>;
} {
  const queryable = new LazyPostgresQueryable(
    validateDatabaseUrl(connectionString),
    loadPool
  );
  return {
    storage: new PostgresAuthStorage(queryable),
    rateLimitStore: new PostgresRateLimitStore(queryable),
    close: () => queryable.close()
  };
}

function validateDatabaseUrl(connectionString: string): string {
  const value = connectionString.trim();

  try {
    const url = new URL(value);
    if (!url.hostname || (url.protocol !== "postgres:" && url.protocol !== "postgresql:")) {
      throw new Error("unsupported database URL");
    }
  } catch {
    throw new Error(
      "DATABASE_URL must be a valid postgres:// or postgresql:// connection URL."
    );
  }

  return value;
}

async function loadPostgresPool(connectionString: string): Promise<OwnedPostgresPool> {
  const { Pool } = await import("pg");
  const pool = new Pool({ connectionString });

  try {
    const client = await pool.connect();
    client.release();
  } catch (error) {
    await pool.end().catch(() => undefined);
    throw error;
  }

  return {
    transaction: (work) => postgresTransaction(pool as PostgresQueryable, work),
    async query<Row = Record<string, unknown>>(
      sql: string,
      params?: readonly unknown[]
    ): Promise<PostgresQueryResult<Row>> {
      const result = await pool.query(sql, params ? [...params] : undefined);
      return { rows: result.rows as Row[] };
    },
    async end(): Promise<void> {
      await pool.end();
    }
  };
}
