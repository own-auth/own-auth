import type { PostgresQueryable } from "./postgres-types.js";
import { AuthError } from "../errors.js";

interface PostgresTransactionSource extends PostgresQueryable {
  connect?(): Promise<PostgresQueryable & { release(): void }>;
}

async function runTransaction<T>(client: PostgresQueryable, work: (client: PostgresQueryable) => Promise<T>): Promise<T> {
  await client.query("begin");
  try {
    const result = await work(client);
    await client.query("commit");
    return result;
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  }
}

export async function postgresTransaction<T>(
  db: PostgresTransactionSource, work: (client: PostgresQueryable) => Promise<T>
): Promise<T> {
  if (db.transaction) return db.transaction(work);
  if (!db.connect) throw new AuthError("user_erasure_unsupported", "Postgres erasure requires a transaction connection", 409);
  const client = await db.connect();
  if (!client || typeof client.query !== "function" || typeof client.release !== "function") {
    throw new AuthError("user_erasure_unsupported", "Pass a Postgres pool or a queryable with transaction support", 409);
  }
  try { return await runTransaction(client, work); }
  finally { client.release(); }
}

const connections = new WeakMap<PostgresQueryable, PostgresQueryable>();

/** Share serialization when several stores use the same checked out pool client. */
export function transactionQueryable(source: PostgresQueryable): PostgresQueryable {
  if (source.transaction || typeof (source as { release?: unknown }).release !== "function") return source;
  const existing = connections.get(source);
  if (existing) return existing;
  let pending: Promise<unknown> = Promise.resolve();
  const exclusive = <T>(work: () => Promise<T>): Promise<T> => {
    const result = pending.then(work);
    pending = result.catch(() => undefined);
    return result;
  };
  const queryable: PostgresQueryable = {
    query: (sql, params) => exclusive(() => source.query(sql, params)),
    transaction: (work) => exclusive(() => runTransaction(source, work))
  };
  connections.set(source, queryable);
  return queryable;
}
