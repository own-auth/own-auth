import { SqlUserErasureStorage } from "../sql-user-erasure-storage.js";
import { erasureUserTables, prepareErasureSql, type ErasureSqlDatabase } from "../user-erasure-sql.js";
import type { PostgresQueryable } from "./postgres-types.js";
import { postgresTransaction } from "./postgres-transactions.js";

function database(db: PostgresQueryable): ErasureSqlDatabase {
  return {
    dialect: "postgres",
    async read(sql, values) { return (await db.query(sql, values)).rows; },
    async atomic(statements) {
      await postgresTransaction(db, async (client) => {
        for (const statement of statements) await client.query(statement.sql, statement.values);
      });
    }
  };
}

export class PostgresUserErasureStorage extends SqlUserErasureStorage {
  constructor(db: PostgresQueryable) {
    super(database(db), async (input) => postgresTransaction(db, async (client) => {
      // All reads below occur after competing writes have committed.
      const tables = ["users", ...erasureUserTables, "organisations", "invitations",
        "audit_events", "webhook_events", "webhook_deliveries", "cloud_outbox", "cloud_commands",
        "cloud_entity_versions", "user_erasures", "rate_limits", "oauth_credentials"].map((name) => `own_auth_${name}`);
      await client.query(`lock table ${tables.join(", ")} in share row exclusive mode`);
      const statements = await prepareErasureSql(database(client), input);
      for (const statement of statements) await client.query(statement.sql, statement.values);
    }));
  }
}
