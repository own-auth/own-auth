import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { coreMigrationFiles, coreMigrationVersions } from "../../src/core-migrations.js";
import { createPostgresTestDatabase, hasPostgresTestDatabase, type PostgresTestDatabase } from "./postgres-test-database.js";

const execute = promisify(execFile);
const cli = fileURLToPath(new URL("../../dist/cli.js", import.meta.url));
const describeWithDatabase = hasPostgresTestDatabase ? describe : describe.skip;
const migrate = (database: PostgresTestDatabase, args: string[] = []) => execute(
  process.execPath, [cli, "migrate", ...args],
  { env: { ...process.env, DATABASE_URL: database.connectionString } }
);
const history = (database: PostgresTestDatabase) => database.client.query(
  "select version, applied_at from own_auth_migrations order by version"
);

describeWithDatabase("compiled Postgres migration command", () => {
  it("creates a fresh database and skips completed migrations on the second run", async () => {
    const database = await createPostgresTestDatabase({ migrations: [] });
    try {
      expect((await migrate(database)).stdout).toContain("Applied Own Auth core tables.");
      const before = await history(database);
      expect(before.rows.map(row => row.version)).toEqual(coreMigrationVersions);
      await database.client.query(`insert into own_auth_users (id, email, created_at, updated_at)
        values ('retained', 'retained@example.test', now(), now())`);
      await migrate(database);
      expect((await history(database)).rows).toEqual(before.rows);
      expect((await database.client.query("select id from own_auth_users")).rows).toEqual([{ id: "retained" }]);
    } finally { await database.close(); }
  });

  it("upgrades an older database once without replaying its completed migrations", async () => {
    const database = await createPostgresTestDatabase({ migrations: coreMigrationFiles.slice(0, -1) });
    try {
      const before = await history(database);
      await migrate(database);
      const after = await history(database);
      expect(after.rows.slice(0, -1)).toEqual(before.rows);
      expect(after.rows.map(row => row.version)).toEqual(coreMigrationVersions);
      await migrate(database);
      expect((await history(database)).rows).toEqual(after.rows);
    } finally { await database.close(); }
  });

  it("serializes concurrent commands against the same fresh database", async () => {
    const database = await createPostgresTestDatabase({ migrations: [] });
    try {
      await Promise.all([migrate(database), migrate(database)]);
      expect((await history(database)).rows.map(row => row.version)).toEqual(coreMigrationVersions);
    } finally { await database.close(); }
  });

  it("rolls back an unsuccessful upgrade without recording or retaining partial changes", async () => {
    const database = await createPostgresTestDatabase({ migrations: coreMigrationFiles.slice(0, -1) });
    try {
      await database.client.query("alter table own_auth_webhook_deliveries add column send_started_at timestamptz");
      const before = await history(database);
      await expect(migrate(database)).rejects.toThrow('column "send_started_at"');
      expect((await history(database)).rows).toEqual(before.rows);
      expect((await database.client.query("select to_regclass('own_auth_user_erasures') as table_name")).rows)
        .toEqual([{ table_name: null }]);
    } finally { await database.close(); }
  });

  it("rejects a newer database before applying core SQL", async () => {
    const database = await createPostgresTestDatabase();
    try {
      await database.client.query("insert into own_auth_migrations (version) values ('999_future')");
      const before = await history(database);
      await expect(migrate(database)).rejects.toThrow("Database is newer than this own-auth version");
      expect((await history(database)).rows).toEqual(before.rows);
    } finally { await database.close(); }
  });

  it("continues to apply missing plugin migrations after completed core migrations", async () => {
    const database = await createPostgresTestDatabase();
    const directory = await mkdtemp(join(tmpdir(), "own-auth-cli-plugin-"));
    try {
      const config = join(directory, "own-auth.config.mjs");
      await writeFile(config, `export default { plugins: [{ id: "example", version: "1.0.0", migrations: [{
        id: "001_records", sql: { postgres: "create table plugin_records (id text primary key)" }
      }] }] };`);
      expect((await migrate(database, ["--config", config])).stdout).toContain("Applied 1 plugin migration.");
      expect((await migrate(database, ["--config", config])).stdout).toContain("Applied 0 plugin migrations.");
      expect((await database.client.query("select id from own_auth_plugin_migrations")).rows)
        .toEqual([{ id: "example:001_records" }]);
    } finally {
      await rm(directory, { recursive: true, force: true });
      await database.close();
    }
  });
});
