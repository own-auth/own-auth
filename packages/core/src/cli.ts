#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import {
  type CoreMigration,
  type DatabaseDialect,
  coreMigrationVersions,
  readCoreMigrationSql,
  readCoreMigrations
} from "./core-migrations.js";
import { loadOwnAuthConfig } from "./plugin-config.js";
import {
  applyPluginMigrations,
  formatChecksumMismatch,
  inspectPluginMigrations,
  resolvePluginMigrations,
  type ResolvedPluginMigration
} from "./plugin-migrations.js";
const { Pool } = pg;
interface CliIo {
  stdout(message: string): void;
  stderr(message: string): void;
}

export interface CliDatabase {
  query<Row = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[]
  ): Promise<{ rows: Row[] }>;
  transaction?<Result>(work: (database: CliDatabase) => Promise<Result>): Promise<Result>;
  end(): Promise<void>;
}

export interface CliDependencies {
  createDatabase(databaseUrl: string): CliDatabase;
}

interface ParsedArgs {
  command: "generate" | "migrate" | "status" | "help";
  databaseUrl?: string;
  out?: string;
  outDir?: string;
  config?: string;
  dialect: DatabaseDialect;
  version: boolean;
}
const defaultIo: CliIo = {
  stdout: (message) => process.stdout.write(message),
  stderr: (message) => process.stderr.write(message)
};
const defaultDependencies: CliDependencies = {
  createDatabase(databaseUrl) {
    const pool = new Pool({ connectionString: databaseUrl });
    return {
      async query<Row>(sql: string, params?: readonly unknown[]) {
        const result = await pool.query(sql, params ? [...params] : undefined);
        return { rows: result.rows as Row[] };
      },
      async transaction<Result>(work: (database: CliDatabase) => Promise<Result>) {
        const client = await pool.connect();
        const transaction: CliDatabase = {
          async query<Row>(sql: string, params?: readonly unknown[]) {
            const result = await client.query(sql, params ? [...params] : undefined);
            return { rows: result.rows as Row[] };
          },
          async end() {},
          async transaction<NestedResult>(nested: (database: CliDatabase) => Promise<NestedResult>) {
            return nested(transaction);
          }
        };
        try {
          await client.query("begin");
          const result = await work(transaction);
          await client.query("commit");
          return result;
        } catch (error) {
          try {
            await client.query("rollback");
          } catch {
            // Keep the migration error when rollback also fails.
          }
          throw error;
        } finally {
          client.release();
        }
      },
      async end() {
        await pool.end();
      }
    };
  }
};
export async function runCli(
  argv = process.argv.slice(2),
  env: NodeJS.ProcessEnv = process.env,
  io: CliIo = defaultIo,
  dependencies: CliDependencies = defaultDependencies
): Promise<number> {
  try {
    const args = parseArgs(argv);
    if (args.version) {
      io.stdout(`${await readPackageVersion()}\n`);
      return 0;
    }
    if (args.command === "help") {
      io.stdout(helpText());
      return 0;
    }
    const loadedConfig = await loadOwnAuthConfig(args.config);
    const pluginMigrations = resolvePluginMigrations(
      loadedConfig.config.plugins ?? [],
      args.dialect
    );
    if (args.command === "generate") {
      if (args.dialect === "d1") {
        const outDir = resolve(args.outDir ?? "migrations");
        const written = await writeD1Migrations(
          outDir,
          await readCoreMigrations("d1"),
          pluginMigrations
        );
        io.stdout(
          written > 0
            ? `Wrote ${written} Own Auth D1 migration${written === 1 ? "" : "s"} to ${outDir}\n`
            : `Own Auth D1 migrations are current in ${outDir}\n`
        );
        return 0;
      }
      const sql = `${await readCoreMigrationSql()}${renderPluginMigrationSql(pluginMigrations)}`;
      if (args.out) {
        const outPath = resolve(args.out);
        await mkdir(dirname(outPath), { recursive: true });
        await writeFile(outPath, sql, "utf8");
        io.stdout(`Wrote Own Auth migration to ${outPath}\n`);
      } else {
        io.stdout(withTrailingNewline(sql));
      }

      return 0;
    }
    const databaseUrl = args.databaseUrl ?? env.DATABASE_URL;
    if (!databaseUrl) {
      throw new Error("DATABASE_URL is required. Set DATABASE_URL or pass --database-url.");
    }

    if (args.command === "migrate") {
      const appliedPlugins = await migrate(
        databaseUrl,
        await readCoreMigrations(),
        pluginMigrations,
        dependencies
      );
      io.stdout("Applied Own Auth core tables.\n");
      if (pluginMigrations.length > 0) {
        io.stdout(`Applied ${appliedPlugins} plugin migration${appliedPlugins === 1 ? "" : "s"}.\n`);
      }
      return 0;
    }

    return await printStatus(databaseUrl, pluginMigrations, io, dependencies) ? 0 : 1;
  } catch (error) {
    io.stderr(`Error: ${error instanceof Error ? error.message : String(error)}\n\n`);
    io.stderr(helpText());
    return 1;
  }
}

function parseArgs(argv: string[]): ParsedArgs {
  if (argv.length === 0) {
    return { command: "help", dialect: "postgres", version: false };
  }
  const [command, ...rest] = argv;
  if (command === "--help" || command === "-h" || command === "help") {
    return { command: "help", dialect: "postgres", version: false };
  }
  if (command === "--version" || command === "-v") {
    return { command: "help", dialect: "postgres", version: true };
  }
  if (command !== "generate" && command !== "migrate" && command !== "status") {
    throw new Error(`Unknown command: ${command}`);
  }
  const parsed: ParsedArgs = { command, dialect: "postgres", version: false };
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--help" || arg === "-h") {
      return { command: "help", dialect: "postgres", version: false };
    }
    if ((arg === "--out" || arg === "--output") && command === "generate") {
      parsed.out = requireValue(rest, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--out-dir" && command === "generate") {
      parsed.outDir = requireValue(rest, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--dialect" && command === "generate") {
      const dialect = requireValue(rest, index, arg);
      if (dialect !== "postgres" && dialect !== "d1") {
        throw new Error("--dialect must be postgres or d1");
      }
      parsed.dialect = dialect;
      index += 1;
      continue;
    }
    if (arg === "--database-url" && (command === "migrate" || command === "status")) {
      parsed.databaseUrl = requireValue(rest, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--config") {
      parsed.config = requireValue(rest, index, arg);
      index += 1;
      continue;
    }
    throw new Error(`Unknown option for ${command}: ${arg}`);
  }
  if (parsed.dialect === "d1" && parsed.out) {
    throw new Error("D1 generation uses --out-dir, not --out");
  }
  if (parsed.dialect === "postgres" && parsed.outDir) {
    throw new Error("Postgres generation uses --out, not --out-dir");
  }
  return parsed;
}

function requireValue(args: string[], index: number, name: string): string {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

async function migrate(
  databaseUrl: string,
  migrations: readonly CoreMigration[],
  pluginMigrations: readonly ResolvedPluginMigration[],
  dependencies: CliDependencies
): Promise<number> {
  const database = dependencies.createDatabase(databaseUrl);
  try {
    if (!database.transaction) {
      throw new Error("Core migrations require a database transaction implementation");
    }
    await database.transaction(async (transaction) => {
      await transaction.query("select pg_advisory_xact_lock(hashtext(current_schema()), hashtext('own_auth_migrations'))");
      const table = await transaction.query<{ tableName: string | null }>(
        "select to_regclass('own_auth_migrations')::text as \"tableName\""
      );
      const result = table.rows[0]?.tableName
        ? await transaction.query<{ version: string }>("select version from own_auth_migrations")
        : { rows: [] };
      const applied = new Set(result.rows.map(({ version }) => version));
      if ([...applied].some((version) => !coreMigrationVersions.includes(version))) {
        throw new Error("Database is newer than this own-auth version");
      }
      for (const migration of migrations) {
        if (!applied.has(migration.file.replace(/\.sql$/, ""))) {
          await transaction.query(migration.sql);
        }
      }
    });
    return await applyPluginMigrations(database, pluginMigrations);
  } finally {
    await database.end();
  }
}

async function printStatus(
  databaseUrl: string,
  pluginMigrations: readonly ResolvedPluginMigration[],
  io: CliIo,
  dependencies: CliDependencies
): Promise<boolean> {
  const database = dependencies.createDatabase(databaseUrl);

  try {
    const table = await database.query<{ tableName: string | null }>(
      "select to_regclass('own_auth_migrations')::text as \"tableName\""
    );
    io.stdout("Database: connected\n");

    if (!table.rows[0]?.tableName) {
      io.stdout("Migration version: none\n");
      io.stdout("Status: migrations required\n");
      return false;
    }

    const result = await database.query<{ version: string }>(
      "select version from own_auth_migrations order by applied_at asc, version asc"
    );
    const appliedVersions = result.rows.map((row) => row.version);
    const applied = new Set(appliedVersions);
    const latestApplied = appliedVersions.at(-1) ?? "none";
    const missing = coreMigrationVersions.filter((version) => !applied.has(version));
    const unknown = appliedVersions.filter((version) => !coreMigrationVersions.includes(version));

    io.stdout(`Migration version: ${latestApplied}\n`);

    if (unknown.length > 0) {
      io.stdout("Status: database is newer than this own-auth version\n");
      return false;
    }

    if (missing.length > 0) {
      io.stdout("Status: migrations required\n");
      return false;
    }

    const pluginStatus = await inspectPluginMigrations(database, pluginMigrations);
    if (pluginStatus.checksumMismatches.length > 0) {
      io.stdout(`Status: ${formatChecksumMismatch(pluginStatus.checksumMismatches[0]!)}\n`);
      return false;
    }
    if (pluginStatus.missing.length > 0) {
      io.stdout(`Plugin migrations required: ${pluginStatus.missing.map(({ id }) => id).join(", ")}\n`);
      io.stdout("Status: migrations required\n");
      return false;
    }

    io.stdout("Status: current\n");
    return true;
  } finally {
    await database.end();
  }
}

async function readPackageVersion(): Promise<string> {
  const packageJson = await readFile(new URL("../package.json", import.meta.url), "utf8");
  const parsed = JSON.parse(packageJson) as { version?: string };
  return parsed.version ?? "unknown";
}

function helpText(): string {
  return `Own Auth CLI

Usage:
  own-auth generate [--dialect postgres] [--out <file>] [--config <file>]
  own-auth generate --dialect d1 [--out-dir <directory>] [--config <file>]
  own-auth migrate [--database-url <url>] [--config <file>]
  own-auth status [--database-url <url>] [--config <file>]

Commands:
  generate  Generate Postgres SQL or versioned D1 migration files.
  migrate   Apply the SQL migration to DATABASE_URL.
  status    Check the database connection and migration version.

Options:
  --out, --output       Write generated SQL to a file.
  --out-dir             Write D1 migrations to a directory (default: ./migrations).
  --dialect             Generate migrations for postgres or d1.
  --database-url        Use this database URL instead of DATABASE_URL.
  --config              Load plugins from an Own Auth config file.
  --help                Show this help.
  --version             Show the package version.
`;
}

function renderPluginMigrationSql(migrations: readonly ResolvedPluginMigration[]): string {
  if (migrations.length === 0) return "";
  return migrations.map((migration) => `
-- Plugin migration ${migration.id}
begin;
${migration.sql.trim()}
${renderPluginMigrationRecord(migration)}
commit;
`).join("");
}

async function writeD1Migrations(
  outDir: string,
  coreMigrations: readonly CoreMigration[],
  pluginMigrations: readonly ResolvedPluginMigration[]
): Promise<number> {
  await mkdir(outDir, { recursive: true });
  const files = [
    ...coreMigrations.map(({ file, sql }) => ({
      name: file.replace(/^(\d+)_/, "$1_own_auth_"),
      contents: sql
    })),
    ...pluginMigrations.map((migration) => ({
      name: `900000_own_auth_plugin_${migration.id.replace(":", "__")}.sql`,
      contents: renderD1PluginMigrationSql(migration)
    }))
  ];
  let written = 0;
  for (const file of files) {
    const path = resolve(outDir, file.name);
    const contents = withTrailingNewline(file.contents);
    const existing = await readOptionalFile(path);
    if (existing === contents) continue;
    if (existing !== null) {
      throw new Error(`Generated D1 migration was modified: ${path}`);
    }
    await writeFile(path, contents, "utf8");
    written += 1;
  }
  return written;
}

function renderD1PluginMigrationSql(migration: ResolvedPluginMigration): string {
  return `-- Own Auth plugin migration ${migration.id}
${migration.sql.trim()}
${renderPluginMigrationRecord(migration)}
`;
}

function renderPluginMigrationRecord(migration: ResolvedPluginMigration): string {
  return `insert into own_auth_plugin_migrations (id, plugin_id, plugin_version, checksum)
values (${sqlLiteral(migration.id)}, ${sqlLiteral(migration.pluginId)}, ${sqlLiteral(migration.pluginVersion)}, ${sqlLiteral(migration.checksum)})
on conflict (id) do nothing;`;
}

function withTrailingNewline(value: string): string {
  return value.endsWith("\n") ? value : `${value}\n`;
}

async function readOptionalFile(path: string): Promise<string | null> {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return null;
    throw error;
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

function sqlLiteral(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  if (!entry) {
    return false;
  }
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(entry);
  } catch {
    return fileURLToPath(import.meta.url) === resolve(entry);
  }
}

if (isDirectRun()) {
  void runCli().then((exitCode) => {
    process.exitCode = exitCode;
  });
}
