import { expectDatabaseValue } from "../database-row.js";
import {
  databaseColumnEntries,
  type DatabaseRow,
  type EntityColumnMap
} from "../database-types.js";
import type { D1DatabaseLike, D1PreparedStatementLike } from "./d1-types.js";
import { toD1Value } from "./d1-values.js";

export class D1StorageBase {
  constructor(protected readonly db: D1DatabaseLike) {}

  protected async insertOne<Entity extends { id: string }>(
    table: string,
    columns: EntityColumnMap<Entity>,
    entity: Entity,
    returning: string,
    authorityExpiresAt?: Date
  ): Promise<DatabaseRow> {
    const statement = this.insertStatement(table, columns, entity, returning, authorityExpiresAt);
    return expectDatabaseValue(
      await statement.first<DatabaseRow>(),
      `D1 insert into ${table}`
    );
  }

  protected insertStatement<Entity extends { id: string }>(
    table: string,
    columns: EntityColumnMap<Entity>,
    entity: Entity,
    returning: string,
    authorityExpiresAt?: Date
  ): D1PreparedStatementLike {
    const entries = databaseColumnEntries(columns, entity);
    return this.prepare(
      `insert into ${table} (${entries.map(([, column]) => column).join(", ")}) ` +
      (authorityExpiresAt
        ? `select ${placeholders(entries.length)} where (julianday('now') - 2440587.5) * 86400000 < ?${entries.length + 1}`
        : `values (${placeholders(entries.length)})`) + ` returning ${returning}`,
      [...entries.map(([key]) => entity[key]), ...(authorityExpiresAt ? [authorityExpiresAt] : [])]
    );
  }

  protected async updateOne<Entity extends { id: string }>(
    table: string,
    columns: EntityColumnMap<Entity>,
    id: string,
    patch: Partial<Entity>,
    returning: string
  ): Promise<DatabaseRow | null> {
    const entries = databaseColumnEntries(columns, patch).filter(([key]) => key !== "id");
    if (entries.length === 0) {
      return this.selectOne(`${returning} from ${table} where id = ?1`, [id]);
    }
    const values: unknown[] = entries.map(([key]) => patch[key]);
    values.push(id);
    const assignments = entries.map(([, column], index) => `${column} = ?${index + 1}`);
    return this.prepare(
      `update ${table} set ${assignments.join(", ")} where id = ?${values.length} returning ${returning}`,
      values
    ).first<DatabaseRow>();
  }

  protected async selectOne(
    sql: string,
    values: readonly unknown[] = []
  ): Promise<DatabaseRow | null> {
    return this.prepare(`select ${sql}`, values).first<DatabaseRow>();
  }

  protected async selectMany(
    sql: string,
    values: readonly unknown[] = []
  ): Promise<DatabaseRow[]> {
    const result = await this.prepare(`select ${sql}`, values).all<DatabaseRow>();
    return result.results ?? [];
  }

  protected prepare(sql: string, values: readonly unknown[] = []): D1PreparedStatementLike {
    const statement = this.db.prepare(sql);
    return values.length > 0 ? statement.bind(...values.map(toD1Value)) : statement;
  }
}

export function placeholders(count: number, offset = 0): string {
  return Array.from({ length: count }, (_, index) => `?${offset + index + 1}`).join(", ");
}
