import { databaseColumnEntries } from "../database-types.js";
import { expectOne, toPostgresValue } from "./postgres-row.js";
import type { ColumnMap, PostgresQueryable, Row } from "./postgres-types.js";
import { transactionQueryable } from "./postgres-transactions.js";

export class PostgresStorageBase {
  protected readonly db: PostgresQueryable;
  constructor(db: PostgresQueryable) { this.db = transactionQueryable(db); }

  protected async insertOne<Entity extends { id: string }>(
    table: string,
    columns: ColumnMap<Entity>,
    entity: Entity,
    returning: string,
    authorityExpiresAt?: Date
  ): Promise<Row> {
    const entries = databaseColumnEntries(columns, entity);
    const columnNames = entries.map(([, column]) => column);
    const params = entries.map(([key]) => toPostgresValue(entity[key]));
    const placeholders = params.map((_, index) => `$${index + 1}`);
    const source = authorityExpiresAt
      ? (params.push(authorityExpiresAt), `select ${placeholders.join(", ")} where clock_timestamp() < $${params.length}::timestamptz`)
      : `values (${placeholders.join(", ")})`;
    const result = await this.db.query<Row>(
      `insert into ${table} (${columnNames.join(", ")}) ${source} returning ${returning}`,
      params
    );
    return expectOne(result.rows);
  }

  protected async updateOne<Entity extends { id: string }>(
    table: string,
    columns: ColumnMap<Entity>,
    id: string,
    patch: Partial<Entity>,
    returning: string
  ): Promise<Row | null> {
    const entries = databaseColumnEntries(columns, patch).filter(([key]) => key !== "id");
    if (entries.length === 0) {
      return this.selectOne(`${returning} from ${table} where id = $1`, [id]);
    }

    const params = entries.map(([key]) => toPostgresValue(patch[key]));
    params.push(id);
    const assignments = entries.map(([, column], index) => `${column} = $${index + 1}`);
    const result = await this.db.query<Row>(
      `update ${table} set ${assignments.join(", ")} where id = $${params.length} returning ${returning}`,
      params
    );
    return result.rows[0] ?? null;
  }

  protected async selectOne(sql: string, params: readonly unknown[]): Promise<Row | null> {
    const result = await this.db.query<Row>(`select ${sql}`, params);
    return result.rows[0] ?? null;
  }

  protected async selectMany(sql: string, params: readonly unknown[]): Promise<Row[]> {
    const result = await this.db.query<Row>(`select ${sql}`, params);
    return result.rows;
  }
}
