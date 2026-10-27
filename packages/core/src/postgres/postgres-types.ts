import type { DatabaseRow, EntityColumnMap } from "../database-types.js";

export interface PostgresQueryResult<Row> {
  rows: Row[];
}

export interface PostgresQueryable {
  transaction?<T>(work: (client: PostgresQueryable) => Promise<T>): Promise<T>;
  query<Row = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[]
  ): Promise<PostgresQueryResult<Row>>;
}

export type ColumnMap<Entity> = EntityColumnMap<Entity>;

export type Row = DatabaseRow;
