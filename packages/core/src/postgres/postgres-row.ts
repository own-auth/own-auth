import { expectDatabaseRow } from "../database-row.js";
import type { Row } from "./postgres-types.js";

export function expectOne(rows: Row[]): Row {
  return expectDatabaseRow(rows, "Postgres query");
}

export function toPostgresValue(value: unknown): unknown {
  if (ArrayBuffer.isView(value)) {
    return value;
  }
  if (value && typeof value === "object" && !(value instanceof Date) && !Array.isArray(value)) {
    return JSON.stringify(value);
  }

  return value;
}
