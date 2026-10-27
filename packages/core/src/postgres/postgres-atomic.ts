import { databaseColumnEntries, type EntityColumnMap } from "../database-types.js";
import { toPostgresValue } from "./postgres-row.js";

export function addInsertCte<Entity>(
  ctes: string[],
  params: unknown[],
  name: string,
  table: string,
  columns: EntityColumnMap<Entity>,
  entity: Entity,
  dependency?: string,
  authorityExpiresAt?: Date
): string {
  const entries = databaseColumnEntries(columns, entity);
  const placeholders = entries.map(([key]) => {
    params.push(toPostgresValue(entity[key]));
    return `$${params.length}`;
  });
  const source = dependency
    ? `select ${placeholders.join(", ")} from ${dependency}`
    : `select ${placeholders.join(", ")}`;
  const authority = authorityExpiresAt
    ? (params.push(authorityExpiresAt), ` where clock_timestamp() < $${params.length}::timestamptz`) : "";
  ctes.push(
    `${name} as (insert into ${table} (${entries.map(([, column]) => column).join(", ")}) ` +
    `${source}${authority} returning id)`
  );
  return name;
}
