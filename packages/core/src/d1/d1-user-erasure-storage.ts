import { SqlUserErasureStorage } from "../sql-user-erasure-storage.js";
import type { D1DatabaseLike } from "./d1-types.js";
import { toD1Value } from "./d1-values.js";

export class D1UserErasureStorage extends SqlUserErasureStorage {
  constructor(db: D1DatabaseLike) {
    super({
      dialect: "d1",
      async read(sql, values = []) {
        const result = await db.prepare(sql).bind(...values.map(toD1Value)).all<Record<string, unknown>>();
        return result.results ?? [];
      },
      async atomic(statements) {
        await db.batch(statements.map(({ sql, values }) => db.prepare(sql).bind(...values.map(toD1Value))));
      }
    });
  }
}
