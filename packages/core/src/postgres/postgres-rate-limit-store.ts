import type { RateLimitResult, RateLimitStore } from "../rate-limit.js";
import { dateValue, numberValue } from "../database-row.js";
import type { PostgresQueryable, Row } from "./postgres-types.js";

export class PostgresRateLimitStore implements RateLimitStore {
  constructor(private readonly db: PostgresQueryable) {}

  async hit(key: string, windowMs: number, limit: number): Promise<RateLimitResult> {
    const now = new Date();
    const resetAt = new Date(now.getTime() + windowMs);
    const result = await this.db.query<Row>(
      `insert into own_auth_rate_limits (key, count, reset_at)
       values ($1, 1, $2)
       on conflict (key) do update set
         count = case
           when own_auth_rate_limits.reset_at <= $3 then 1
           else own_auth_rate_limits.count + 1
         end,
         reset_at = case
           when own_auth_rate_limits.reset_at <= $3 then $2
           else own_auth_rate_limits.reset_at
         end
       returning count, reset_at`,
      [key, resetAt, now]
    );
    const row = result.rows[0];
    if (!row) {
      throw new Error("Postgres rate limit query returned no rows");
    }

    const count = numberValue(row.count);
    return {
      count,
      resetAt: dateValue(row.reset_at),
      allowed: count <= limit
    };
  }

  async reset(key: string): Promise<void> {
    await this.db.query("delete from own_auth_rate_limits where key = $1", [key]);
  }
}

export function createPostgresRateLimitStore(db: PostgresQueryable): PostgresRateLimitStore {
  return new PostgresRateLimitStore(db);
}
