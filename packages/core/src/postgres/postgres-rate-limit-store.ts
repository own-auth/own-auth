import type { RateLimitResult, RateLimitStore } from "../rate-limit.js";
import { dateValue, numberValue } from "../database-row.js";
import type { PostgresQueryable, Row } from "./postgres-types.js";
import type { UserErasureSubject } from "../user-erasure.js";
import { erasureLookupIdentifiers } from "../user-erasure-subject.js";
import { transactionQueryable } from "./postgres-transactions.js";

export class PostgresRateLimitStore implements RateLimitStore {
  async eraseUser(subject: Readonly<UserErasureSubject>): Promise<void> {
    const identifiers = erasureLookupIdentifiers(subject);
    await this.db.query("delete from own_auth_rate_limits where user_id = $2 or (user_id is null and exists (select 1 from unnest($1::text[]) identifier where right(key, length(identifier) + 1) = ':' || identifier))", [identifiers, subject.userId]);
  }
  private readonly db: PostgresQueryable;
  constructor(db: PostgresQueryable) { this.db = transactionQueryable(db); }

  async hit(key: string, windowMs: number, limit: number, ownerUserId?: string): Promise<RateLimitResult> {
    const now = new Date();
    const resetAt = new Date(now.getTime() + windowMs);
    const result = await this.db.query<Row>(
      `insert into own_auth_rate_limits (key, count, reset_at, user_id)
       values ($1, 1, $2, $4)
       on conflict (key) do update set
         user_id = excluded.user_id,
         count = case
           when own_auth_rate_limits.reset_at <= $3 then 1
           else own_auth_rate_limits.count + 1
         end,
         reset_at = case
           when own_auth_rate_limits.reset_at <= $3 then $2
           else own_auth_rate_limits.reset_at
         end
       returning count, reset_at`,
      [key, resetAt, now, ownerUserId ?? null]
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
