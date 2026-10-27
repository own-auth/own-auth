import { dateValue, numberValue } from "../database-row.js";
import type { DatabaseRow } from "../database-types.js";
import type { RateLimitResult, RateLimitStore } from "../rate-limit.js";
import type { D1DatabaseLike } from "./d1-types.js";
import type { UserErasureSubject } from "../user-erasure.js";
import { erasureLookupIdentifiers } from "../user-erasure-subject.js";

export class D1RateLimitStore implements RateLimitStore {
  async eraseUser(subject: Readonly<UserErasureSubject>): Promise<void> {
    const identifiers = erasureLookupIdentifiers(subject);
    await this.db.prepare("delete from own_auth_rate_limits where user_id = ?2 or (user_id is null and exists (select 1 from json_each(?1) identifier where substr(key, -length(identifier.value) - 1) = ':' || identifier.value))")
      .bind(JSON.stringify(identifiers), subject.userId).run();
  }
  constructor(private readonly db: D1DatabaseLike) {}

  async hit(key: string, windowMs: number, limit: number, ownerUserId?: string): Promise<RateLimitResult> {
    const now = Date.now();
    const resetAt = now + windowMs;
    const row = await this.db.prepare(
      `insert into own_auth_rate_limits (key, count, reset_at, user_id)
       values (?1, 1, ?2, ?4)
       on conflict (key) do update set
         user_id = excluded.user_id,
         count = case
           when own_auth_rate_limits.reset_at <= ?3 then 1
           else own_auth_rate_limits.count + 1
         end,
         reset_at = case
           when own_auth_rate_limits.reset_at <= ?3 then ?2
           else own_auth_rate_limits.reset_at
         end
       returning count, reset_at`
    ).bind(key, resetAt, now, ownerUserId ?? null).first<DatabaseRow>();
    if (!row) {
      throw new Error("D1 rate limit query returned no rows");
    }
    const count = numberValue(row.count);
    return {
      count,
      resetAt: dateValue(row.reset_at),
      allowed: count <= limit
    };
  }

  async reset(key: string): Promise<void> {
    await this.db.prepare("delete from own_auth_rate_limits where key = ?1").bind(key).run();
  }
}

export function createD1RateLimitStore(database: D1DatabaseLike): D1RateLimitStore {
  return new D1RateLimitStore(database);
}
