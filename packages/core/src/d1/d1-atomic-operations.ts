import type { DatabaseRow } from "../database-types.js";
import { currentPasswordResetTokenSql } from "../password-reset-sql.js";
import { mapSmsOtp, mapToken } from "../database-mappers.js";
import { smsOtpReturning, tokenReturning } from "../database-schema.js";
import type { AuthToken, SmsOtp, TokenType } from "../types.js";
import type { D1DatabaseLike } from "./d1-types.js";

export async function atomicConsumeD1Token(
  db: D1DatabaseLike,
  tokenHash: string,
  type: TokenType,
  consumedAt: Date
): Promise<AuthToken | null> {
  const row = await db.prepare(
    `update own_auth_tokens set used_at = ?3
     where token_hash = ?1 and type = ?2 and used_at is null and expires_at > ?3
       and ${currentPasswordResetTokenSql("own_auth_tokens")}
     returning ${tokenReturning}`
  ).bind(tokenHash, type, consumedAt.getTime()).first<DatabaseRow>();
  return row ? mapToken(row) : null;
}

export async function atomicIncrementD1SmsOtpAttempts(
  db: D1DatabaseLike,
  id: string,
  attemptedAt: Date
): Promise<SmsOtp | null> {
  const row = await db.prepare(
    `update own_auth_sms_otps set attempts = attempts + 1
     where id = ?1 and consumed_at is null and expires_at > ?2 and attempts < max_attempts
     returning ${smsOtpReturning}`
  ).bind(id, attemptedAt.getTime()).first<DatabaseRow>();
  return row ? mapSmsOtp(row) : null;
}

export async function atomicConsumeD1SmsOtp(
  db: D1DatabaseLike,
  id: string,
  consumedAt: Date
): Promise<SmsOtp | null> {
  const row = await db.prepare(
    `update own_auth_sms_otps
     set consumed_at = ?2, attempts = attempts + 1
     where id = ?1 and consumed_at is null and expires_at > ?2 and attempts < max_attempts
     returning ${smsOtpReturning}`
  ).bind(id, consumedAt.getTime()).first<DatabaseRow>();
  return row ? mapSmsOtp(row) : null;
}
