import type { AuthToken, SmsOtp, TokenType } from "../types.js";
import { currentPasswordResetTokenSql } from "../password-reset-sql.js";
import { mapSmsOtp, mapToken } from "../database-mappers.js";
import { smsOtpReturning, tokenReturning } from "../database-schema.js";
import type { PostgresQueryable, Row } from "./postgres-types.js";

export async function atomicConsumeToken(
  db: PostgresQueryable,
  tokenHash: string,
  type: TokenType,
  consumedAt: Date
): Promise<AuthToken | null> {
  const result = await db.query<Row>(
    `update own_auth_tokens
     set used_at = $3
     where token_hash = $1
       and type = $2
       and used_at is null
       and expires_at > $3
       and ${currentPasswordResetTokenSql("own_auth_tokens")}
     returning ${tokenReturning}`,
    [tokenHash, type, consumedAt]
  );
  const row = result.rows[0];
  return row ? mapToken(row) : null;
}

export async function atomicIncrementSmsOtpAttempts(
  db: PostgresQueryable,
  id: string,
  attemptedAt: Date
): Promise<SmsOtp | null> {
  const result = await db.query<Row>(
    `update own_auth_sms_otps
     set attempts = attempts + 1
     where id = $1
       and consumed_at is null
       and expires_at > $2
       and attempts < max_attempts
     returning ${smsOtpReturning}`,
    [id, attemptedAt]
  );
  const row = result.rows[0];
  return row ? mapSmsOtp(row) : null;
}

export async function atomicConsumeSmsOtp(
  db: PostgresQueryable,
  id: string,
  consumedAt: Date
): Promise<SmsOtp | null> {
  const result = await db.query<Row>(
    `update own_auth_sms_otps
     set consumed_at = $2,
         attempts = attempts + 1
     where id = $1
       and consumed_at is null
       and expires_at > $2
       and attempts < max_attempts
     returning ${smsOtpReturning}`,
    [id, consumedAt]
  );
  const row = result.rows[0];
  return row ? mapSmsOtp(row) : null;
}
