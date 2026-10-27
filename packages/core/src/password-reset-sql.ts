import { databaseColumnEntries } from "./database-types.js";
import { tokenColumns, tokenReturning, userReturning } from "./database-schema.js";
import type { AuthToken } from "./types.js";
import type { AtomicPasswordUpdateInput } from "./auth-storage-atomic.js";

/** Used tokens remain observable as used. Unused older reset authority is rejected. */
export function currentPasswordResetTokenSql(token: string): string {
  return `(${token}.type <> 'password_reset' or ${token}.used_at is not null or exists (
    select 1 from own_auth_users reset_owner where reset_owner.id = ${token}.user_id
      and reset_owner.password_reset_version = ${token}.password_reset_version
  ))`;
}

export function insertAuthTokenSql(token: AuthToken, bind: (value: unknown) => string): string {
  const entries = databaseColumnEntries(tokenColumns, token)
    .filter(([key]) => key !== "passwordResetVersion");
  const values = entries.map(([key]) => bind(token[key]));
  const version = token.type === "password_reset"
    ? `coalesce((select password_reset_version from own_auth_users where id = ${bind(token.userId)}), 0)`
    : "0";
  return `insert into own_auth_tokens (${entries.map(([, column]) => column).join(", ")}, password_reset_version)
    values (${values.join(", ")}, ${version}) returning ${tokenReturning}`;
}

export function updatePasswordSql(input: AtomicPasswordUpdateInput, bind: (value: unknown) => string): string {
  const userId = bind(input.userId);
  const expected = bind(input.expectedPasswordHash);
  const password = bind(input.passwordHash);
  const at = bind(input.updatedAt);
  return `update own_auth_users set password_hash = ${password}, updated_at = ${at},
    password_reset_version = password_reset_version + ${input.purpose === "replacement" ? "1" : "0"}
    where id = ${userId} and disabled_at is null
      and (password_hash = ${expected} or (password_hash is null and ${expected} is null))
    returning ${userReturning}`;
}
