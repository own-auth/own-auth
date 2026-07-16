import type {
  RotateAuthorizationRefreshTokenInput,
  RotateAuthorizationRefreshTokenResult
} from "../authorization-server-storage.js";
import {
  authorizationAccessTokenValues,
  authorizationRefreshTokenValues
} from "../authorization-server-token-values.js";
import { toPostgresValue } from "./postgres-row.js";
import type { PostgresQueryable } from "./postgres-types.js";

export async function rotatePostgresAuthorizationRefreshToken(
  db: PostgresQueryable,
  input: RotateAuthorizationRefreshTokenInput
): Promise<RotateAuthorizationRefreshTokenResult> {
  const params = [
    input.tokenHash,
    input.authorizationClientId,
    input.rotatedAt,
    input.replacementRefreshToken.id,
    ...authorizationRefreshTokenValues(input.replacementRefreshToken),
    ...authorizationAccessTokenValues(input.accessToken)
  ];
  const result = await db.query<{ status: RotateAuthorizationRefreshTokenResult }>(
    `with target as materialized (
       select token.*
       from own_auth_authorization_refresh_tokens token
       join own_auth_authorization_grants grant_record on grant_record.id = token.grant_id
       where token.token_hash = $1 and token.authorization_client_id = $2
       for update of token
     ), reused_grant as (
       update own_auth_authorization_grants
       set revoked_at = $3, updated_at = $3
       where id in (
         select grant_id from target
         where revoked_at is null and expires_at > $3
           and (consumed_at is not null or replaced_by_token_id is not null)
       )
       and revoked_at is null
       returning id
     ), consumed as (
       update own_auth_authorization_refresh_tokens token
       set consumed_at = $3, replaced_by_token_id = $4
       where token.id in (
         select target.id from target
         join own_auth_authorization_grants grant_record
           on grant_record.id = target.grant_id
         where target.revoked_at is null and target.expires_at > $3
           and target.consumed_at is null and target.replaced_by_token_id is null
           and grant_record.revoked_at is null
       )
       returning token.grant_id
     ), inserted_refresh as (
       insert into own_auth_authorization_refresh_tokens
         (id, token_hash, prefix, grant_id, authorization_client_id, user_id,
          scopes, generation, replaced_by_token_id, expires_at, consumed_at,
          revoked_at, created_at)
       select $5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17
       where exists (select 1 from consumed)
       returning id
     ), inserted_access as (
       insert into own_auth_authorization_access_tokens
         (id, token_hash, prefix, grant_id, authorization_client_id,
          user_id, scopes, expires_at, revoked_at, created_at)
       select $18,$19,$20,$21,$22,$23,$24,$25,$26,$27
       where exists (select 1 from consumed)
     )
     select case
       when exists (select 1 from inserted_refresh) then 'rotated'
       when exists (select 1 from reused_grant) then 'reused'
       else 'invalid'
     end as status`,
    params.map(toPostgresValue)
  );
  const status = result.rows[0]?.status ?? "invalid";
  if (status === "reused") {
    await revokeRefreshTokenFamily(db, input);
  }
  return status;
}

async function revokeRefreshTokenFamily(
  db: PostgresQueryable,
  input: RotateAuthorizationRefreshTokenInput
): Promise<void> {
  await db.query(
    `with target_grant as (
       select grant_id from own_auth_authorization_refresh_tokens
       where token_hash = $1 and authorization_client_id = $2
     ), revoked_access as (
       update own_auth_authorization_access_tokens set revoked_at = $3
       where grant_id in (select grant_id from target_grant)
         and revoked_at is null
     )
     update own_auth_authorization_refresh_tokens set revoked_at = $3
     where grant_id in (select grant_id from target_grant)
       and revoked_at is null`,
    [
      input.tokenHash,
      input.authorizationClientId,
      input.rotatedAt
    ].map(toPostgresValue)
  );
}
