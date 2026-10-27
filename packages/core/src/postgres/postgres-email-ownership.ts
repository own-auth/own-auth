import type { AtomicEmailOwnershipInput, AtomicEmailOwnershipResult } from "../auth-storage-atomic.js";
import { databaseColumnEntries } from "../database-types.js";
import { userColumns, userReturning } from "../database-schema.js";
import { mapOrganisationMember, mapSession, mapUser } from "../database-mappers.js";
import { emailOwnershipRetentionSql } from "../email-ownership-sql.js";
import { toPostgresValue } from "./postgres-row.js";
import type { PostgresQueryable, Row } from "./postgres-types.js";

export async function claimPostgresEmailOwnership(
  db: PostgresQueryable,
  input: AtomicEmailOwnershipInput
): Promise<AtomicEmailOwnershipResult | null> {
  const values: unknown[] = [];
  const bind = (value: unknown) => { values.push(toPostgresValue(value)); return `$${values.length}`; };
  const sourceId = bind(input.sourceUserId);
  const email = bind(input.email);
  const at = bind(input.verifiedAt);
  const session = bind(input.sessionTokenHash);
  const account = bind(input.verifiedAccountId ?? null);
  const actor = bind(input.proof.kind === "provider" ? input.proof.originalActorUserId ?? null : null);
  const samlOrganisationId = input.proof.kind === "provider" ? input.proof.samlOrganisationId : undefined;
  const password = input.passwordHash === undefined ? "auth_user.password_hash" : bind(input.passwordHash);
  const newId = bind(input.replacementUser.id);
  let proof = "true";
  const tokenCte = input.proof.kind === "token"
    ? `locked_token as materialized (
        select id, password_reset_version from own_auth_tokens
        where token_hash = ${bind(input.proof.tokenHash)} and type = ${bind(input.proof.type)}
          and email = ${email} and (user_id is null or user_id = ${sourceId})
          and used_at is null and expires_at > ${at}
        for update
      ),`
    : "";
  if (input.proof.kind === "token") proof = "exists (select 1 from locked_token)";
  const membershipCte = samlOrganisationId
    ? `locked_membership as materialized (
        select status from own_auth_organisation_members
        where user_id = ${sourceId} and organisation_id = ${bind(samlOrganisationId)} for update
      ),`
    : "";
  const entries = databaseColumnEntries(userColumns, input.replacementUser);
  const candidateColumns = entries.map(([, column]) => column).join(", ");
  const candidateValues = entries.map(([key]) => bind(input.replacementUser[key])).join(", ");
  const primary = input.replacementAccount;
  const sql = `with ${tokenCte}${membershipCte}
    original as materialized (
      select auth_user.* from own_auth_users auth_user
      where auth_user.id = ${sourceId} and auth_user.email = ${email}
        and (auth_user.email_verified_at is null or auth_user.disabled_at is null
          or ${input.proof.kind === "token" && input.proof.type === "password_reset" ? "true" : "false"})
        and ${proof}
        ${samlOrganisationId ? "and not exists (select 1 from locked_membership where status <> 'active')" : ""}
        ${input.proof.kind === "token" && input.proof.type === "password_reset"
          ? "and auth_user.password_reset_version = (select password_reset_version from locked_token)" : ""}
      for update
    ),
    decision as (
      select auth_user.id,
        ${emailOwnershipRetentionSql("auth_user", session, account, at, actor)} as keep_original
      from original auth_user
    ),
    changed_original as (
      update own_auth_users auth_user set
        email = case when decision.keep_original then auth_user.email else null end,
        email_verified_at = case when decision.keep_original
          then coalesce(auth_user.email_verified_at, ${at}) else null end,
        password_hash = case when decision.keep_original then ${password} else auth_user.password_hash end,
        password_reset_version = auth_user.password_reset_version + ${input.passwordHash === undefined ? "0" : "1"},
        updated_at = ${at}
      from decision where auth_user.id = decision.id
      returning auth_user.*
    ),
    detached_email_accounts as (
      delete from own_auth_accounts where user_id = ${sourceId}
        and provider in ('password', 'magic_link') and provider_account_id = ${email}
        and exists (select 1 from changed_original where email is null)
      returning id
    ),
    inserted_owner as (
      insert into own_auth_users (${candidateColumns})
      select ${candidateValues}
      where exists (select 1 from changed_original where email is null)
        or (${sourceId} is null and ${proof}
          and not exists (select 1 from own_auth_users where email = ${email}))
      returning *
    ),
    inserted_email_account as (
      insert into own_auth_accounts
        (id, user_id, provider, provider_account_id, provider_email, provider_phone, created_at, updated_at)
      select ${bind(primary.id)}, id, ${bind(primary.provider)}, ${email}, ${email}, null, ${at}, ${at}
      from inserted_owner where (select count(*) from detached_email_accounts) >= 0
      returning id
    ),
    moved_verified_account as (
      update own_auth_accounts set user_id = ${newId}, updated_at = ${at}
      where id = ${account} and user_id = ${sourceId} and exists (select 1 from inserted_owner)
      returning id
    ),
    moved_provisioned_memberships as (
      update own_auth_organisation_members set user_id = ${newId}, updated_at = ${at}
      where id in (select membership_id from own_auth_scim_users
        where user_id = ${sourceId} and normalized_email = ${email} and deleted_at is null)
        and user_id = ${sourceId} and exists (select 1 from inserted_owner)
      returning *
    ),
    moved_provisioned_users as (
      update own_auth_scim_users set user_id = ${newId}, version = version + 1, updated_at = ${at}
      where user_id = ${sourceId} and normalized_email = ${email} and deleted_at is null
        and exists (select 1 from inserted_owner)
      returning id
    ),
    revoked_original_sessions as (
      update own_auth_sessions set revoked_at = ${at}, revoke_reason = 'email_ownership_changed'
      where user_id = ${sourceId} and revoked_at is null
        and exists (select 1 from inserted_owner)
      returning *
    ),
    owner as (
      select * from changed_original where email is not null
      union all select * from inserted_owner
    )
    ${input.proof.kind === "token" ? `, consumed_proof as (
      update own_auth_tokens set used_at = ${at}
      where id in (select id from locked_token) and exists (select 1 from owner)
      returning id
    )` : ""}
    select ${userReturning},
      exists (select 1 from inserted_owner) as created_owner,
      (exists (select 1 from inserted_owner) or
        exists (select 1 from original where email_verified_at is null)) as verified_owner,
      coalesce((select jsonb_agg(revoked_original_sessions) from revoked_original_sessions), '[]'::jsonb) as revoked_sessions,
      coalesce((select jsonb_agg(moved_provisioned_memberships) from moved_provisioned_memberships), '[]'::jsonb) as reassigned_memberships
      from owner
      ${input.proof.kind === "token" ? "where exists (select 1 from consumed_proof)" : ""}`;
  const result = await db.query<Row>(sql, values);
  const row = result.rows[0];
  return row ? {
    user: mapUser(row), created: row.created_owner === true, verified: row.verified_owner === true,
    revokedSessions: (row.revoked_sessions as Row[]).map(mapSession),
    reassignedMemberships: (row.reassigned_memberships as Row[]).map(mapOrganisationMember)
  } : null;
}
