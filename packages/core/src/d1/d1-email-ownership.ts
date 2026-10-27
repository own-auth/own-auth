import type { AtomicEmailOwnershipInput, AtomicEmailOwnershipResult } from "../auth-storage-atomic.js";
import { databaseColumnEntries, type DatabaseRow } from "../database-types.js";
import { organisationMemberReturning, sessionReturning, userColumns, userReturning } from "../database-schema.js";
import { mapOrganisationMember, mapSession, mapUser } from "../database-mappers.js";
import { emailOwnershipRetentionSql } from "../email-ownership-sql.js";
import type { D1DatabaseLike } from "./d1-types.js";
import { toD1Value } from "./d1-values.js";

export async function claimD1EmailOwnership(
  db: D1DatabaseLike,
  input: AtomicEmailOwnershipInput
): Promise<AtomicEmailOwnershipResult | null> {
  const at = input.verifiedAt.getTime();
  const tokenHash = input.proof.kind === "token" ? input.proof.tokenHash : null;
  const tokenType = input.proof.kind === "token" ? input.proof.type : null;
  const providerProof = input.proof.kind === "provider" ? 1 : 0;
  const samlOrganisationId = input.proof.kind === "provider" ? input.proof.samlOrganisationId : undefined;
  const statement = (sql: string, values: unknown[]) => db.prepare(sql).bind(...values.map(toD1Value));
  const retention = emailOwnershipRetentionSql("auth_user", "?5", "?6", "?4", "?12");
  const proof = `(?14 is null or ?14 > (julianday('now') - 2440587.5) * 86400000) and (?11 = 1 or exists (
    select 1 from own_auth_tokens where token_hash = ?9 and type = ?10 and email = ?3
      and (user_id is null or user_id = ?2) and used_at is null and expires_at > ?4
      and (type <> 'password_reset' or password_reset_version = auth_user.password_reset_version)
  ))`;
  const originalGuard = `exists (select 1 from own_auth_users
    where id = ? and auth_method_operation_id = ? and email is null)`;
  const replacementGuard = `exists (select 1 from own_auth_users
    where id = ? and auth_method_operation_id = ? and email = ?)`;
  const replacementValues: unknown[] = [];
  const bind = (value: unknown) => { replacementValues.push(value); return `?${replacementValues.length}`; };
  const entries = databaseColumnEntries(userColumns, input.replacementUser);
  const newColumns = entries.map(([, column]) => column).join(", ");
  const newValues = entries.map(([key]) => bind(input.replacementUser[key])).join(", ");
  const operation = bind(input.operationId);
  const sourceId = bind(input.sourceUserId);
  const email = bind(input.email);
  const timestamp = bind(at);
  const proofHash = bind(tokenHash);
  const proofType = bind(tokenType);
  const provider = bind(providerProof);
  const authority = bind(input.proof.expiresAt ?? null);
  const primary = input.replacementAccount;
  const ownerGuard = `exists (select 1 from own_auth_users
    where id in (?, ?) and email = ? and auth_method_operation_id = ?)`;
  const ownerValues = [input.sourceUserId, input.replacementUser.id, input.email, input.operationId];
  const statements = [
    statement("select email_verified_at from own_auth_users where id = ?", [input.sourceUserId]),
    statement(`with original as materialized (
      select auth_user.id, ${retention} as keep_original
      from own_auth_users auth_user
      where auth_user.id = ?2 and auth_user.email = ?3
        and (auth_user.email_verified_at is null or auth_user.disabled_at is null
          or ${input.proof.kind === "token" && input.proof.type === "password_reset" ? "1" : "0"}) and ${proof}
        and (?13 is null or not exists (select 1 from own_auth_organisation_members
          where user_id = ?2 and organisation_id = ?13 and status <> 'active'))
    ) update own_auth_users set
      auth_method_operation_id = ?1,
      email = case when (select keep_original from original) then email else null end,
      email_verified_at = case when (select keep_original from original) then coalesce(email_verified_at, ?4) else null end,
      password_hash = case when (select keep_original from original) and ?8 = 1 then ?7 else password_hash end,
      password_reset_version = password_reset_version + ?8,
      updated_at = ?4
      where id in (select id from original)`, [
      input.operationId, input.sourceUserId, input.email, at, input.sessionTokenHash,
      input.verifiedAccountId ?? null, input.passwordHash ?? null,
      input.passwordHash === undefined ? 0 : 1, tokenHash, tokenType, providerProof,
      input.proof.kind === "provider" ? input.proof.originalActorUserId ?? null : null,
      samlOrganisationId ?? null, input.proof.expiresAt ?? null
    ]),
    statement(`insert into own_auth_users (${newColumns}, auth_method_operation_id)
      select ${newValues}, ${operation}
      where (${authority} is null or ${authority} > (julianday('now') - 2440587.5) * 86400000) and (exists (select 1 from own_auth_users
          where id = ${sourceId} and email is null and auth_method_operation_id = ${operation})
        or (${sourceId} is null
          and not exists (select 1 from own_auth_users where email = ${email})
          and (${provider} = 1 or exists (
            select 1 from own_auth_tokens where token_hash = ${proofHash} and type = ${proofType}
              and email = ${email} and user_id is null and used_at is null and expires_at > ${timestamp}
          ))))`, replacementValues),
    statement(`delete from own_auth_accounts
      where user_id = ? and provider in ('password', 'magic_link') and provider_account_id = ?
        and ${originalGuard}`, [input.sourceUserId, input.email, input.sourceUserId, input.operationId]),
    statement(`insert into own_auth_accounts
      (id, user_id, provider, provider_account_id, provider_email, provider_phone, created_at, updated_at)
      select ?, ?, ?, ?, ?, null, ?, ? where ${replacementGuard}`, [
      primary.id, primary.userId, primary.provider, input.email, input.email, at, at,
      input.replacementUser.id, input.operationId, input.email
    ]),
    statement(`update own_auth_accounts set user_id = ?, updated_at = ?
      where id = ? and user_id = ? and ${replacementGuard}`, [
      input.replacementUser.id, at, input.verifiedAccountId ?? null, input.sourceUserId,
      input.replacementUser.id, input.operationId, input.email
    ]),
    statement(`update own_auth_organisation_members set user_id = ?, updated_at = ?
      where user_id = ? and id in (select membership_id from own_auth_scim_users
        where user_id = ? and normalized_email = ? and deleted_at is null)
        and ${replacementGuard} returning ${organisationMemberReturning}`, [
      input.replacementUser.id, at, input.sourceUserId, input.sourceUserId, input.email,
      input.replacementUser.id, input.operationId, input.email
    ]),
    statement(`update own_auth_scim_users set user_id = ?, version = version + 1, updated_at = ?
      where user_id = ? and normalized_email = ? and deleted_at is null and ${replacementGuard}`, [
      input.replacementUser.id, at, input.sourceUserId, input.email,
      input.replacementUser.id, input.operationId, input.email
    ]),
    statement(`update own_auth_tokens set used_at = ?
      where token_hash = ? and type = ? and used_at is null and ${ownerGuard}`, [
      at, tokenHash, tokenType, ...ownerValues
    ]),
    statement(`update own_auth_sessions set revoked_at = ?, revoke_reason = 'email_ownership_changed'
      where user_id = ? and revoked_at is null and ${replacementGuard}
      returning ${sessionReturning}`, [
      at, input.sourceUserId, input.replacementUser.id, input.operationId, input.email
    ]),
    statement(`select ${userReturning} from own_auth_users
      where id in (?, ?) and email = ? and auth_method_operation_id = ?`, ownerValues),
    statement(`update own_auth_users set auth_method_operation_id = null
      where id in (?, ?) and auth_method_operation_id = ?`, [
      input.sourceUserId, input.replacementUser.id, input.operationId
    ])
  ];
  const [original, , , , , , memberships, , , sessions, ownerResult] = await db.batch<DatabaseRow>(statements);
  const owner = ownerResult?.results?.[0];
  return owner ? {
    user: mapUser(owner),
    created: owner.id === input.replacementUser.id,
    verified: owner.id === input.replacementUser.id || original?.results?.[0]?.email_verified_at === null,
    revokedSessions: (sessions?.results ?? []).map(mapSession),
    reassignedMemberships: (memberships?.results ?? []).map(mapOrganisationMember)
  } : null;
}
