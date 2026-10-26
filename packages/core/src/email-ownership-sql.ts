/** The current account is safe to keep only when its original actor is also proved. */
export function emailOwnershipRetentionSql(
  user: string,
  sessionHash: string,
  verifiedAccountId: string,
  at: string,
  originalActor: string = "null"
): string {
  return `(${user}.email_verified_at is not null or (${user}.disabled_at is null and (
    ${user}.id = ${originalActor}
    or exists (
      select 1 from own_auth_sessions original_session
      where original_session.user_id = ${user}.id
        and original_session.token_hash = ${sessionHash}
        and original_session.revoked_at is null
        and original_session.expires_at > ${at}
        and original_session.idle_expires_at > ${at}
    )
    or (${user}.password_hash is null and ${user}.phone is null
      and not exists (select 1 from own_auth_sessions s where s.user_id = ${user}.id)
      and not exists (select 1 from own_auth_api_keys k where k.user_id = ${user}.id)
      and not exists (select 1 from own_auth_passkeys p where p.user_id = ${user}.id)
      and not exists (select 1 from own_auth_mfa_factors f where f.user_id = ${user}.id)
      and not exists (select 1 from own_auth_recovery_codes r where r.user_id = ${user}.id)
      and not exists (select 1 from own_auth_mfa_challenges m where m.user_id = ${user}.id)
      and not exists (select 1 from own_auth_webauthn_challenges w where w.user_id = ${user}.id)
      and not exists (select 1 from own_auth_organisations o where o.owner_user_id = ${user}.id)
      and not exists (select 1 from own_auth_authorization_interactions i where i.user_id = ${user}.id)
      and not exists (select 1 from own_auth_authorization_grants g where g.user_id = ${user}.id)
      and not exists (select 1 from own_auth_oidc_subjects s where s.user_id = ${user}.id)
      and not exists (
        select 1 from own_auth_accounts a where a.user_id = ${user}.id
          and a.provider not in ('password', 'magic_link')
          and a.id <> coalesce(${verifiedAccountId}, '')
      )
    )
  )))`;
}
