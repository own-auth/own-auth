create table if not exists own_auth_user_erasures (
  operation_id text primary key,
  write_id text not null,
  user_id text unique,
  subject jsonb,
  pending_stores jsonb not null default '[]',
  protected_until_ms bigint not null,
  cloud_event_id text unique,
  pending_cloud_events jsonb not null default '[]',
  cloud_complete boolean not null default false,
  created_at_ms bigint not null,
  completed_at_ms bigint,
  constraint own_auth_erasure_subject_check check ((user_id is null) = (subject is null))
);

alter table own_auth_invitations alter column invited_by_user_id drop not null;
alter table own_auth_invitations drop constraint own_auth_invitations_invited_by_user_id_fkey;
alter table own_auth_invitations add constraint own_auth_invitations_invited_by_user_id_fkey
  foreign key (invited_by_user_id) references own_auth_users(id) on delete set null;
alter table own_auth_webhook_deliveries add column send_started_at timestamptz;

create index own_auth_user_erasures_pending_idx on own_auth_user_erasures(protected_until_ms)
  where subject is not null;

alter table own_auth_rate_limits add column user_id text references own_auth_users(id) on delete cascade;
create index own_auth_rate_limits_user_idx on own_auth_rate_limits(user_id) where user_id is not null;

create function own_auth_erasure_matches(value jsonb, subject jsonb) returns boolean
language plpgsql immutable as $$
declare entry record; item jsonb;
begin
  if jsonb_typeof(value) = 'array' then
    for item in select jsonb_array_elements(value) loop
      if own_auth_erasure_matches(item, subject) then return true; end if;
    end loop;
  elsif jsonb_typeof(value) = 'object' then
    for entry in select * from jsonb_each(value) loop
      if jsonb_typeof(entry.value) = 'string' then
        if entry.key in ('id', 'userId', 'user_id', 'actorUserId', 'actor_user_id', 'actorId',
          'targetUserId', 'target_user_id', 'recipientUserId', 'accountId', 'account_id',
          'sessionId', 'session_id', 'tokenId', 'token_id', 'otpId', 'apiKeyId', 'api_key_id',
          'grantId', 'grant_id', 'membershipId', 'membership_id', 'memberId', 'scimUserId',
          'eventId', 'event_id', 'deliveryId', 'delivery_id', 'ownerUserId', 'owner_user_id',
          'invitedByUserId', 'invited_by_user_id', 'revokedBy', 'revoked_by',
          'mfaChallengeId', 'mfa_challenge_id', 'organisationId', 'organisation_id',
          'connectionId', 'connection_id')
          and subject->'references' ? (entry.value #>> '{}') then return true; end if;
        if entry.key = 'targetId' and value->>'targetType' = 'user'
          and entry.value #>> '{}' = subject->>'userId' then return true; end if;
        if entry.key in ('email', 'normalizedEmail', 'providerEmail', 'inviteeEmail')
          and lower(entry.value #>> '{}') = lower(subject->>'email') then return true; end if;
        if entry.key in ('phone', 'providerPhone')
          and entry.value #>> '{}' = subject->>'phone' then return true; end if;
        if entry.key = 'payload' then
          begin
            if own_auth_erasure_matches((entry.value #>> '{}')::jsonb, subject) then return true; end if;
          exception when invalid_text_representation then null;
          end;
        end if;
      end if;
      if own_auth_erasure_matches(entry.value, subject) then return true; end if;
    end loop;
  end if;
  return false;
end;
$$;

create function own_auth_guard_erased_record() returns trigger language plpgsql as $$
declare row_value jsonb := to_jsonb(new); receipt record;
begin
  if tg_table_name = 'own_auth_cloud_outbox' and row_value->>'event_type' in ('user.deleted', 'org.deleted') then return new; end if;
  if tg_table_name = 'own_auth_cloud_commands' and row_value->'payload'->>'userId' is not null
    and not exists (select 1 from own_auth_users where id = row_value->'payload'->>'userId')
  then raise exception 'own_auth_erasure_protected' using errcode = 'P0001'; end if;
  if tg_table_name = 'own_auth_cloud_outbox' and exists (
    select 1 from (values (row_value->'payload'->'data'->>'userId'),
      (row_value->'payload'->'data'->>'recipientUserId'),
      (case when row_value->>'event_type' = 'audit.entry' and
        (row_value->'payload'->'data'->'metadata'->>'reason' = 'cloud_command' or
          row_value->'payload'->'data'->'metadata'->>'source' = 'cloud') then null
        else row_value->'payload'->'meta'->>'userId' end)) users(id)
    where id is not null and not exists (select 1 from own_auth_users u where u.id = users.id)
  ) then raise exception 'own_auth_erasure_protected' using errcode = 'P0001'; end if;
  for receipt in select subject from own_auth_user_erasures
    where subject is not null and (protected_until_ms > extract(epoch from clock_timestamp()) * 1000
      or pending_stores <> '[]'::jsonb) loop
    if row_value->>'user_id' is not null and row_value->>'user_id' <> receipt.subject->>'userId'
      and tg_table_name <> 'own_auth_accounts' then continue; end if;
    if own_auth_erasure_matches(case when tg_table_name in ('own_auth_users', 'own_auth_api_keys')
        then row_value - 'metadata' else row_value end, receipt.subject)
      or (tg_table_name = 'own_auth_accounts' and exists (
        select 1 from jsonb_array_elements(receipt.subject->'identities') identity
        where identity->>'provider' = row_value->>'provider'
          and identity->>'providerAccountId' = row_value->>'provider_account_id'))
      or (tg_table_name = 'own_auth_rate_limits' and row_value->>'user_id' is null and exists (
        select 1 from (
          select jsonb_array_elements_text(receipt.subject->'references') as reference
          union select receipt.subject->>'email'
          union select receipt.subject->>'phone'
          union select i->>'providerAccountId' from jsonb_array_elements(receipt.subject->'identities') i
        ) identifiers
        where right(row_value->>'key', length(reference) + 1) = ':' || reference))
    then raise exception 'own_auth_erasure_protected' using errcode = 'P0001'; end if;
  end loop;
  return new;
end;
$$;

do $$
declare table_name text;
begin
  foreach table_name in array array[
    'users', 'accounts', 'sessions', 'tokens', 'sms_otps', 'api_keys',
    'organisation_members', 'oauth_transactions', 'oauth_credentials', 'mfa_factors',
    'recovery_codes', 'mfa_challenges', 'passkeys', 'webauthn_challenges',
    'authorization_interactions', 'authorization_grants', 'authorization_codes',
    'authorization_access_tokens', 'authorization_refresh_tokens', 'oidc_subjects',
    'saml_transactions', 'scim_users', 'device_authorizations', 'audit_events',
    'webhook_events', 'cloud_outbox', 'cloud_commands', 'rate_limits'
  ] loop
    execute format('create trigger own_auth_erasure_write_guard before insert or update on %I
      for each row execute function own_auth_guard_erased_record()', 'own_auth_' || table_name);
  end loop;
end;
$$;

insert into own_auth_migrations (version) values ('020_user_erasure') on conflict do nothing;
