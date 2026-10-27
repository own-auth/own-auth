create table if not exists own_auth_user_erasures (
  operation_id text primary key,
  write_id text not null,
  user_id text unique,
  subject text,
  pending_stores text not null default '[]',
  protected_until_ms integer not null,
  cloud_event_id text unique,
  pending_cloud_events text not null default '[]',
  cloud_complete integer not null default 0,
  created_at_ms integer not null,
  completed_at_ms integer,
  constraint own_auth_erasure_subject_check check ((user_id is null) = (subject is null))
);

create table own_auth_invitations_erasure (
  id text primary key,
  token_id text references own_auth_tokens(id) on delete set null,
  organisation_id text not null references own_auth_organisations(id) on delete cascade,
  email text,
  phone text,
  role text not null,
  invited_by_user_id text references own_auth_users(id) on delete set null,
  status text not null,
  expires_at integer not null,
  accepted_at integer,
  revoked_at integer,
  created_at integer not null,
  operation_id text,
  constraint own_auth_invitations_role_check check (
    length(role) between 1 and 64
    and substr(role, 1, 1) glob '[a-z]'
    and role not glob '*[^a-z0-9_-]*'
  ),
  constraint own_auth_invitations_status_check check (status in ('pending', 'accepted', 'expired', 'revoked')),
  constraint own_auth_invitations_contact_check check (email is not null or phone is not null)
);
insert into own_auth_invitations_erasure select
  id, token_id, organisation_id, email, phone, role, invited_by_user_id,
  status, expires_at, accepted_at, revoked_at, created_at, operation_id
  from own_auth_invitations;
drop table own_auth_invitations;
alter table own_auth_invitations_erasure rename to own_auth_invitations;
create unique index own_auth_invitations_token_idx on own_auth_invitations(token_id) where token_id is not null;
create index own_auth_invitations_pending_email_idx
  on own_auth_invitations(organisation_id, lower(email), status, created_at desc) where email is not null;
alter table own_auth_webhook_deliveries add column send_started_at integer;
create index own_auth_user_erasures_pending_idx on own_auth_user_erasures(protected_until_ms)
  where subject is not null;

alter table own_auth_rate_limits add column user_id text references own_auth_users(id) on delete cascade;
create index own_auth_rate_limits_user_idx on own_auth_rate_limits(user_id) where user_id is not null;

create view own_auth_active_erasure_subjects as
  select user_id, subject from own_auth_user_erasures where subject is not null
    and (protected_until_ms > (julianday('now') - 2440587.5) * 86400000 or pending_stores <> '[]');

create view own_auth_erasure_identities as
  select e.user_id, lower(json_extract(e.subject, '$.email')) as email,
    json_extract(e.subject, '$.phone') as phone,
    json_extract(a.value, '$.provider') as provider,
    json_extract(a.value, '$.providerAccountId') as provider_account_id
  from own_auth_active_erasure_subjects e left join json_each(e.subject, '$.identities') a on true;

create trigger own_auth_erasure_user_guard before insert on own_auth_users when exists (
  select 1 from own_auth_erasure_identities e where new.id = e.user_id or lower(new.email) = e.email or new.phone = e.phone
) begin select raise(abort, 'own_auth_erasure_protected'); end;
create trigger own_auth_erasure_user_update_guard before update on own_auth_users when exists (
  select 1 from own_auth_erasure_identities e where new.id = e.user_id or lower(new.email) = e.email or new.phone = e.phone
) begin select raise(abort, 'own_auth_erasure_protected'); end;
create trigger own_auth_erasure_account_guard before insert on own_auth_accounts when exists (
  select 1 from own_auth_erasure_identities e where new.user_id = e.user_id or
    (new.provider = e.provider and new.provider_account_id = e.provider_account_id)
) begin select raise(abort, 'own_auth_erasure_protected'); end;
create trigger own_auth_erasure_account_update_guard before update on own_auth_accounts when exists (
  select 1 from own_auth_erasure_identities e where new.user_id = e.user_id or
    (new.provider = e.provider and new.provider_account_id = e.provider_account_id)
) begin select raise(abort, 'own_auth_erasure_protected'); end;
create trigger own_auth_erasure_token_guard before insert on own_auth_tokens when exists (
  select 1 from own_auth_erasure_identities e where new.user_id = e.user_id or
    (new.user_id is null and (lower(new.email) = e.email or new.phone = e.phone))
) begin select raise(abort, 'own_auth_erasure_protected'); end;
create trigger own_auth_erasure_token_update_guard before update on own_auth_tokens when exists (
  select 1 from own_auth_erasure_identities e where new.user_id = e.user_id or
    (new.user_id is null and (lower(new.email) = e.email or new.phone = e.phone))
) begin select raise(abort, 'own_auth_erasure_protected'); end;
create trigger own_auth_erasure_otp_guard before insert on own_auth_sms_otps when exists (
  select 1 from own_auth_erasure_identities e where new.user_id = e.user_id or (new.user_id is null and new.phone = e.phone)
) begin select raise(abort, 'own_auth_erasure_protected'); end;
create trigger own_auth_erasure_otp_update_guard before update on own_auth_sms_otps when exists (
  select 1 from own_auth_erasure_identities e where new.user_id = e.user_id or (new.user_id is null and new.phone = e.phone)
) begin select raise(abort, 'own_auth_erasure_protected'); end;

create view own_auth_erasure_lookup_identifiers as
  select e.user_id, r.value as identifier from own_auth_active_erasure_subjects e, json_each(e.subject, '$.references') r
  union select user_id, email from own_auth_erasure_identities
  union select user_id, phone from own_auth_erasure_identities
  union select user_id, provider_account_id from own_auth_erasure_identities;
create trigger own_auth_erasure_rate_guard before insert on own_auth_rate_limits when exists (
  select 1 from own_auth_erasure_lookup_identifiers e where new.user_id = e.user_id or
    (new.user_id is null and substr(new.key, -length(e.identifier) - 1) = ':' || e.identifier)
) begin select raise(abort, 'own_auth_erasure_protected'); end;
create trigger own_auth_erasure_rate_update_guard before update on own_auth_rate_limits when exists (
  select 1 from own_auth_erasure_lookup_identifiers e where new.user_id = e.user_id or
    (new.user_id is null and substr(new.key, -length(e.identifier) - 1) = ':' || e.identifier)
) begin select raise(abort, 'own_auth_erasure_protected'); end;

create view own_auth_erasure_event_documents as
  with recursive documents(kind, record_id, doc) as (
    select 'audit', id, json_object('actorUserId', actor_user_id, 'targetUserId', target_user_id,
      'apiKeyId', api_key_id, 'payload', metadata) from own_auth_audit_events
    union all select 'webhook', id, payload from own_auth_webhook_events where json_valid(payload)
    union all select 'cloud', id, payload from own_auth_cloud_outbox
      where event_type not in ('user.deleted', 'org.deleted') and json_valid(payload)
    union all select 'command', idempotency_key, json_object('payload', payload, 'result', json(result))
      from own_auth_cloud_commands
    union all select d.kind, d.record_id, n.atom from documents d, json_tree(d.doc) n
      where n.key = 'payload' and n.type = 'text' and json_valid(n.atom)
  ) select * from documents;

create view own_auth_erasure_protected_events as
  select distinct d.kind, d.record_id from own_auth_erasure_event_documents d,
    json_tree(d.doc) n, own_auth_active_erasure_subjects e where n.type = 'text' and (
      (n.key in ('id','userId','user_id','actorUserId','actor_user_id','actorId','targetUserId','target_user_id',
        'recipientUserId','ownerUserId','owner_user_id','invitedByUserId','invited_by_user_id','revokedBy','revoked_by',
        'accountId','account_id','sessionId','session_id','tokenId','token_id','otpId','apiKeyId','api_key_id',
        'grantId','grant_id','membershipId','membership_id','memberId','scimUserId','eventId','event_id',
        'deliveryId','delivery_id','mfaChallengeId','mfa_challenge_id','organisationId','organisation_id','connectionId','connection_id')
        and exists (select 1 from json_each(e.subject, '$.references') r where r.value = n.atom))
      or (n.key in ('email','normalizedEmail','providerEmail','inviteeEmail') and lower(n.atom) = lower(json_extract(e.subject, '$.email')))
      or (n.key in ('phone','providerPhone') and n.atom = json_extract(e.subject, '$.phone'))
      or (n.key = 'targetId' and json_extract(d.doc, n.path || '.targetType') = 'user' and n.atom = e.user_id)
    );

create trigger own_auth_erasure_audit_guard after insert on own_auth_audit_events when exists (
  select 1 from own_auth_erasure_protected_events where kind = 'audit' and record_id = new.id
) begin select raise(abort, 'own_auth_erasure_protected'); end;
create trigger own_auth_erasure_audit_update_guard after update on own_auth_audit_events when exists (
  select 1 from own_auth_erasure_protected_events where kind = 'audit' and record_id = new.id
) begin select raise(abort, 'own_auth_erasure_protected'); end;
create trigger own_auth_erasure_webhook_guard after insert on own_auth_webhook_events when exists (
  select 1 from own_auth_erasure_protected_events where kind = 'webhook' and record_id = new.id
) or exists (
  select 1 from json_tree(new.payload) n where n.key = 'targetUserId' and n.type = 'text'
    and not exists (select 1 from own_auth_users u where u.id = n.atom)
) begin select raise(abort, 'own_auth_erasure_protected'); end;
create trigger own_auth_erasure_webhook_update_guard after update on own_auth_webhook_events when exists (
  select 1 from own_auth_erasure_protected_events where kind = 'webhook' and record_id = new.id
) or exists (
  select 1 from json_tree(new.payload) n where n.key = 'targetUserId' and n.type = 'text'
    and not exists (select 1 from own_auth_users u where u.id = n.atom)
) begin select raise(abort, 'own_auth_erasure_protected'); end;
create trigger own_auth_erasure_cloud_guard after insert on own_auth_cloud_outbox
when new.event_type not in ('user.deleted', 'org.deleted') and (exists (
  select 1 from own_auth_erasure_protected_events where kind = 'cloud' and record_id = new.id
) or exists (
  select 1 from json_tree(new.payload) n where n.key in ('userId','recipientUserId') and n.type = 'text'
    and not (n.path = '$.meta' and new.event_type = 'audit.entry' and
      (coalesce(json_extract(new.payload, '$.data.metadata.reason'), '') = 'cloud_command' or
        coalesce(json_extract(new.payload, '$.data.metadata.source'), '') = 'cloud'))
    and not exists (select 1 from own_auth_users u where u.id = n.atom)
)) begin select raise(abort, 'own_auth_erasure_protected'); end;
create trigger own_auth_erasure_cloud_update_guard after update on own_auth_cloud_outbox
when new.event_type not in ('user.deleted', 'org.deleted') and (exists (
  select 1 from own_auth_erasure_protected_events where kind = 'cloud' and record_id = new.id
) or exists (
  select 1 from json_tree(new.payload) n where n.key in ('userId','recipientUserId') and n.type = 'text'
    and not (n.path = '$.meta' and new.event_type = 'audit.entry' and
      (coalesce(json_extract(new.payload, '$.data.metadata.reason'), '') = 'cloud_command' or
        coalesce(json_extract(new.payload, '$.data.metadata.source'), '') = 'cloud'))
    and not exists (select 1 from own_auth_users u where u.id = n.atom)
)) begin select raise(abort, 'own_auth_erasure_protected'); end;
create trigger own_auth_erasure_command_guard after insert on own_auth_cloud_commands when exists (
  select 1 from own_auth_erasure_protected_events where kind = 'command' and record_id = new.idempotency_key
) or (json_extract(new.payload, '$.userId') is not null and not exists (
  select 1 from own_auth_users where id = json_extract(new.payload, '$.userId')
)) begin select raise(abort, 'own_auth_erasure_protected'); end;
create trigger own_auth_erasure_command_update_guard after update on own_auth_cloud_commands when exists (
  select 1 from own_auth_erasure_protected_events where kind = 'command' and record_id = new.idempotency_key
) or (json_extract(new.payload, '$.userId') is not null and not exists (
  select 1 from own_auth_users where id = json_extract(new.payload, '$.userId')
)) begin select raise(abort, 'own_auth_erasure_protected'); end;

insert into own_auth_migrations (version) values ('020_user_erasure') on conflict do nothing;
