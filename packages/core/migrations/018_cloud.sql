create table if not exists own_auth_cloud_entity_versions (
  entity_type text not null,
  entity_id text not null,
  version integer not null,
  primary key (entity_type, entity_id),
  constraint own_auth_cloud_entity_version_positive check (version > 0)
);

create table if not exists own_auth_cloud_outbox (
  id text primary key,
  event_type text not null,
  payload jsonb not null,
  entity_version integer,
  priority boolean not null default false,
  created_at timestamptz not null,
  sent_at timestamptz,
  ack_at timestamptz,
  attempts integer not null default 0,
  next_retry_at timestamptz not null,
  lease_until timestamptz,
  constraint own_auth_cloud_outbox_attempts_nonnegative check (attempts >= 0)
);

create index if not exists own_auth_cloud_outbox_claim_idx
  on own_auth_cloud_outbox (priority desc, next_retry_at, created_at)
  where ack_at is null;

create or replace function own_auth_enqueue_cloud_event(
  p_id text,
  p_event_type text,
  p_payload jsonb,
  p_entity_type text,
  p_entity_id text,
  p_priority boolean,
  p_created_at timestamptz,
  p_maximum_pending integer
) returns table (inserted boolean, entity_version integer)
language plpgsql
as $$
declare
  assigned_version integer;
  pending_count integer;
begin
  perform pg_advisory_xact_lock(hashtext('own_auth_cloud_outbox_capacity'));

  if p_maximum_pending is not null then
    select count(*)::integer into pending_count
    from own_auth_cloud_outbox
    where ack_at is null and priority = false;

    if pending_count >= p_maximum_pending then
      return query select false, null::integer;
      return;
    end if;
  end if;

  if p_entity_type is not null and p_entity_id is not null then
    insert into own_auth_cloud_entity_versions (entity_type, entity_id, version)
    values (p_entity_type, p_entity_id, 1)
    on conflict (entity_type, entity_id)
    do update set version = own_auth_cloud_entity_versions.version + 1
    returning version into assigned_version;
  end if;

  insert into own_auth_cloud_outbox
    (id, event_type, payload, entity_version, priority, created_at, next_retry_at)
  values (
    p_id, p_event_type, p_payload, assigned_version, p_priority,
    p_created_at, p_created_at
  );

  return query select true, assigned_version;
end;
$$;

create table if not exists own_auth_cloud_commands (
  idempotency_key text primary key,
  nonce text not null unique,
  action text not null,
  payload_hash text not null,
  payload jsonb not null,
  status text not null default 'reserved',
  result jsonb,
  reserved_at timestamptz not null,
  lease_until timestamptz not null,
  completed_at timestamptz,
  constraint own_auth_cloud_command_status check (status in ('reserved', 'completed', 'failed'))
);

create index if not exists own_auth_cloud_commands_cleanup_idx
  on own_auth_cloud_commands (completed_at) where completed_at is not null;

create table if not exists own_auth_cloud_config (
  key text primary key,
  value text not null
);

create table if not exists own_auth_cloud_challenge_nonces (
  nonce text primary key,
  expires_at timestamptz not null
);

insert into own_auth_migrations (version)
values ('018_cloud')
on conflict (version) do nothing;
