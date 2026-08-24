create table if not exists own_auth_cloud_entity_versions (
  entity_type text not null,
  entity_id text not null,
  version integer not null check (version > 0),
  primary key (entity_type, entity_id)
);

create table if not exists own_auth_cloud_outbox (
  id text primary key,
  event_type text not null,
  payload text not null,
  entity_version integer,
  priority integer not null default 0 check (priority in (0, 1)),
  created_at text not null,
  sent_at text,
  ack_at text,
  attempts integer not null default 0 check (attempts >= 0),
  next_retry_at text not null,
  lease_until text
);

create index if not exists own_auth_cloud_outbox_claim_idx
  on own_auth_cloud_outbox (priority desc, next_retry_at, created_at);

create table if not exists own_auth_cloud_commands (
  idempotency_key text primary key,
  nonce text not null unique,
  action text not null,
  payload_hash text not null,
  payload text not null,
  status text not null default 'reserved' check (status in ('reserved', 'completed', 'failed')),
  result text,
  reserved_at text not null,
  lease_until text not null,
  completed_at text
);

create index if not exists own_auth_cloud_commands_cleanup_idx
  on own_auth_cloud_commands (completed_at);

create table if not exists own_auth_cloud_config (
  key text primary key,
  value text not null
);

create table if not exists own_auth_cloud_challenge_nonces (
  nonce text primary key,
  expires_at text not null
);

insert into own_auth_migrations (version)
values ('018_cloud')
on conflict (version) do nothing;
