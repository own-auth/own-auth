alter table own_auth_authorization_clients
  add column grant_types text not null
    default '["authorization_code","refresh_token"]';

create table if not exists own_auth_device_authorizations (
  id text primary key,
  device_code_hash text not null unique,
  user_code_hash text not null unique,
  authorization_client_id text not null references own_auth_authorization_clients(id) on delete cascade,
  protected_resource_id text references own_auth_protected_resources(id) on delete restrict,
  request_ciphertext text not null,
  request_nonce text not null,
  encryption_key_id text not null,
  dpop_jkt text check (
    dpop_jkt is null or
    (length(dpop_jkt) = 43 and dpop_jkt not glob '*[^A-Za-z0-9_-]*')
  ),
  status text not null,
  user_id text references own_auth_users(id) on delete set null,
  session_id text references own_auth_sessions(id) on delete set null,
  grant_id text references own_auth_authorization_grants(id) on delete set null,
  approved_scopes text not null default '[]',
  polling_interval_seconds integer not null,
  next_poll_at integer not null,
  expires_at integer not null,
  approved_at integer,
  denied_at integer,
  consumed_at integer,
  created_at integer not null,
  constraint own_auth_device_authorizations_status_check
    check (status in ('pending', 'approved', 'denied', 'consumed')),
  constraint own_auth_device_authorizations_polling_check
    check (polling_interval_seconds > 0)
);

create index if not exists own_auth_device_authorizations_cleanup_idx
  on own_auth_device_authorizations (expires_at);

insert into own_auth_migrations (version)
values ('016_device_authorization')
on conflict (version) do nothing;
