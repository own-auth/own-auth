create table if not exists own_auth_authorization_clients (
  id text primary key,
  client_id text not null unique,
  name text not null,
  client_type text not null,
  application_type text not null,
  token_endpoint_auth_method text not null,
  redirect_uris text[] not null,
  allowed_scopes text[] not null,
  status text not null,
  created_at timestamptz not null,
  updated_at timestamptz not null,
  revoked_at timestamptz,
  constraint own_auth_authorization_clients_type_check
    check (client_type in ('public', 'confidential')),
  constraint own_auth_authorization_clients_application_check
    check (application_type in ('web', 'native')),
  constraint own_auth_authorization_clients_auth_method_check
    check (token_endpoint_auth_method in (
      'none',
      'client_secret_basic',
      'client_secret_post'
    )),
  constraint own_auth_authorization_clients_status_check
    check (status in ('active', 'revoked'))
);

create table if not exists own_auth_authorization_client_secrets (
  id text primary key,
  authorization_client_id text not null
    references own_auth_authorization_clients(id) on delete cascade,
  prefix text not null,
  secret_hash text not null,
  created_at timestamptz not null,
  expires_at timestamptz,
  revoked_at timestamptz
);

create unique index if not exists own_auth_authorization_client_secrets_prefix_unique
  on own_auth_authorization_client_secrets (authorization_client_id, prefix);

create table if not exists own_auth_authorization_interactions (
  id text primary key,
  interaction_hash text not null unique,
  authorization_client_id text not null
    references own_auth_authorization_clients(id) on delete cascade,
  user_id text references own_auth_users(id) on delete cascade,
  request_ciphertext text not null,
  request_nonce text not null,
  encryption_key_id text not null,
  status text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null,
  constraint own_auth_authorization_interactions_status_check
    check (status in ('pending', 'approved', 'denied'))
);

create index if not exists own_auth_authorization_interactions_usable_idx
  on own_auth_authorization_interactions (
    interaction_hash,
    status,
    consumed_at,
    expires_at
  );

create table if not exists own_auth_authorization_grants (
  id text primary key,
  authorization_client_id text not null
    references own_auth_authorization_clients(id) on delete cascade,
  user_id text not null references own_auth_users(id) on delete cascade,
  scopes text[] not null,
  created_at timestamptz not null,
  updated_at timestamptz not null,
  revoked_at timestamptz
);

create unique index if not exists own_auth_authorization_grants_client_user_unique
  on own_auth_authorization_grants (authorization_client_id, user_id);

create table if not exists own_auth_authorization_codes (
  id text primary key,
  code_hash text not null unique,
  grant_id text not null references own_auth_authorization_grants(id) on delete cascade,
  authorization_client_id text not null
    references own_auth_authorization_clients(id) on delete cascade,
  user_id text not null references own_auth_users(id) on delete cascade,
  session_id text not null references own_auth_sessions(id) on delete cascade,
  redirect_uri text not null,
  scopes text[] not null,
  code_challenge text not null,
  nonce_ciphertext text,
  nonce_nonce text,
  encryption_key_id text,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null,
  constraint own_auth_authorization_codes_nonce_check check (
    (nonce_ciphertext is null and nonce_nonce is null and encryption_key_id is null)
    or
    (nonce_ciphertext is not null and nonce_nonce is not null and encryption_key_id is not null)
  )
);

create index if not exists own_auth_authorization_codes_usable_idx
  on own_auth_authorization_codes (
    code_hash,
    authorization_client_id,
    consumed_at,
    expires_at
  );

create table if not exists own_auth_authorization_access_tokens (
  id text primary key,
  token_hash text not null unique,
  prefix text not null,
  grant_id text not null references own_auth_authorization_grants(id) on delete cascade,
  authorization_client_id text not null
    references own_auth_authorization_clients(id) on delete cascade,
  user_id text not null references own_auth_users(id) on delete cascade,
  scopes text[] not null,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_at timestamptz not null
);

create index if not exists own_auth_authorization_access_tokens_grant_idx
  on own_auth_authorization_access_tokens (grant_id, revoked_at, expires_at);

create table if not exists own_auth_authorization_refresh_tokens (
  id text primary key,
  token_hash text not null unique,
  prefix text not null,
  grant_id text not null references own_auth_authorization_grants(id) on delete cascade,
  authorization_client_id text not null
    references own_auth_authorization_clients(id) on delete cascade,
  user_id text not null references own_auth_users(id) on delete cascade,
  scopes text[] not null,
  generation integer not null,
  replaced_by_token_id text,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null,
  constraint own_auth_authorization_refresh_tokens_generation_check
    check (generation >= 0)
);

create index if not exists own_auth_authorization_refresh_tokens_grant_idx
  on own_auth_authorization_refresh_tokens (
    grant_id,
    revoked_at,
    consumed_at,
    expires_at
  );

create table if not exists own_auth_oidc_subjects (
  id text primary key,
  user_id text not null unique references own_auth_users(id) on delete cascade,
  subject text not null unique,
  created_at timestamptz not null
);

insert into own_auth_migrations (version)
values ('011_authorization_server')
on conflict (version) do nothing;
