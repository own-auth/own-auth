-- Coordinate cross-table invitation acceptance and authentication-method
-- removal without exposing internal operation state through public models.

alter table own_auth_users
  add column if not exists auth_method_version integer not null default 0;

alter table own_auth_users
  add column if not exists auth_method_operation_id text;

alter table own_auth_invitations
  add column if not exists operation_id text;

insert into own_auth_migrations (version)
values ('017_atomic_auth_operations')
on conflict (version) do nothing;
