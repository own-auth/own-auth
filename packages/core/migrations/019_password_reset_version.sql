alter table own_auth_users
  add column if not exists password_reset_version integer not null default 1;

alter table own_auth_tokens
  add column if not exists password_reset_version integer not null default 0;

insert into own_auth_migrations (version)
values ('019_password_reset_version')
on conflict (version) do nothing;
