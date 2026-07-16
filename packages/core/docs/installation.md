# Installation

## Requirements

- Node.js 20 or later, or a Cloudflare Worker with `nodejs_compat`
- A Postgres database, or Cloudflare D1 when deploying to Workers

Cloudflare Workers use the explicit `own-auth/d1` adapter without loading the Node.js `pg` driver. See [Cloudflare D1](/docs/cloudflare-d1) for the complete Worker setup.

## Install the package

```bash
npm install own-auth
```

Or with another package manager:

```bash
pnpm add own-auth
yarn add own-auth
```

## Set up your environment

The default Postgres setup reads two environment variables:

```bash
# .env
DATABASE_URL=postgres://user:password@localhost:5432/myapp
OWN_AUTH_TOKEN_PEPPER=your-random-secret-string
```

`DATABASE_URL` is your Postgres connection string. Any Postgres provider works: local, Supabase, Neon, Railway, RDS, or a VPS running Postgres.

Cloudflare D1 uses a Worker binding instead of `DATABASE_URL`. The token pepper remains a server-only Worker secret.

`OWN_AUTH_TOKEN_PEPPER` adds an extra layer of protection when hashing tokens. Generate a long random string, keep it secret, and use it only on the backend. If you change it, existing sessions, auth links, SMS codes, and API keys become invalid.

To generate a pepper:

```bash
openssl rand -base64 32
```

## Run migrations

For Postgres:

```bash
npx own-auth migrate
```

This creates the tables Own Auth needs in your database:

- `own_auth_migrations`
- `own_auth_users`
- `own_auth_accounts`
- `own_auth_sessions`
- `own_auth_tokens`
- `own_auth_sms_otps`
- `own_auth_organisations`
- `own_auth_organisation_members`
- `own_auth_invitations`
- `own_auth_api_keys`
- `own_auth_audit_events`
- `own_auth_rate_limits`
- `own_auth_oauth_transactions`
- `own_auth_mfa_factors`
- `own_auth_recovery_codes`
- `own_auth_mfa_challenges`
- `own_auth_oauth_credentials`
- `own_auth_passkeys`
- `own_auth_webauthn_challenges`
- `own_auth_plugin_migrations`
- `own_auth_webhook_events`
- `own_auth_webhook_deliveries`
- `own_auth_webhook_attempts`
- `own_auth_authorization_clients`
- `own_auth_authorization_client_secrets`
- `own_auth_authorization_interactions`
- `own_auth_authorization_grants`
- `own_auth_authorization_codes`
- `own_auth_authorization_access_tokens`
- `own_auth_authorization_refresh_tokens`
- `own_auth_oidc_subjects`

All Own Auth tables are prefixed with `own_auth_` to avoid conflicts. Your existing application tables are not modified.

For Cloudflare D1, generate versioned files and apply them with Wrangler. See [Cloudflare D1](/docs/cloudflare-d1).

## Verify

Check that everything is connected:

```bash
npx own-auth status
```

This prints the database connection status and the latest applied migration version. If it shows `Database: connected` and `Status: current`, you are ready.

## Database providers

Own Auth works with any Postgres database. Some common setups:

### Local Postgres

```bash
DATABASE_URL=postgres://postgres:postgres@localhost:5432/myapp
```

### Supabase

```bash
DATABASE_URL=postgres://postgres:[password]@db.[project].supabase.co:5432/postgres
```

### Neon

```bash
DATABASE_URL=postgres://[user]:[password]@[endpoint].neon.tech/[database]?sslmode=require
```

### Railway

```bash
DATABASE_URL=${{Postgres.DATABASE_URL}}
```

### AWS RDS

```bash
DATABASE_URL=postgres://[user]:[password]@[instance].rds.amazonaws.com:5432/[database]?sslmode=require
```

Use `?sslmode=require` for hosted databases that require TLS.

## Next step

Create your auth instance in the [Configuration guide](/docs/configuration).
