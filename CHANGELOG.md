# Changelog

## 0.3.0

### Breaking changes

- Node.js 20 or later is now required by the current SimpleWebAuthn server package used for passkeys. Cloudflare Workers remain supported with the `nodejs_compat` compatibility flag.
- First-factor sign-in methods now return a `SignInResult` discriminated union. Check `status` before reading `user`, `session`, or `sessionToken`. Users without MFA still receive `status: "complete"` immediately.
- `signUpEmailPassword` still completes immediately and keeps its existing session result shape because a newly created user cannot already have MFA factors.
- Applications using the HTTP handler must use its temporary HttpOnly MFA cookie when a sign-in returns `status: "mfa_required"`.
- Custom `AuthStorage` adapters must implement the new OAuth transaction, MFA, encrypted credential, passkey, WebAuthn challenge, and related atomic operations before using `0.3.0`.
- Plugin migration SQL is now keyed by database dialect so generation can fail before deployment when a plugin does not support the selected database.
- Plugin endpoint definitions now reject invalid methods, session requirements, missing handlers, and schemas outside Own Auth's supported subset when the plugin is configured.

### Added

- Google, GitHub, and Apple redirect OAuth with PKCE, nonce verification, atomic state consumption, explicit account linking, and popup support.
- Google One Tap with a stored, single-use nonce transaction.
- TOTP MFA, one-time recovery codes, MFA challenges, and session assurance levels.
- Optional encrypted OAuth refresh credentials with key rotation and server-only access-token refresh.
- Passkey registration, primary sign-in, MFA completion, listing, renaming, and revocation.
- A public plugin contract with namespaced routes, hooks, rate limits, migrations, OpenAPI output, and client fingerprints.
- Migrations `003_oauth_transactions` through `007_plugin_migrations`.
- Lazy Postgres initialization so importing `own-auth` with custom storage does not load `pg`.
- `auth.close()` for idempotent shutdown of the Postgres pool owned by Own Auth.
- Cloudflare D1 storage and rate-limit adapters through the explicit `own-auth/d1` package export.
- Named `AuditEventFilter` and `ClaimWebhookDeliveriesInput` types for custom storage adapters.
- Plugin `GET` endpoints can accept string-array query inputs through repeated query parameters; duplicate scalar parameters fail validation.
- Versioned D1 migration generation through `npx own-auth generate --dialect d1` for Wrangler-managed deployment.
- OpenTelemetry API instrumentation for core operations, HTTP handlers, provider calls, email and SMS delivery, plugins, and rate-limit denials. Applications configure their own SDK and exporters; without an SDK, telemetry is a no-op.
- Signed core authentication webhooks with durable Postgres and D1 outboxes, leased concurrent processing, bounded retries, complete attempt history, manual retry, and retention cleanup.
- A receiver verifier through `own-auth/webhooks` with exact-body HMAC validation, configurable timestamp tolerance, secret rotation, and an application-owned atomic replay claim.
- Migration `008_webhooks` for webhook events, deliveries, and cascading attempt history.
- Application-defined organisation roles and permissions with factory-inferred TypeScript unions, fail-closed removed roles, and migration `009_custom_authorization` for Postgres and D1.

### Security

- OAuth state, One Tap nonces, MFA challenges, recovery codes, and WebAuthn challenges are consumed atomically.
- Owner invitations now require an owner actor; administrators cannot grant the owner role.
- Personal API keys stop authenticating when their owning user is missing or disabled.
- Core endpoint and plugin contracts are runtime-owned and immutable, so caller mutation cannot change routes, session requirements, validation schemas, handlers, or client fingerprints after setup.
- Empty OAuth credential rotations now retain their expected-ciphertext comparison in Postgres and D1.
- In-memory storage keeps entity IDs immutable and isolates stored webhook and rate-limit timestamps from caller mutation.
- TOTP timesteps and passkey counters use atomic comparison updates to reject replay and concurrent reuse.
- Provider refresh tokens and TOTP secrets use purpose-separated AES-256-GCM encryption through the shared encryption key ring.
- Disabling TOTP invalidates its recovery codes, including codes attached to an outstanding MFA challenge.
- HTTP request body limits are enforced while streaming, including Apple's 64 KiB form-post callback limit.
- Generated plugin clients reject missing or mismatched server contract fingerprints.
- Browser OAuth popups exchange only completion state. OAuth codes, provider tokens, session tokens, and MFA challenge tokens are never sent through `postMessage`.
- Telemetry uses bounded attributes and excludes passwords, tokens, personal data, request contents, delivery contents, exception details, and database queries.
- Webhook payloads expose only fixed event fields and safe event-specific details. Delivery logs exclude response bodies, response headers, remote error messages, and raw secrets.
- Custom roles cannot grant owner transitions to non-owners, and invitations revalidate their configured role before consuming the single-use token.

### Runtime

- `DATABASE_URL` is validated when `createOwnAuth` runs, while driver import and connection errors retain their original PostgreSQL diagnostics on first use.
- Auth operations after `auth.close()` fail with the typed `auth_closed` error.
- Recovery-code sign-in webhook events identify `recovery_code` as the authentication method in their safe event details.

The trusted `signInWithVerifiedExternalIdentity` flow remains available for native provider SDKs and other integrations that verify provider credentials before calling Own Auth.
