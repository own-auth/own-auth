# Security Model

## Passwords

Passwords are hashed with **Argon2id**, the winner of the Password Hashing Competition and the recommended algorithm for new projects. It's resistant to GPU attacks, side-channel attacks, and time-memory trade-offs.

Own Auth never stores, logs, or returns plain-text passwords. The raw password exists in memory only during the hash operation and is discarded immediately after.

The hashing algorithm is not configurable. There's no reason to downgrade to bcrypt or scrypt for new projects.

## Tokens

All tokens, including magic links, password resets, email verification, phone codes, and invites, follow the same security model:

- **Random.** Generated with a cryptographically secure random number generator.
- **Single-use.** Consumed on first use. A second use fails.
- **Expiring.** Each token type has a TTL. After expiry, the token is rejected.
- **Hashed in storage.** The raw token is hashed with the token pepper before storage. The database contains only the hash.
- **Peppered.** The token pepper adds a secret layer to the hash. Even with database access, an attacker cannot reconstruct raw tokens without the pepper.

The raw token is sent to the user in an email link or SMS and is never persisted by Own Auth.

## Sessions

- **High-entropy tokens.** Session tokens are generated with a cryptographically secure random number generator, producing 256 bits of entropy.
- **Hashed in storage.** Only the hash of the session token is stored in the database. The raw token is returned to the application and is not persisted by Own Auth.
- **Revocable.** Individual sessions can be revoked instantly. Revoking all sessions for a user is a single call.
- **Expiring.** Sessions have an absolute TTL and an idle timeout. Both are enforced server-side on every `getCurrentSession` call.
- **No client-side session state.** Own Auth never stores session data in a JWT or client-side token. The session token is an opaque reference to a server-side record. Revocation is instant, with no window where a revoked session remains valid.

## Redirect protection

Magic-link redirect targets are checked against `redirectAllowlist`.

- Relative paths such as `/dashboard` are accepted.
- Absolute URLs must match the origin of an allowed URL.
- Unapproved absolute URLs throw `redirect_not_allowed`.

Configure only destinations controlled by the application. See [Magic Links](/docs/magic-links) for setup.

## Organisation permissions

Organisation reads and mutations verify the actor's active membership and required role permission. This includes members, invitations, organisation API keys, and organisation audit events. Owners and administrators receive explicit permission sets, while members receive only member-level access.

Pass `actorUserId` from the authenticated session. Own Auth performs the organisation permission check inside each operation, so a separate `requirePermission` call is not needed first.

## Rate limiting

Every sensitive operation is rate-limited automatically. You don't enable it, configure it, or write middleware. See [Rate limiting](/docs/rate-limiting) for the full table of limits.

Rate limiting protects against brute-force attacks, credential stuffing, SMS pumping, and abuse of email-sending endpoints.

## Account enumeration protection

Own Auth prevents public authentication responses from revealing which emails or phone numbers are registered:

| Operation | Behavior |
|---|---|
| Magic-link request | Uses the same success response whether or not the email already exists. |
| Password-reset request | Uses the same success response whether or not the email exists. |
| Phone-code request | Uses the same success response whether or not the phone number exists. |
| Sign-in failure | Returns `invalid_credentials`, never separate "email not found" or "wrong password" errors. |

These flows use the same public response shape for known and unknown accounts. Exact response timing is not guaranteed, so Own Auth does not claim timing-based enumeration resistance.

The exception is sign-up. `signUpEmailPassword` throws `email_already_exists` when the email exists because the application must explain why it cannot create the account.

## API-key security

- **Shown once.** The raw API key is returned only at creation. After that, only the visible prefix and safe metadata are available.
- **Hashed in storage.** The full key is hashed before storage, using the same token-hashing protection as session tokens.
- **Prefixed for scanning.** Keys start with `oa_`, giving code-scanning tools a stable pattern for identifying possible leaked keys.
- **Scoped.** Keys can be limited to specific operations through scopes.
- **Revocable.** Keys can be revoked instantly and individually.
- **Never logged.** Raw API keys never appear in Own Auth audit logs or error messages.

## Token pepper

The token pepper (`OWN_AUTH_TOKEN_PEPPER`) adds a secret component to token, session, and API-key hashing. It serves as a defense-in-depth layer:

- Without the pepper, an attacker with database access could attempt offline brute-force attacks against stored hashes.
- With the pepper, the attacker also needs the pepper value, which is stored in the environment rather than the database.

The pepper must be:

- long and random, with at least 32 bytes
- kept secret and never committed to source control
- stable, because changing it invalidates all outstanding tokens, sessions, and API keys

If the pepper may have been compromised, rotate it. Changing the pepper is equivalent to a full token, session, and API-key reset, and recovery is a manual process.

## Audit logs

Supported security-sensitive operations write audit events containing the actor, target user, organisation, API-key record, request context, and event-specific metadata when those values are available.

Own Auth's event writers do not add passwords, raw tokens, SMS codes, API-key values, or the token pepper. Applications must also keep secrets out of their own metadata fields. See [Audit Logs](/docs/audit-logs) for the event list and access-control requirements.

## What Own Auth doesn't do

Own Auth does not:

- **Encrypt data at rest.** User emails, names, and metadata are stored in plain text in the Postgres database. If column-level encryption is required, apply it at the database level.
- **Manage TLS.** Application and database connections must use TLS in production. Own Auth does not configure it.
- **Handle CORS.** Cross-origin request policies are the application's responsibility.
- **Set cookies.** Own Auth returns tokens. The application decides whether to deliver them through cookies, headers, or a response body.
- **Manage secrets.** The token pepper, database URL, provider credentials, and API keys must be secured using the deployment platform's secret management.

## Production checklist

- [ ] `OWN_AUTH_TOKEN_PEPPER` contains a long random secret and is available to every server instance.
- [ ] `DATABASE_URL` points to durable Postgres and uses TLS when required by the provider.
- [ ] Current Own Auth migrations have been applied.
- [ ] `exposeRawTokens` is disabled.
- [ ] Web session cookies use `HttpOnly`, `Secure`, an appropriate `SameSite` value, and explicit expiry.
- [ ] Cookie-based endpoints have an appropriate CSRF strategy.
- [ ] Web auth links use HTTPS, and mobile or desktop link schemes are limited to destinations controlled by the application.
- [ ] `redirectAllowlist` contains only approved application destinations.
- [ ] Real email and SMS providers are configured for the auth methods in use.
- [ ] The default Postgres rate-limit store is active, or a durable `rateLimitStore` is supplied with custom storage.
- [ ] Every `actorUserId` comes from a verified session rather than client input.
- [ ] Audit-log access is restricted and a retention policy has been chosen.
- [ ] Postgres backups, access controls, monitoring, and encryption meet the application's requirements.
