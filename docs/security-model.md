# Security Model

## Passwords

Passwords are hashed with **Argon2id**, the winner of the Password Hashing Competition and the recommended algorithm for new projects. It's resistant to GPU attacks, side-channel attacks, and time-memory trade-offs.

Own Auth never stores, logs, or returns plain-text passwords. The raw password exists in memory only during the hash operation and is discarded immediately after.

The hashing algorithm is not configurable. There's no reason to downgrade to bcrypt or scrypt for new projects.

## Tokens

All tokens, including magic links, password resets, email verification, phone codes, and invites, follow the same security model:

- **Random.** Generated with a cryptographically secure random number generator.
- **Single-use.** Consumed through an atomic storage operation so only one concurrent request can succeed. Every later use fails.
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

Sessions record the authentication methods used, an `aal1` or `aal2` assurance level, and the time authentication completed. Existing sessions are migrated to `authenticationMethods: ["legacy"]` and `assuranceLevel: "aal1"`.

## Multi-factor authentication

TOTP, recovery codes, and passkeys can complete a pending second-factor challenge. The first factor creates a hashed, expiring, attempt-limited challenge instead of a session. A session is created only after the challenge is atomically consumed.

- TOTP uses SHA-1, six digits, 30-second periods, and a one-step clock tolerance.
- A successfully used TOTP timestep is recorded through an atomic comparison update and cannot be reused.
- Recovery codes are random, independently hashed, shown once, and atomically consumed.
- Regenerating recovery codes invalidates every previous code.
- Successful MFA creates an `aal2` session containing both authentication methods.

## Passkeys

WebAuthn registration and authentication validate the expected origin, RP ID, challenge, signature, credential owner, and user-verification result. Challenges are hashed, expiring, and atomically single-use.

Non-zero authenticator counters use atomic comparison updates. Valid multi-device passkeys whose counters remain zero follow WebAuthn's multi-device behavior. Non-discoverable credentials are supported for username-first sign-in and MFA, while usernameless sign-in accepts discoverable credentials only.

## Redirect protection

Magic-link redirect targets are checked against `redirectAllowlist`.

- Relative paths such as `/dashboard` are accepted.
- HTTPS and localhost URLs must match an allowlisted protocol, hostname, port, and path prefix.
- Custom app schemes must match an allowlisted scheme, host, port, and path prefix.
- Plain HTTP is rejected outside localhost.
- Unapproved absolute URLs throw `redirect_not_allowed`.

Configure only destinations controlled by the application. See [Magic Links](/docs/magic-links) for setup.

## OAuth

OAuth redirect transactions store only a peppered state hash, provider, intent, validated destination, interaction mode, opener origin, expiry, and consumption time. State is atomically consumed before the authorization code is exchanged.

PKCE verifier and OIDC nonce values are derived independently from the raw state and are never stored. Google and Apple responses verify signature, issuer, audience, expiry, nonce, subject, and verified-email claims. GitHub identities use the authenticated API response and only verified email addresses.

Explicit provider linking is the default. A matching verified email does not silently link to an existing user unless `oauth.accountLinking` is set to `verified_email`. Unverified emails are never used for account linking.

Popup callbacks post only completion state to the exact stored opener origin. OAuth codes, provider tokens, session tokens, and MFA challenge tokens never enter `postMessage`.

## OAuth and OpenID Connect authorization server

The optional authorization server requires authorization code with PKCE S256. Redirect URIs match the client's registered value exactly.

Interaction handles, authorization codes, access tokens, refresh tokens, and client secrets are random and stored only as peppered hashes. Authorization requests and OIDC nonces are encrypted with authenticated metadata.

Refresh tokens rotate on every use. Reuse revokes the complete grant family, including an access or refresh token created by a concurrent winning request.

ID tokens use RS256 and publish only public key material through JWKS. OIDC subjects are random, stable per user, deleted with the user, and never reassigned.

Unauthenticated interaction reads do not reveal the client or requested scopes. `prompt=select_account` always reaches the interaction page, while `prompt=none` fails instead of showing UI.

See [OAuth And OpenID Connect Authorization Server](/docs/authorization-server) for the protocol and application integration contract.

## Organisation permissions

Organisation reads and mutations verify the actor's active membership and required role permission. This includes members, invitations, organisation API keys, and organisation audit events. Owners and administrators receive explicit permission sets, while members receive only member-level access.

Pass `actorUserId` from the authenticated session. Own Auth performs the organisation permission check inside each operation, so a separate `requirePermission` call is not needed first.

## Rate limiting

Sensitive authentication entry points have built-in rate-limit buckets. OAuth and One Tap IP limits are applied when request IP context is available. MFA challenges and SMS codes also enforce per-credential attempt limits. See [Rate limiting](/docs/rate-limiting) for the full table.

Rate limiting protects against brute-force attacks, credential stuffing, SMS pumping, and abuse of email-sending endpoints.

The Postgres rate-limit store increments counters atomically so concurrent requests cannot bypass a limit by overwriting one another's counts.

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

The token pepper (`OWN_AUTH_TOKEN_PEPPER`) adds a secret component to token, session, API-key, OAuth client-secret, and authorization-server token hashing. It serves as a defense-in-depth layer:

- Without the pepper, an attacker with database access could attempt offline brute-force attacks against stored hashes.
- With the pepper, the attacker also needs the pepper value, which is stored in the environment rather than the database.

The pepper must be:

- long and random, with at least 32 bytes
- kept secret and never committed to source control
- stable, because changing it invalidates all outstanding tokens, sessions, and API keys

If the pepper may have been compromised, rotate it. Changing the pepper is equivalent to a full token, session, and API-key reset, and recovery is a manual process.

## Encryption key ring

TOTP secrets, optional provider refresh credentials, and authorization-server request state use AES-256-GCM with a new 96-bit nonce and authenticated record metadata. HKDF-SHA256 derives separate keys for `own-auth:totp:v1`, `own-auth:oauth-refresh:v1`, and `own-auth:authorization-request:v1`, so ciphertext from one purpose cannot be used as another.

The current key encrypts and decrypts. Previous keys decrypt only, and successful reads rotate old ciphertext to the current key. Unknown key IDs fail closed with `encryption_key_unavailable`.

Access tokens are never persisted. Refresh credentials are stored only when `offlineAccess: true` is configured for a provider and are never exposed through the HTTP handler or browser client.

## Plugins

Plugin routes are namespaced and cannot replace core routes, error identifiers, cookie policy, CSRF behavior, or core security checks. Before-hooks fail closed on denial, errors, rejection, or timeout. After-hooks receive secret-redacted data and cannot change a committed authentication result.

Plugin migrations are checksummed per database dialect. Postgres runs each pending migration in its own transaction. D1 migrations are generated as versioned files and applied transactionally by Wrangler.

## Webhooks

Webhook payloads are signed with endpoint-specific HMAC-SHA256 secrets. The signature covers the stable event ID, delivery timestamp, and exact request bytes. The receiver helper validates the signature and timestamp before returning the event.

Receivers provide an atomic `claimEvent` operation so a repeated event ID is rejected. Webhook events contain a fixed, versioned subset of audit data and never include passwords, session tokens, API-key values, one-time tokens, provider credentials, or arbitrary audit metadata.

Own Auth stores delivery attempts but not response bodies, response headers, or remote error messages. See [Webhooks](/docs/webhooks) for the complete sender and receiver contract.

## Audit logs

Supported security-sensitive operations write audit events containing the actor, target user, organisation, API-key record, request context, and event-specific metadata when those values are available.

Own Auth's event writers do not add passwords, raw tokens, SMS codes, API-key values, or the token pepper. See [Audit Logs](/docs/audit-logs) for the event list and access-control requirements.

## What Own Auth doesn't do

Own Auth does not:

- **Encrypt data at rest.** User emails, names, and metadata are stored in plain text in the configured database. If column-level encryption is required, apply it at the database level.
- **Manage TLS.** Application and database connections must use TLS in production. Own Auth does not configure it.
- **Handle CORS.** Cross-origin request policies are the application's responsibility.
- **Manage secrets.** The token pepper, database URL, provider credentials, and API keys must be secured using the deployment platform's secret management.

## Production checklist

- [ ] `OWN_AUTH_TOKEN_PEPPER` contains a long random secret and is available to every server instance.
- [ ] `DATABASE_URL` points to durable Postgres, or the Worker uses the intended D1 binding.
- [ ] Current Own Auth migrations have been applied.
- [ ] Web session cookies use `HttpOnly`, `Secure`, an appropriate `SameSite` value, and explicit expiry.
- [ ] Cookie-based endpoints have an appropriate CSRF strategy.
- [ ] Web auth links use HTTPS, and mobile or desktop link schemes are limited to destinations controlled by the application.
- [ ] `redirectAllowlist` contains only approved application destinations.
- [ ] Real email and SMS providers are configured for the auth methods in use.
- [ ] The encryption key ring is configured and backed up before enabling TOTP or provider offline access.
- [ ] OAuth callback URLs exactly match the URLs registered with each provider.
- [ ] Passkey RP ID and expected origins exactly match the deployed application.
- [ ] Every configured webhook endpoint has a unique secret of at least 32 bytes.
- [ ] A worker or scheduled job runs `processWebhookDeliveries` when webhooks are enabled.
- [ ] Webhook receivers verify exact request bytes and claim event IDs atomically.
- [ ] The built-in Postgres or D1 rate-limit store is active, or a durable `rateLimitStore` is supplied with custom storage.
- [ ] Every `actorUserId` comes from a verified session rather than client input.
- [ ] Audit-log access is restricted and a retention policy has been chosen.
- [ ] Database backups, access controls, monitoring, and encryption meet the application's requirements.
