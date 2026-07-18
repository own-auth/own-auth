# Configuration

Create an `auth.ts` file in your project. This is the single entry point for all auth operations.

## Basic configuration

```ts
// auth.ts
import { createOwnAuth } from "own-auth";

export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  session: {
    ttlMs: 30 * 24 * 60 * 60 * 1000, // 30 days
  },
});
```

Own Auth reads `DATABASE_URL` from the environment. That is enough to get started. Everything below is optional.

## Full configuration

```ts
import { createOwnAuth, defineOwnAuthAuthorization } from "own-auth";
import { createSaml } from "own-auth/saml";

const appUrl = "https://app.example.com";
const authorization = defineOwnAuthAuthorization({
  permissions: ["documents:read", "documents:write"],
  roles: {
    reviewer: ["view_members", "documents:read"],
    editor: ["view_members", "documents:read", "documents:write"],
  },
});

export const auth = createOwnAuth({
  // Required in production
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,

  // Base URL used to create auth links
  baseUrl: appUrl,

  // Session settings
  session: {
    ttlMs: 30 * 24 * 60 * 60 * 1000,     // absolute timeout: 30 days
    idleTtlMs: 7 * 24 * 60 * 60 * 1000, // idle timeout: 7 days
  },

  // Password settings
  password: {
    minLength: 8,
  },

  // Magic link, email verification, password reset, and invite expiry
  tokenTtlMs: {
    magic_link: 15 * 60 * 1000,                   // 15 minutes
    email_verification: 24 * 60 * 60 * 1000,     // 24 hours
    password_reset: 60 * 60 * 1000,              // 1 hour
    organisation_invite: 7 * 24 * 60 * 60 * 1000, // 7 days
  },

  // Application-defined organisation roles and permissions
  authorization,

  // Phone and SMS settings
  sms: {
    otpTtlMs: 10 * 60 * 1000, // 10 minutes
    codeLength: 6,             // 6 digits
    maxAttempts: 5,            // 5 wrong attempts
  },

  // Signup controls
  allowMagicLinkSignup: true,
  allowPhoneSignup: true,

  // Redirect security
  redirectAllowlist: [appUrl],

  // Google, GitHub, and Apple redirect OAuth
  oauth: {
    accountLinking: "explicit",
    providers: {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID!,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        redirectUri: "https://api.example.com/api/auth/oauth/google/callback",
      },
    },
  },

  // Organisation-scoped SAML 2.0 sign-in
  saml: createSaml(),

  // Organisation-scoped SCIM 2.0 provisioning
  scim: {},

  // Shared encryption for TOTP and optional OAuth refresh credentials
  encryption: {
    current: {
      id: "2026-01",
      key: process.env.OWN_AUTH_ENCRYPTION_KEY!,
    },
  },

  // Multi-factor authentication
  mfa: {
    issuer: "My App",
    challengeTtlMs: 5 * 60 * 1000,
    maxAttempts: 5,
    recoveryCodeCount: 10,
  },

  // Passkeys and WebAuthn
  passkeys: {
    rpId: "example.com",
    rpName: "My App",
    origins: [appUrl],
  },
});
```

Storage, rate limiting, email, and SMS can be replaced with adapters through `storage`, `rateLimitStore`, `emailProvider`, and `smsProvider`.

## Configuration reference

### `tokenPepper`

A secret string used when hashing sessions, auth links, SMS codes, API keys, OAuth client secrets, authorization codes, and OAuth access and refresh tokens before storing them. If this option is omitted, Own Auth reads `OWN_AUTH_TOKEN_PEPPER` from the environment.

It is required in production. Generate it once, keep it secret, and do not change it unless you intend to invalidate existing sessions, links, codes, API keys, OAuth client secrets, and authorization-server tokens.

### `baseUrl`

| Type | Default | Description |
|---|---|---|
| `string` | `http://localhost:3000` | Base URL used to create magic links, verification links, password reset links, and invitation links. |

### `session`

| Option | Type | Default | Description |
|---|---|---|---|
| `ttlMs` | `number` | `2592000000` (30 days) | Maximum session lifetime in milliseconds. |
| `idleTtlMs` | `number` | `604800000` (7 days) | Session idle timeout. Verifying an active session extends this deadline. |

### `password`

| Option | Type | Default | Description |
|---|---|---|---|
| `minLength` | `number` | `8` | Minimum password length. |

New passwords are hashed with Argon2id. Existing scrypt hashes remain valid and are upgraded to Argon2id after a successful sign in. The hashing algorithm is not configurable.

### Magic links

| Option | Type | Default | Description |
|---|---|---|---|
| `tokenTtlMs.magic_link` | `number` | `900000` (15 minutes) | How long a magic link is valid. |
| `allowMagicLinkSignup` | `boolean` | `true` | Create a user when a valid magic link is used for an unknown email address. |

### Email verification

| Option | Type | Default | Description |
|---|---|---|---|
| `tokenTtlMs.email_verification` | `number` | `86400000` (24 hours) | How long an email verification link is valid. |

### Password reset

| Option | Type | Default | Description |
|---|---|---|---|
| `tokenTtlMs.password_reset` | `number` | `3600000` (1 hour) | How long a password reset link is valid. |

### Phone and SMS

| Option | Type | Default | Description |
|---|---|---|---|
| `sms.otpTtlMs` | `number` | `600000` (10 minutes) | How long an SMS code is valid. |
| `sms.codeLength` | `number` | `6` | Number of digits in the code. |
| `sms.maxAttempts` | `number` | `5` | Wrong attempts allowed before the code is invalidated. |
| `allowPhoneSignup` | `boolean` | `true` | Create a user when a valid phone login code is used for an unknown number. |
| `smsProvider` | `SmsProvider` | `ConsoleSmsProvider` | Sends phone login and verification codes. |

### Invitations

| Option | Type | Default | Description |
|---|---|---|---|
| `tokenTtlMs.organisation_invite` | `number` | `604800000` (7 days) | How long an organisation invitation is valid. |

### Organisation authorization

Use `authorization` to add application-specific roles and permissions. The built-in `owner`, `admin`, and `member` roles remain available. Custom roles can reference built-in permissions and configured custom permissions.

```ts
const authorization = defineOwnAuthAuthorization({
  permissions: ["documents:read", "documents:write"],
  roles: {
    reviewer: ["view_members", "documents:read"],
    editor: ["view_members", "documents:read", "documents:write"],
  },
});

const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  authorization,
});
```

The factory preserves these literal role and permission names in TypeScript. Every Own Auth instance sharing a database must use the same definition. Before removing a role, reassign its members; an unconfigured stored role has no permissions, and pending invitations for it fail with `role_not_configured`.

See [Roles](/docs/organisations/roles) for identifier rules, owner protections, and migration guidance.

### Administration

Administration is disabled unless `administration.authorize` is configured. The callback connects Own Auth to the application's system-level staff or support permissions.

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  administration: {
    authorize: ({ actor, action, targetUserId }) =>
      canUseAuthAdministration({
        actorUserId: actor.id,
        action,
        targetUserId,
      }),
  },
});
```

Organisation roles do not grant system administration access. Returning `false`, throwing, or rejecting denies the operation. See [Administration](/docs/administration) for actions, methods, HTTP routes, audit behavior, and rate limits.

### Email

Configure `emailProvider` to send auth emails using any email service. This is not needed if you use Own Auth Delivery.

| Option | Type | Default | Description |
|---|---|---|---|
| `emailProvider` | `EmailProvider` | `ConsoleEmailProvider` | Sends magic links, verification links, password reset links, and invitations. |

The console provider is for development and does not send emails. Use [Own Auth Delivery](/docs/delivery/setup) for managed auth email delivery.

### Managed delivery

Use Own Auth Delivery to send magic links, verification links, password reset links, and invitations without connecting your own email service. See the [Delivery setup guide](/docs/delivery/setup).

```ts
import { OwnAuthManagedEmailProvider, createOwnAuth } from "own-auth";

export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  emailProvider: new OwnAuthManagedEmailProvider({
    deliveryKey: process.env.OWN_AUTH_EMAIL_DELIVERY_KEY,
  }),
});
```

| Option | Type | Description |
|---|---|---|
| `deliveryKey` | `string` | Delivery key from the Own Auth dashboard. |

### `redirectAllowlist`

An array of allowed magic-link and OAuth destination targets. The default contains `baseUrl`.

Accepted targets:

- HTTPS URLs and universal links, such as `https://app.example.com/auth`
- Local development URLs, such as `http://localhost:3000/auth`
- Custom app schemes, such as `myapp://auth`
- Relative paths beginning with one slash, such as `/dashboard`

HTTP is rejected outside localhost. Absolute targets must match an allowlisted protocol, hostname, port, and path prefix. For example, allowlisting `myapp://auth` accepts `myapp://auth/magic` but not `evilapp://auth/magic` or `myapp://other/magic`.

### OAuth

Configure Google, GitHub, and Apple under `oauth.providers`. Each provider needs a registered callback URL that points to the matching Own Auth HTTP-handler endpoint.

| Option | Type | Default | Description |
|---|---|---|---|
| `oauth.accountLinking` | `"explicit" \| "verified_email"` | `"explicit"` | Require an existing user to deliberately link a provider, or automatically link a verified matching email. |
| `oauth.providers.google` | `GoogleOAuthOptions` | none | Google redirect OAuth and Google One Tap. |
| `oauth.providers.github` | `GitHubOAuthOptions` | none | GitHub redirect OAuth. |
| `oauth.providers.apple` | `AppleOAuthOptions` | none | Apple redirect OAuth using `form_post`. |
| `oauth.adapters` | `OAuthProviderAdapter[]` | `[]` | Additional trusted provider adapters. |
| `oauth.fetch` | `typeof fetch` | `globalThis.fetch` | Optional fetch implementation for provider requests. |

`offlineAccess: true` is opt-in per provider. It requires `encryption` and stores only the encrypted refresh credential. Access tokens remain server-only and are never persisted.

See [OAuth And External Providers](/docs/external-providers) for provider-specific setup and account-linking behavior.

### SAML SSO

SAML is disabled unless the separate provider is added to the auth instance:

```ts
import { createOwnAuth } from "own-auth";
import { createSaml } from "own-auth/saml";

export const auth = createOwnAuth({
  baseUrl: "https://auth.example.com",
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  saml: createSaml(),
});
```

| Option | Type | Default | Description |
|---|---|---|---|
| `basePath` | `string` | `/api/auth` | Path containing the SAML start, callback, and metadata routes. It must match the HTTP handler base path. |
| `clockSkewMs` | `number` | `120000` | Allowed difference between the identity provider and application clocks. |
| `responseTtlMs` | `number` | `300000` | Maximum lifetime of a SAML authentication transaction. |
| `maxResponseBytes` | `number` | `65536` | Maximum decoded SAML response size. |

Connections are managed through `auth.saml`. Only organisation owners can create, read, update, enable, or disable them. Request signing is optional and requires the shared `encryption` key ring because Own Auth encrypts the signing private key.

See [SAML SSO](/docs/saml) for identity-provider setup, account linking, JIT membership provisioning, request signing, HTTP routes, and security behavior.

### SCIM provisioning

SCIM is disabled unless the `scim` option is present:

```ts
export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  scim: {},
});
```

| Option | Type | Default | Description |
|---|---|---|---|
| `requestLimit` | `number` | `1200` | Authenticated SCIM requests allowed per connection in one window. |
| `requestWindowMs` | `number` | `60000` | Authenticated request window. |
| `failedAuthLimit` | `number` | `30` | Failed bearer-token attempts allowed per IP address when IP context is available. |
| `failedAuthWindowMs` | `number` | `60000` | Failed-authentication window. |

Connections and bearer tokens are managed through `auth.scim`. Only organisation owners can manage them. Mount the separate handler from `own-auth/scim` at `/scim/v2/*`.

See [SCIM Provisioning](/docs/scim) for the supported User lifecycle, account-linking rules, optional SAML pairing, restoration, and protocol endpoints.

### OAuth and OpenID Connect authorization server

`authorizationServer` makes the application an OAuth 2.1 and OpenID Connect provider for other applications. It is separate from `oauth`, which signs users into the application with Google, GitHub, or Apple.

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  encryption: {
    current: {
      id: "2026-01",
      key: process.env.OWN_AUTH_ENCRYPTION_KEY!,
    },
  },
  authorizationServer: {
    issuer: "https://auth.example.com",
    interactionUrl: "https://auth.example.com/authorize",
    signingKeys: {
      current: {
        id: "2026-01",
        privateKey: process.env.OWN_AUTH_SIGNING_PRIVATE_KEY!,
      },
    },
    resourceIntrospectionRequestsPerMinute: 6_000,
    failedIntrospectionAttemptsPerMinute: 30,
    dpop: {
      proofTtlMs: 5 * 60 * 1_000,
      clockSkewMs: 60 * 1_000,
    },
    deviceAuthorization: {
      verificationUrl: "https://auth.example.com/device",
      ttlMs: 10 * 60 * 1_000,
      pollingIntervalSeconds: 5,
    },
  },
});
```

| Option | Type | Default | Description |
|---|---|---|---|
| `resourceIntrospectionRequestsPerMinute` | `number` | `6000` | Authenticated introspection requests shared by every instance using one protected-resource identity. |
| `failedIntrospectionAttemptsPerMinute` | `number` | `30` | Failed protected-resource authentication attempts allowed per IP address. |
| `dpop.proofTtlMs` | `number` | `300000` | Maximum age of a DPoP proof before clock skew is applied. |
| `dpop.clockSkewMs` | `number` | `60000` | Allowed client and server clock difference for DPoP proof timestamps. |
| `deviceAuthorization.verificationUrl` | `string` | - | Application page where users enter and approve a device code. |
| `deviceAuthorization.ttlMs` | `number` | `600000` | Device and user code lifetime. |
| `deviceAuthorization.pollingIntervalSeconds` | `number` | `5` | Initial minimum token polling interval in seconds. |

The authorization-server schema starts with migrations `011_authorization_server`, `012_protected_resources`, and `013_dpop`. Device authorization additionally uses `016_device_authorization`. The shared encryption key ring protects stored protocol requests. DPoP and device authorization remain optional. See [OAuth And OpenID Connect Authorization Server](/docs/authorization-server), [Device Authorization](/docs/device-authorization), and [Protected Resources](/docs/protected-resources).

### Encryption

The shared encryption key ring protects TOTP secrets, optional external-provider refresh credentials, OAuth authorization-server request state, and optional SAML request-signing keys.

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  encryption: {
    current: {
      id: "2026-01",
      key: process.env.OWN_AUTH_ENCRYPTION_KEY!,
    },
    previous: [{
      id: "2025-01",
      key: process.env.OWN_AUTH_PREVIOUS_ENCRYPTION_KEY!,
    }],
  },
});
```

Each key must be a 32-byte `Uint8Array` or a base64url string that decodes to exactly 32 bytes. Generate a base64url key with Node.js 20:

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

`current` encrypts and decrypts. Entries in `previous` decrypt only. Records read with a previous key are re-encrypted with the current key. Removing a key while records still use it causes `encryption_key_unavailable`.

Key IDs must be unique, non-empty, and at most 64 characters. Enabling `offlineAccess` without this encryption configuration fails when the auth instance is created.

### Multi-factor authentication

| Option | Type | Default | Description |
|---|---|---|---|
| `mfa.issuer` | `string` | `Own Auth` | Issuer shown by authenticator applications. |
| `mfa.challengeTtlMs` | `number` | `300000` (5 minutes) | How long a pending second-factor challenge remains valid. |
| `mfa.maxAttempts` | `number` | `5` | Failed attempts allowed before a challenge is unusable. |
| `mfa.recoveryCodeCount` | `number` | `10` | Recovery codes generated after TOTP confirmation. |

The numeric MFA options must be positive integers. TOTP enrollment requires `encryption`. See [Multi-Factor Authentication](/docs/mfa).

### Passkeys

| Option | Type | Description |
|---|---|---|
| `passkeys.rpId` | `string` | WebAuthn relying-party domain. |
| `passkeys.rpName` | `string` | Product name shown by the authenticator. |
| `passkeys.origins` | `string[]` | Exact browser origins allowed to complete WebAuthn ceremonies. |
| `passkeys.timeoutMs` | `number` | Registration and authentication timeout. Default: `60000` (60 seconds). |

See [Passkeys](/docs/passkeys) for registration, primary sign-in, and MFA usage.

### Plugins

Install plugins on the auth instance through `plugins`. The default before-hook timeout is five seconds and can only be shortened:

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  plugins: [examplePlugin],
  pluginRuntime: {
    beforeHookTimeoutMs: 2_000,
    onAfterHookError(error, details) {
      reportPluginError(error, details);
    },
  },
});
```

See [Plugins](/docs/plugins) for the public extension and migration contract.

### Webhooks

Configure signed authentication events under `webhooks`:

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  webhooks: {
    endpoints: [{
      id: "application-events",
      url: process.env.OWN_AUTH_WEBHOOK_URL!,
      secret: process.env.OWN_AUTH_WEBHOOK_SECRET!,
      events: ["user.signed_up", "password.changed"],
    }],
  },
});
```

| Option | Type | Description |
|---|---|---|
| `webhooks.endpoints[].id` | `string` | Stable endpoint identifier containing 1 to 64 safe characters. |
| `webhooks.endpoints[].url` | `string \| URL` | HTTPS endpoint or HTTP loopback URL. |
| `webhooks.endpoints[].secret` | `string` | Signing secret containing at least 32 UTF-8 bytes. |
| `webhooks.endpoints[].events` | `WebhookEventType[]` | Core events sent to this endpoint. |
| `webhooks.fetch` | `typeof fetch` | Optional fetch implementation. Defaults to `globalThis.fetch`. |

Own Auth queues subscribed events but does not start a background worker. See [Webhooks](/docs/webhooks) for processing, signature verification, retries, cleanup, and custom storage requirements.

## Database connection and shutdown

Postgres is the default persistence path. `createOwnAuth` validates `DATABASE_URL` when the auth instance is created, then loads the Postgres driver and opens the database connection only when the first database operation runs.

Cloudflare Workers can instead pass the explicit persistence returned by `createD1Persistence(env.DB)`. See [Cloudflare D1](/docs/cloudflare-d1).

For long-running servers, close the auth instance during graceful shutdown:

```ts
await auth.close();
```

`close` waits for an in-progress first connection, closes the Postgres pool created by Own Auth, and is safe to call more than once. Auth methods called afterward reject with an `AuthError` whose code is `auth_closed`.

Do not call `close` after every request. Serverless and edge runtimes should keep the auth instance reusable across requests. When `storage` or `rateLimitStore` is supplied by the application, Own Auth does not manage its lifecycle. Cloudflare owns D1 bindings, so the D1 adapter has nothing to close.

## Validation

`createOwnAuth` checks required runtime configuration when the auth instance is created. Without `DATABASE_URL` or an explicit storage adapter, it throws:

```text
DATABASE_URL is required. Set DATABASE_URL or pass storage to createOwnAuth().
```

In production, a missing token pepper throws:

```text
OWN_AUTH_TOKEN_PEPPER is required in production.
```

These errors happen when your application starts, before an auth method is called.

A malformed or non-Postgres database URL also fails immediately:

```text
DATABASE_URL must be a valid postgres:// or postgresql:// connection URL.
```

Driver import and database connection errors happen on the first database operation and retain the original PostgreSQL error and code.

## Next step

Start adding auth methods: [Passwords](/docs/passwords), [Magic links](/docs/magic-links), or [Phone login](/docs/phone-login).
