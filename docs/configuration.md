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
import { createOwnAuth } from "own-auth";

const appUrl = "https://app.example.com";

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
});
```

Storage, rate limiting, email, and SMS can be replaced with adapters through `storage`, `rateLimitStore`, `emailProvider`, and `smsProvider`.

## Configuration reference

### `tokenPepper`

A secret string used when hashing sessions, auth links, SMS codes, and API keys before storing them. If this option is omitted, Own Auth reads `OWN_AUTH_TOKEN_PEPPER` from the environment.

It is required in production. Generate it once, keep it secret, and do not change it unless you intend to invalidate existing sessions, links, codes, and API keys.

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

An array of URLs allowed as absolute magic-link redirect targets. Relative redirect paths are allowed. The default is an array containing `baseUrl`.

## Validation

`createOwnAuth` checks required runtime configuration when the auth instance is created. Without a database connection, it throws:

```text
DATABASE_URL is required. Set DATABASE_URL or pass storage to createOwnAuth().
```

In production, a missing token pepper throws:

```text
OWN_AUTH_TOKEN_PEPPER is required in production.
```

These errors happen when your application starts, before an auth method is called.

## Next step

Start adding auth methods: [Passwords](/docs/passwords), [Magic links](/docs/magic-links), or [Phone login](/docs/phone-login).
