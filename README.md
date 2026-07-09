# Own Auth

Own your auth. Own your users.

Framework-independent authentication for TypeScript. Backed by Postgres, controlled by you.

```bash
npm install own-auth
```

## Get Started

Run the migration to set up your database.

```bash
export DATABASE_URL=postgres://localhost:5432/your_database
export OWN_AUTH_TOKEN_PEPPER=replace-with-a-long-random-secret
npx own-auth migrate
```

Create your auth instance.

```ts
import { createOwnAuth } from "own-auth";

export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
});
```

Sign up, sign in, sign out.

```ts
const { user } = await auth.signUpEmailPassword({
  email: "user@example.com",
  password: "secure-password",
  name: "Jane",
});

const { sessionToken } = await auth.signInEmailPassword({
  email: "user@example.com",
  password: "secure-password",
});

const { user } = await auth.requireCurrentSession(sessionToken);

await auth.signOut(sessionToken);
```

That's it. You have working auth.

## Providers

Each provider is a single `send` function. Use any email or SMS service you want. Both are optional. Without one configured, tokens log to the console for development.

### Email

Required for magic links, email verification, password reset, and org invites.

```ts
import type { EmailProvider } from "own-auth";

const emailProvider: EmailProvider = {
  async send(message) {
    await emailClient.send({
      from: "auth@yourapp.com",
      to: message.to,
      subject: message.type === "magic_link" ? "Your login link" : "Verify your email",
      html: `<a href="${message.url}">Continue</a>`,
    });
  },
};

export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  baseUrl: "https://yourapp.com",
  emailProvider,
});
```

### SMS

Required for phone/SMS login.

```ts
import type { SmsProvider } from "own-auth";

const smsProvider: SmsProvider = {
  async send(message) {
    await smsClient.send({
      from: "+15550001234",
      to: message.to,
      body: `Your code is ${message.code}`,
    });
  },
};

export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  smsProvider,
});
```

### Managed Email

Skip this if your app sends its own emails. Use this if you want Own Auth to handle delivery for you.

```ts
import { OwnAuthManagedEmailProvider, createOwnAuth } from "own-auth";

export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  baseUrl: "https://yourapp.com",
  emailProvider: new OwnAuthManagedEmailProvider({
    deliveryKey: process.env.OWN_AUTH_EMAIL_DELIVERY_KEY,
  }),
});
```

## Magic Links

Passwordless email login. Own Auth creates a single-use link, hashes the token, and calls your email provider.

```ts
// Request
await auth.requestMagicLink({
  email: "user@example.com",
  redirectUrl: "/dashboard",
});

// Verify
const { user, sessionToken } = await auth.verifyMagicLink({ token });
```

New users are created automatically. Disable with `allowMagicLinkSignup: false`.

## Phone / SMS Login

Six-digit codes, hashed and rate-limited.

```ts
// Request
await auth.requestSmsOtp({ phone: "+15551234567" });

// Verify
const { user, sessionToken } = await auth.verifySmsOtp({
  phone: "+15551234567",
  code: "123456",
});
```

New users are created automatically. Disable with `allowPhoneSignup: false`.

## Email Verification

```ts
await auth.requestEmailVerification({ email: "user@example.com" });
await auth.verifyEmail({ token });
```

## Password Reset

All existing sessions are revoked after a successful reset.

```ts
await auth.requestPasswordReset({ email: "user@example.com" });
await auth.resetPassword({ token, newPassword: "new-secure-password" });
```

## API Keys

Scoped keys for machine-to-machine access. The raw key is returned once. Only the hash is stored.

```ts
const { rawKey } = await auth.createApiKey({
  name: "Production API",
  organisationId: org.id,
  actorUserId: user.id,
  scopes: ["users:read", "users:write"],
});

// rawKey looks like: oa_x8kLm2nQ_...
```

Verify incoming requests.

```ts
const { apiKey, user, organisation } = await auth.verifyApiKey(
  request.headers.authorization,
  ["users:read"]
);
```

Revoke a key.

```ts
await auth.revokeApiKey(apiKey.keyPrefix, user.id);
```

## Organisations

Create organisations, invite members, assign roles.

```ts
const { organisation } = await auth.createOrganisation({
  name: "Acme Inc",
  ownerUserId: user.id,
});

await auth.inviteMember({
  organisationId: organisation.id,
  email: "teammate@example.com",
  invitedByUserId: user.id,
  role: "member",
});

const { user, member } = await auth.acceptInvitation({ token });
```

### Roles and Permissions

Built-in roles: `owner`, `admin`, `member`.

```ts
const allowed = await auth.checkPermission(orgId, userId, "invite_members");

// Or throw if denied
await auth.requirePermission(orgId, userId, "manage_api_keys");
```

### Manage Members

```ts
await auth.changeMemberRole({
  organisationId: orgId,
  memberId: member.id,
  role: "admin",
  actorUserId: currentUser.id,
});

await auth.removeMember({
  organisationId: orgId,
  memberId: member.id,
  actorUserId: currentUser.id,
});
```

## Audit Logs

Every auth action is logged automatically. Sign ups, sign ins, password resets, API key usage, org changes.

```ts
const events = await auth.listAuditEvents({
  userId: user.id,
  organisationId: org.id,
});
```

## Configuration

```ts
createOwnAuth({
  // Required
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,

  // Base URL for email links (default: "http://localhost:3000")
  baseUrl: "https://yourapp.com",

  // Providers (default: log to console)
  emailProvider,
  smsProvider,

  // Signup controls
  allowMagicLinkSignup: true,
  allowPhoneSignup: true,

  // Session durations
  session: {
    ttlMs: 30 * 24 * 60 * 60 * 1000,       // 30 days absolute
    idleTtlMs: 7 * 24 * 60 * 60 * 1000,     // 7 days idle
  },

  // Token expiry
  tokenTtlMs: {
    magic_link: 15 * 60 * 1000,              // 15 minutes
    email_verification: 24 * 60 * 60 * 1000, // 24 hours
    password_reset: 60 * 60 * 1000,          // 1 hour
    organisation_invite: 7 * 24 * 60 * 60 * 1000, // 7 days
  },

  // SMS OTP
  sms: {
    otpTtlMs: 10 * 60 * 1000, // 10 minutes
    maxAttempts: 5,
    codeLength: 6,
  },

  // Password policy
  password: {
    minLength: 8,
  },

  // Security
  redirectAllowlist: ["https://yourapp.com"],

  // Development only. Exposes raw tokens in responses.
  exposeRawTokens: false,
});
```

## Database Setup

Auto-migrate (recommended):

```bash
npx own-auth migrate
```

Or generate SQL and apply it yourself:

```bash
npx own-auth generate --out own-auth.sql
psql "$DATABASE_URL" -f own-auth.sql
```

## Method Reference

| Area | Methods |
|---|---|
| **Users** | `createUser` `signUpEmailPassword` `signInEmailPassword` |
| **Sessions** | `getCurrentSession` `requireCurrentSession` `signOut` `revokeAllSessions` |
| **Magic Links** | `requestMagicLink` `verifyMagicLink` |
| **Email Verification** | `requestEmailVerification` `verifyEmail` |
| **Password Reset** | `requestPasswordReset` `resetPassword` |
| **SMS OTP** | `requestSmsOtp` `verifySmsOtp` |
| **API Keys** | `createApiKey` `verifyApiKey` `revokeApiKey` |
| **Organisations** | `createOrganisation` `updateOrganisation` |
| **Members & Invites** | `inviteMember` `acceptInvitation` `changeMemberRole` `removeMember` |
| **Permissions** | `checkPermission` `requirePermission` |
| **Audit Logs** | `listAuditEvents` |

## Security

- Passwords hashed with scrypt
- Session tokens, magic links, reset tokens, SMS codes, and API keys hashed before storage
- Single-use tokens with expiry
- Rate limiting on all sensitive flows
- Account enumeration protection on reset and verification endpoints
- Redirect URL allowlist for magic links

## Docs

- [Installation](./docs/installation.md)
- [Security Model](./docs/security-model.md)
- [Security Policy](./SECURITY.md)
- [Contributing](./CONTRIBUTING.md)

## Development

```bash
pnpm install
pnpm test
pnpm build
```

## Release

```bash
pnpm run release:publish
```

This runs the release checks, publishes `own-auth`, then creates and pushes the matching Git tag, such as `v0.1.9`.

## License

MIT
