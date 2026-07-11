# Own Auth

Own your auth. Own your users.

Framework-independent authentication for TypeScript. Backed by Postgres, controlled by you.

## Quickstart

Get your first login working in under five minutes. You need Node.js 18+ and a Postgres database.

### Install

```bash
npm install own-auth
```

### Set Your Environment Variables

Add your Postgres connection string and token pepper to your environment.

```bash .env
DATABASE_URL=postgres://user:password@localhost:5432/myapp
OWN_AUTH_TOKEN_PEPPER=your-random-secret-string
```

The token pepper adds an extra layer of protection to hashed tokens in your database. Generate a long random string and keep it secret.

Any Postgres database works: local, hosted, Supabase, Neon, Railway, or RDS. Own Auth creates its own tables and does not modify yours.

### Run Migrations

```bash
npx own-auth migrate
```

This creates the tables Own Auth needs: users, sessions, tokens, organisations, API keys, and audit logs. Your existing tables are not modified.

Run this once during setup.

Verify the database connection and migration version:

```bash
npx own-auth status
```

### Create Your Auth Instance

Create an `auth.ts` file in your project. This is the single entry point for all auth operations.

```ts auth.ts
import { createOwnAuth } from "own-auth";

export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  session: {
    ttlMs: 30 * 24 * 60 * 60 * 1000, // 30 days
  },
});
```

That is your auth layer. Every function in this guide is called on this `auth` instance. Own Auth reads `DATABASE_URL` automatically.

### Sign Up A User

```ts signup.ts
const { user, session, sessionToken } = await auth.signUpEmailPassword({
  email: "alice@example.com",
  password: "her-secret-password",
  name: "Alice",
});

// user.id           -> "usr_a1b2c3..."
// user.email        -> "alice@example.com"
// user.name         -> "Alice"
// sessionToken      -> send this to the client securely
// session.expiresAt -> 2026-08-09T...
```

The password is hashed before it is stored. Own Auth never saves plain-text passwords. The session is created automatically, so the user is signed in as soon as they sign up.

If the email is already taken, `signUpEmailPassword` throws a typed error you can catch and handle:

```ts signup.ts
import { AuthError } from "own-auth";

try {
  const { user, session, sessionToken } = await auth.signUpEmailPassword({
    email,
    password,
    name,
  });
} catch (error) {
  if (error instanceof AuthError && error.code === "email_already_exists") {
    // Handle the duplicate email.
  }
  throw error;
}
```

### Sign In

```ts signin.ts
const { user, session, sessionToken } = await auth.signInEmailPassword({
  email: "alice@example.com",
  password: "her-secret-password",
});

// sessionToken      -> send this to the client securely
// session.userId    -> "usr_a1b2c3..."
// session.expiresAt -> 2026-08-09T...
```

The session token identifies the user on future requests. Send it to the client as a cookie, a header, or however your application handles tokens.

If the credentials are wrong, `signInEmailPassword` throws `AuthError` with the code `invalid_credentials`. The error deliberately does not reveal whether the email or password was wrong.

### Verify A Session

On every authenticated request, verify the session token to identify the user.

```ts session.ts
const result = await auth.getCurrentSession(sessionToken);

if (!result) {
  // Not signed in. Return 401.
}

// result.session.userId -> "usr_a1b2c3..."
// result.user            -> { id, email, name, ... }
```

`getCurrentSession` checks the token against the database. If the session is expired or has been revoked, it returns `null`.

### Sign Out

```ts
await auth.signOut(sessionToken);
```

The session is revoked immediately. The token stops working on the next request.

### Full Example

Here is everything together in a minimal script. No framework, just plain TypeScript. Swap in Express, Hono, Fastify, or whatever you use.

```ts server.ts
import { auth } from "./auth";

// Sign up.
const { sessionToken } = await auth.signUpEmailPassword({
  email: "alice@example.com",
  password: "her-secret-password",
  name: "Alice",
});

// Send sessionToken to the client as a cookie, header, or another secure value.

// Later, verify the session on an incoming request.
const result = await auth.getCurrentSession(sessionToken);

if (result) {
  console.log("Signed in as", result.user.email);
}

// Sign out.
await auth.signOut(sessionToken);
```

That is it. Users, passwords, and sessions are working. Everything is in your Postgres database, under your control.

### What's Next

You have basic email/password auth. Here is where to go next:

**Auth methods**: Add passwordless login with [magic links](https://own-auth.com/docs/magic-links), or phone-based login with [SMS verification](https://own-auth.com/docs/phone-login).

**Sessions**: Learn how [session management](https://own-auth.com/docs/sessions) works, including revoking sessions across devices.

**Organisations**: Add [teams, roles, and invitations](https://own-auth.com/docs/organisations) for multi-tenant applications.

**API access for integrations**: Issue scoped [application API keys](https://own-auth.com/docs/api-keys) for programmatic access to your application's API.

**Email delivery**: Set up your own email provider, or use [Own Auth Delivery](https://own-auth.com/docs/sending-email) to send magic links, verification emails, and invitations without configuring SMTP.

**Security**: Read the [security model](https://own-auth.com/docs/security-model) to understand hashing, token expiry, rate limiting, and audit logs.

**Framework guides**: See integration guides for [Next.js](https://own-auth.com/docs/frameworks/nextjs), [Express](https://own-auth.com/docs/frameworks/express), [Hono](https://own-auth.com/docs/frameworks/hono), and [Fastify](https://own-auth.com/docs/frameworks/fastify).

## Sessions

Sessions are stored in Postgres, tied to a user, and revocable at any time.

### Get The Current Session

```ts session.ts
const current = await auth.getCurrentSession(sessionToken);

if (!current) {
  // Not signed in. Return 401.
}

console.log(current.user.email);
```

Use `requireCurrentSession` when authentication is required. It throws `AuthError` with the code `invalid_session` when the token cannot be used.

```ts
const { user, session } = await auth.requireCurrentSession(sessionToken);
```

### List Sessions

```ts
const sessions = await auth.listSessions({
  actorUserId: current.user.id,
});
```

Session records include creation, expiry, activity, and revocation state.

### Revoke Sessions

```ts
await auth.signOut(sessionToken);

await auth.revokeSession({
  sessionToken,
  sessionId,
});

const revokedCount = await auth.revokeAllSessions({
  actorUserId: current.user.id,
});
```

Revocation takes effect immediately.

### Configure Expiry

```ts auth.ts
export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  session: {
    ttlMs: 30 * 24 * 60 * 60 * 1000,   // 30 days
    idleTtlMs: 7 * 24 * 60 * 60 * 1000 // 7 days
  }
});
```

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

const appLink = "replace-with-the-url-your-app-handles";

export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  baseUrl: appLink,
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

const appLink = "replace-with-the-url-your-app-handles";

export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  baseUrl: appLink,
  emailProvider: new OwnAuthManagedEmailProvider({
    deliveryKey: process.env.OWN_AUTH_EMAIL_DELIVERY_KEY,
  }),
});
```

Managed delivery uses `https://api.own-auth.com/v1/email` by default.

## Magic Links

Passwordless email login. Own Auth creates a single-use link to the app, hashes the token, and calls the email provider.

Set `baseUrl` to the URL the app handles for auth links. That can be a route, universal link, deep link, or any other callback URL owned by the app.

```ts
// Request
await auth.requestMagicLink({
  email: "user@example.com",
  redirectUrl: "/dashboard",
});

// Verify
const { user, sessionToken } = await auth.verifyMagicLink({ token });
```

The app reads the token from the link, verifies it, saves the returned session, and then opens `redirectUrl`.

New users are created automatically. Disable with `allowMagicLinkSignup: false`.

`redirectUrl` supports any URL in your `redirectAllowlist`, including mobile deep links like `myapp://settings`.

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

## External Provider Sign In

After your backend verifies an Apple or Google token, pass the verified provider identity to Own Auth.

```ts
const { user, sessionToken } = await auth.signInWithExternalProvider({
  provider: "google",
  providerAccountId: googleUser.sub,
  email: googleUser.email,
  emailVerified: googleUser.email_verified === true
});
```

Own Auth links the provider account, creates or finds the user, creates the session, and writes the audit events.

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

## Change Password

For signed-in users who know their current password.

```ts
await auth.changePassword({
  sessionToken,
  currentPassword: "current-password",
  newPassword: "new-secure-password"
});
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
const authorization = request.headers.authorization ?? "";
const rawKey = authorization.replace(/^Bearer\s+/i, "");

const { apiKey, user, organisation } = await auth.verifyApiKey(rawKey, [
  "users:read",
]);
```

Revoke a key.

```ts
await auth.revokeApiKey({
  keyPrefix: apiKey.keyPrefix,
  actorUserId: currentUser.id,
});
```

## Organisations

Create organisations, invite members, assign roles.

```ts
const { organisation } = await auth.createOrganisation({
  name: "Acme Inc",
  ownerUserId: user.id,
});

const currentOrganisation = await auth.getOrganisation({
  organisationId: organisation.id,
  actorUserId: currentUser.id,
});

await auth.inviteMember({
  organisationId: organisation.id,
  email: "teammate@example.com",
  invitedByUserId: user.id,
  role: "member",
});

const { member } = await auth.acceptInvite({
  token,
  userId: signedInUser.id,
});

await auth.deleteOrganisation({
  organisationId: organisation.id,
  actorUserId: user.id,
});
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
  userId: targetUser.id,
  role: "admin",
  actorUserId: currentUser.id,
});

await auth.removeMember({
  organisationId: orgId,
  userId: targetUser.id,
  actorUserId: currentUser.id,
});
```

## Audit Logs

Every auth action is logged automatically. Sign ups, sign ins, password resets, API key usage, org changes.

```ts
const events = await auth.listAuditEvents({
  organisationId: org.id,
  actorUserId: currentUser.id,
});
```

## Configuration

```ts
const appLink = "replace-with-the-url-your-app-handles";

createOwnAuth({
  // Required
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,

  // URL the app handles for auth links
  baseUrl: appLink,

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
  redirectAllowlist: [appLink],

  // Development only. Exposes raw tokens in responses.
  exposeRawTokens: false,
});
```

## Database Setup

Auto-migrate (recommended):

```bash
npx own-auth migrate
```

Own Auth saves users, sessions, tokens, API keys, organisations, and rate-limit attempts in Postgres.

Or generate SQL and apply it yourself:

```bash
npx own-auth generate --out own-auth.sql
psql "$DATABASE_URL" -f own-auth.sql
```

## Method Reference

### Methods

| Area | Methods |
|---|---|
| **Users** | `createUser` `signUpEmailPassword` `signInEmailPassword` `disableUser` `enableUser` |
| **Sessions** | `getCurrentSession` `requireCurrentSession` `signOut` `revokeSession` `revokeAllSessions` `listSessions` |
| **Magic Links** | `requestMagicLink` `verifyMagicLink` |
| **External Providers** | `signInWithExternalProvider` |
| **Email Verification** | `requestEmailVerification` `verifyEmail` |
| **Passwords** | `requestPasswordReset` `resetPassword` `changePassword` |
| **SMS OTP** | `requestSmsOtp` `verifySmsOtp` |
| **API Keys** | `createApiKey` `verifyApiKey` `revokeApiKey` `listApiKeys` |
| **Organisations** | `createOrganisation` `getOrganisation` `updateOrganisation` `deleteOrganisation` `listOrganisations` |
| **Members & Invites** | `getMember` `listMembers` `inviteMember` `acceptInvite` `revokeInvitation` `listInvitations` `changeMemberRole` `removeMember` |
| **Permissions** | `checkPermission` `requirePermission` |
| **Audit Logs** | `listAuditEvents` `cleanupAuditLogs` |

## Security

- New passwords are hashed with Argon2id; legacy scrypt hashes are upgraded after a successful sign in
- Session tokens, magic links, reset tokens, SMS codes, and API keys hashed before storage
- Single-use tokens with expiry
- Rate limiting on all sensitive flows
- Account enumeration protection on reset and verification endpoints
- Redirect URL allowlist for magic links

## Docs

- [Installation](https://github.com/tina-li-xx/own-auth/blob/main/docs/installation.md)
- [Security Model](https://github.com/tina-li-xx/own-auth/blob/main/docs/security-model.md)
- [Next.js](https://github.com/tina-li-xx/own-auth/blob/main/docs/frameworks/nextjs.md)
- [Express](https://github.com/tina-li-xx/own-auth/blob/main/docs/frameworks/express.md)
- [Hono](https://github.com/tina-li-xx/own-auth/blob/main/docs/frameworks/hono.md)
- [Fastify](https://github.com/tina-li-xx/own-auth/blob/main/docs/frameworks/fastify.md)
- [Security Policy](https://github.com/tina-li-xx/own-auth/blob/main/SECURITY.md)
- [Contributing](https://github.com/tina-li-xx/own-auth/blob/main/CONTRIBUTING.md)

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
