# Own Auth

Own your auth. Own your users.

Framework-independent authentication for TypeScript, with auth data that stays under your control.

## Quickstart

Get your first login working in under five minutes. You need Node.js 20+ and a Postgres database.

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
const result = await auth.signInEmailPassword({
  email: "alice@example.com",
  password: "her-secret-password",
});

if (result.status === "mfa_required") {
  // Show one of result.methods and complete the second factor.
} else {
  // result.sessionToken      -> send this to the client securely
  // result.session.userId    -> "usr_a1b2c3..."
  // result.session.expiresAt -> 2026-08-09T...
}
```

For users without MFA, sign-in completes immediately and the session token identifies the user on future requests. Send it to the client as a cookie, a header, or however your application handles tokens. Users with MFA receive `status: "mfa_required"` and no session until they complete a second factor.

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

### Use The HTTP Handler

Applications that want ready-made auth endpoints can mount one framework-neutral Web handler:

```ts auth-handler.ts
import { createOwnAuthHandler } from "own-auth/http";

import { auth } from "./auth";

export const authHandler = createOwnAuthHandler(auth);
```

The handler provides signup, signin, sessions, signout, password flows, magic links, email verification, SMS verification, invitation acceptance, OAuth, SAML SSO, MFA, and passkeys under `/api/auth`. It sets secure `HttpOnly` cookies, checks browser request origins, and returns one documented error format.

Browser TypeScript can use the matching client:

```ts auth-client.ts
import { createOwnAuthClient } from "own-auth/client";

export const authClient = createOwnAuthClient();
```

React applications can use the matching client and session hook from `own-auth/react`:

```tsx auth-client.ts
import { createOwnAuthReactClient } from "own-auth/react";

export const authClient = createOwnAuthReactClient();

// Inside a component:
// const { data, isPending, error } = authClient.useSession();
```

See the [HTTP handler](./docs/http-handler.md) and [TypeScript client](./docs/typescript-client.md) guides for the complete route and error contract.

### What's Next

You have basic email/password auth. Here is where to go next:

**Auth methods**: Add passwordless login with [magic links](https://own-auth.com/docs/magic-links), or phone-based login with [SMS verification](https://own-auth.com/docs/phone-login).

**OAuth**: Add Google, GitHub, or Apple through [OAuth and external providers](https://own-auth.com/docs/external-providers).

**OAuth server**: Let other applications authorize users through the [OAuth and OpenID Connect server](https://own-auth.com/docs/authorization-server), including [device authorization](https://own-auth.com/docs/device-authorization) for command-line tools and input-limited devices.

**Enterprise SSO**: Connect an organisation identity provider through [SAML SSO](https://own-auth.com/docs/saml).

**Enterprise provisioning**: Provision organisation users and memberships through [SCIM](https://own-auth.com/docs/scim).

**MFA and passkeys**: Add [TOTP and recovery codes](https://own-auth.com/docs/mfa), or use [passkeys](https://own-auth.com/docs/passkeys) for sign-in and MFA.

**Sessions**: Learn how [session management](https://own-auth.com/docs/sessions) works, including revoking sessions across devices.

**Organisations**: Add [teams, roles, and invitations](https://own-auth.com/docs/organisations) for multi-tenant applications.

**API access for integrations**: Issue scoped [application API keys](https://own-auth.com/docs/api-keys) for programmatic access to your application's API.

**Email delivery**: Set up your own email provider, or use [Own Auth Delivery](https://own-auth.com/docs/sending-email) to send magic links, verification emails, and invitations without configuring SMTP.

**Security**: Read the [security model](https://own-auth.com/docs/security-model) to understand hashing, token expiry, rate limiting, and audit logs.

**Extensions**: Add namespaced behavior through the public [plugin contract](https://own-auth.com/docs/plugins).

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
const result = await auth.verifyMagicLink({ token });

if (result.status === "mfa_required") {
  // Complete a configured second factor before creating a session.
}
```

The app reads the token from the link, verifies it, saves the returned session, and then opens `redirectUrl`.

New users are created automatically. Disable with `allowMagicLinkSignup: false`.

`redirectUrl` supports allowlisted HTTPS links, localhost development URLs, and app links such as `myapp://settings`. Relative paths are also accepted.

## Phone / SMS Login

Six-digit codes, hashed and rate-limited.

```ts
// Request
await auth.requestSmsOtp({ phone: "+15551234567" });

// Verify
const result = await auth.verifySmsOtp({
  phone: "+15551234567",
  code: "123456",
});

if (result.status === "mfa_required") {
  // Complete a configured second factor before creating a session.
}
```

New users are created automatically. Disable with `allowPhoneSignup: false`.

## OAuth And External Providers

Own Auth includes Google, GitHub, and Apple redirect OAuth, popup OAuth, and Google One Tap. Native SDKs can still pass a provider identity that a trusted backend adapter has already verified.

```ts
const result = await auth.signInWithVerifiedExternalIdentity({
  provider: "google",
  providerAccountId: googleUser.sub,
  email: googleUser.email,
  emailVerified: googleUser.email_verified === true
});
```

Own Auth resolves the linked provider account, applies the configured account-linking policy, and either creates a session or returns `mfa_required`.

`signInWithVerifiedExternalIdentity` does not verify a provider token. Only call it after a trusted provider adapter has verified the token signature, issuer, audience, expiry, and nonce where required. See [External providers](./docs/external-providers.md).

## SAML SSO

Enable organisation-scoped SAML 2.0 sign-in through the separate protocol export:

```ts
import { createOwnAuth } from "own-auth";
import { createSaml } from "own-auth/saml";

export const auth = createOwnAuth({
  baseUrl: "https://auth.example.com",
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  saml: createSaml(),
});
```

Run `npx own-auth migrate`, create a connection through `auth.saml.createConnection`, and give the identity provider the generated metadata URL. See [SAML SSO](./docs/saml.md) for connection management, identity linking, JIT provisioning, request signing, and the HTTP flow.

## SCIM Provisioning

Enable organisation-scoped SCIM 2.0 provisioning and mount its separate protocol handler:

```ts
import { createOwnAuth } from "own-auth";
import { createOwnAuthScimHandler } from "own-auth/scim";

export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  scim: {},
});

export const scimHandler = createOwnAuthScimHandler(auth);
```

Organisation owners create connections and one-time-visible bearer tokens through `auth.scim`. SCIM creates and updates organisation memberships without deleting or disabling the global Own Auth user account. See [SCIM Provisioning](./docs/scim.md) for connection setup, account linking, SAML pairing, restoration, and the supported protocol surface.

## OAuth And OpenID Connect Authorization Server

Own Auth can also act as the OAuth and OpenID Connect server for other applications. This is separate from signing in with Google, GitHub, or Apple.

Configure `authorizationServer`, create clients through `auth.authorizationServer`, and mount the separate framework-neutral protocol handler:

```ts
import { createOwnAuthAuthorizationServerHandler } from "own-auth/authorization-server";

export const authorizationHandler =
  createOwnAuthAuthorizationServerHandler(auth);
```

The server supports authorization code with PKCE, signed ID tokens, opaque access tokens, rotating refresh tokens, optional DPoP token binding, revocation, protected-resource introspection, userinfo, discovery, JWKS, consent, account selection, and AAL2 step-up. See [OAuth And OpenID Connect Authorization Server](./docs/authorization-server.md) and [Protected Resources](./docs/protected-resources.md).

## Multi-Factor Authentication

TOTP, one-time recovery codes, and passkeys can protect every first-factor flow. No session is created until MFA succeeds. See [Multi-Factor Authentication](./docs/mfa.md).

## Passkeys

Passkeys support usernameless or username-first primary sign-in and can complete pending MFA challenges. See [Passkeys](./docs/passkeys.md).

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

Built-in roles are `owner`, `admin`, and `member`. Applications can add typed roles and permissions:

```ts
import { createOwnAuth, defineOwnAuthAuthorization } from "own-auth";

const authorization = defineOwnAuthAuthorization({
  permissions: ["documents:read", "documents:write"],
  roles: {
    reviewer: ["view_members", "documents:read"],
  },
});

const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  authorization,
});
```

```ts
const allowed = await auth.checkPermission(orgId, userId, "invite_members");

// Or throw if denied
await auth.requirePermission(orgId, userId, "manage_api_keys");
```

See [Roles and permissions](./docs/organisations/roles.md) for owner protections, role-removal behavior, and migration guidance.

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

## Webhooks

Configure signed authentication events and run the delivery processor from an application worker or scheduled job:

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

await auth.processWebhookDeliveries();
```

See [Webhooks](./docs/webhooks.md) for signature verification, retries, attempt history, cleanup, and custom storage requirements.

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
});
```

OAuth providers, the shared encryption key ring, TOTP, passkeys, plugins, and webhooks are documented in the [Configuration guide](./docs/configuration.md).

Privileged support workflows are available through the optional, application-authorized [`auth.admin` namespace](./docs/administration.md).

For long-running servers, close Own Auth during graceful shutdown:

```ts
await auth.close();
```

Own Auth closes only the Postgres pool it creates. Applications that pass custom storage or rate-limit adapters remain responsible for those resources. See [Database connection and shutdown](./docs/configuration.md#database-connection-and-shutdown).

## Postgres Database Setup

Auto-migrate (recommended):

```bash
npx own-auth migrate
```

Own Auth saves users, sessions, tokens, API keys, organisations, rate-limit attempts, and configured webhook delivery history in Postgres.

Or generate SQL and apply it yourself:

```bash
npx own-auth generate --out own-auth.sql
psql "$DATABASE_URL" -f own-auth.sql
```

## Cloudflare D1

Cloudflare Workers can use the explicit D1 adapter for both auth data and rate limits:

```ts auth.ts
import { createOwnAuth } from "own-auth";
import { createD1Persistence } from "own-auth/d1";

export const auth = createOwnAuth({
  ...createD1Persistence(env.DB),
  tokenPepper: env.OWN_AUTH_TOKEN_PEPPER,
});
```

Generate versioned migrations for Wrangler:

```bash
npx own-auth generate --dialect d1 --out-dir migrations
```

See [Cloudflare D1](./docs/cloudflare-d1.md) for the complete Worker and migration setup.

## OpenTelemetry

Own Auth emits privacy-safe traces and metrics through `@opentelemetry/api`. Applications with an OpenTelemetry SDK configured receive operation, HTTP handler, provider, email/SMS delivery, webhook delivery, plugin, and rate-limit telemetry. Without an SDK, telemetry is a no-op.

Telemetry is controlled by the application's OpenTelemetry SDK, not by a `createOwnAuth()` option. Own Auth never records passwords, tokens, request bodies, URLs, headers, cookies, delivery contents, or database queries.

See [Observability](./docs/observability.md) for span hierarchy, metric names, attributes, and data-safety rules.

## Method Reference

### Methods

| Area | Methods |
|---|---|
| **Users** | `createUser` `signUpEmailPassword` `signInEmailPassword` `disableUser` `enableUser` |
| **Sessions** | `getCurrentSession` `requireCurrentSession` `signOut` `revokeSession` `revokeAllSessions` `listSessions` |
| **Magic Links** | `requestMagicLink` `verifyMagicLink` |
| **OAuth** | `createOAuthAuthorizationUrl` `completeOAuthSignIn` `linkOAuthProvider` `unlinkOAuthProvider` `prepareGoogleOneTap` `signInWithGoogleOneTap` `signInWithVerifiedExternalIdentity` |
| **SAML** | `auth.saml.createConnection` `auth.saml.getConnection` `auth.saml.listConnections` `auth.saml.updateConnection` `auth.saml.disableConnection` `auth.saml.enableConnection` `auth.saml.createSignInUrl` `auth.saml.createLinkUrl` `auth.saml.unlinkIdentity` `auth.saml.getMetadata` |
| **SCIM** | `auth.scim.createConnection` `auth.scim.getConnection` `auth.scim.listConnections` `auth.scim.updateConnection` `auth.scim.disableConnection` `auth.scim.enableConnection` `auth.scim.createToken` `auth.scim.listTokens` `auth.scim.revokeToken` `auth.scim.linkUser` `auth.scim.restoreUser` |
| **Provider Credentials** | `getExternalAccessToken` `revokeExternalProviderAccess` |
| **MFA** | `beginTotpEnrollment` `confirmTotpEnrollment` `completeMfaWithTotp` `completeMfaWithRecoveryCode` `regenerateRecoveryCodes` `disableTotp` |
| **Passkeys** | `beginPasskeyRegistration` `completePasskeyRegistration` `beginPasskeyAuthentication` `completePasskeyAuthentication` `listPasskeys` `renamePasskey` `revokePasskey` |
| **Email Verification** | `requestEmailVerification` `verifyEmail` |
| **Passwords** | `requestPasswordReset` `resetPassword` `changePassword` |
| **SMS OTP** | `requestSmsOtp` `verifySmsOtp` |
| **API Keys** | `createApiKey` `verifyApiKey` `revokeApiKey` `listApiKeys` |
| **Organisations** | `createOrganisation` `getOrganisation` `updateOrganisation` `deleteOrganisation` `listOrganisations` |
| **Members & Invites** | `getMember` `listMembers` `inviteMember` `acceptInvite` `revokeInvitation` `listInvitations` `changeMemberRole` `removeMember` |
| **Permissions** | `checkPermission` `requirePermission` |
| **Audit Logs** | `listAuditEvents` `cleanupAuditLogs` |
| **Administration** | `auth.admin.listUsers` `auth.admin.getUser` `auth.admin.listUserSessions` `auth.admin.listUserAuditEvents` `auth.admin.disableUser` `auth.admin.enableUser` `auth.admin.revokeUserSessions` |
| **Authorization Server** | `auth.authorizationServer.createClient` `auth.authorizationServer.listClients` `auth.authorizationServer.updateClient` `auth.authorizationServer.rotateClientSecret` `auth.authorizationServer.revokeClient` `auth.authorizationServer.createProtectedResource` `auth.authorizationServer.listProtectedResources` `auth.authorizationServer.updateProtectedResource` `auth.authorizationServer.rotateProtectedResourceSecret` `auth.authorizationServer.revokeProtectedResource` `auth.authorizationServer.getInteraction` `auth.authorizationServer.approveInteraction` `auth.authorizationServer.denyInteraction` `auth.authorizationServer.verifyAccessToken` `auth.authorizationServer.listUserGrants` `auth.authorizationServer.revokeUserGrant` `auth.authorizationServer.cleanupDpopProofs` |
| **Webhooks** | `processWebhookDeliveries` `listWebhookDeliveries` `retryWebhookDelivery` `cleanupWebhookDeliveries` |
| **Plugins** | `callPluginMethod` plus methods and endpoints declared by configured plugins |
| **Lifecycle** | `close` |

## Security

- New passwords are hashed with Argon2id; legacy scrypt hashes are upgraded after a successful sign in
- Session tokens, magic links, reset tokens, SMS codes, and API keys are hashed before storage
- Single-use tokens with expiry
- Atomic OAuth state, One Tap nonce, MFA challenge, recovery-code, and WebAuthn challenge consumption
- TOTP timestep and passkey counter replay protection
- Purpose-separated AES-256-GCM encryption for TOTP and optional provider refresh credentials
- Built-in rate limiting for password, email, SMS, OAuth, invitation, and API-key flows
- Account enumeration protection on reset and verification endpoints
- Redirect URL allowlist for magic links and OAuth destinations
- HMAC-SHA256 webhook signatures with timestamp validation and receiver-owned replay claims
- Optional DPoP-bound OAuth tokens with method, URL, access-token hash, timestamp, and atomic proof-replay verification
- Connection-scoped SCIM tokens are shown once, stored as peppered hashes, rate-limited, and rejected when revoked, expired, or disabled

Report suspected vulnerabilities through the private process in
[Security Policy](./SECURITY.md#reporting-a-vulnerability). Do not open a public
issue for an undisclosed vulnerability.

## Docs

- [Installation](./docs/installation.md)
- [Security Model](./docs/security-model.md)
- [OAuth And External Providers](./docs/external-providers.md)
- [SAML SSO](./docs/saml.md)
- [SCIM Provisioning](./docs/scim.md)
- [OAuth And OpenID Connect Authorization Server](./docs/authorization-server.md)
- [Protected Resources](./docs/protected-resources.md)
- [Multi-Factor Authentication](./docs/mfa.md)
- [Passkeys](./docs/passkeys.md)
- [Plugins](./docs/plugins.md)
- [Cloudflare D1](./docs/cloudflare-d1.md)
- [Webhooks](./docs/webhooks.md)
- [Observability](./docs/observability.md)
- [Administration](./docs/administration.md)
- [Next.js](./docs/frameworks/nextjs.md)
- [Express](./docs/frameworks/express.md)
- [Hono](./docs/frameworks/hono.md)
- [Fastify](./docs/frameworks/fastify.md)
- [Security Policy](./SECURITY.md)
- [Contributing](./CONTRIBUTING.md)

## Development

```bash
pnpm install
pnpm test
pnpm build
```

## Release

Maintainers publish through an explicit npm channel:

```bash
pnpm release:stable
pnpm release:next
```

Stable versions use npm's `latest` tag. Versions such as `0.4.0-next.0` use the
`next` tag without changing `latest`. See [Contributing](./CONTRIBUTING.md#release)
for the release checks and recovery commands.

## License

MIT
