# Introduction

## What you get

**Auth methods** - Email/password, magic links, and phone/SMS login. Each method is independent: use one, use all, or add more later.

**Sessions** - Database-backed sessions with expiry, idle timeout, and per-device revocation. Session tokens are hashed before storage.

**Organisations** - Teams, workspaces, or tenants. Members, roles (owner, admin, member), and email invites. Built in from the start, not bolted on later.

**API keys** - Let your users create API keys to access your product programmatically. Keys are shown once, stored hashed, scoped, and revocable.

**Security defaults** - Passwords are hashed with Argon2id. Legacy scrypt hashes are upgraded after a successful sign in. Tokens are single-use and expiring. Sensitive auth actions are rate limited. Security-sensitive auth events are recorded in audit logs. You do not configure these: they work by default.

## What this is not

Own Auth is not a hosted service. There is no login page we host for you, no user database we manage, and no dashboard where you look up your users. Your backend runs the auth. Your database stores the data. Your code controls the flow.

Own Auth Delivery is the one optional managed service. It sends auth emails (magic links, verification, password resets, and invites) so you do not have to configure SMTP. Delivery does not touch your users or sessions. It sends an email containing a link.

## How it works

```bash
npm install own-auth          # install the package
npx own-auth migrate          # create tables in your Postgres database
```

Then in your code:

```ts
import { createOwnAuth } from "own-auth";

const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  session: {
    ttlMs: 30 * 24 * 60 * 60 * 1000, // 30 days
  },
});

const { user, sessionToken } = await auth.signUpEmailPassword({
  email: "alice@example.com",
  password: "her-password",
  name: "Alice",
});
```

No account to create. No API key to generate. No third-party server to call. Auth is in your app.

## Next step

Follow the [Quickstart](/docs/quickstart) to get your first login working in under five minutes.
