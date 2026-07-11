# Session Management

Sessions are how users stay signed in between requests. When a user signs in, Own Auth creates a session and returns a token. That token is sent with each later request to identify the user.

## How sessions work

1. The user signs in with a password, magic link, phone code, or external provider.
2. Own Auth creates a row in `own_auth_sessions` containing a hashed token, the user ID, activity timestamps, and expiry timestamps.
3. The raw session token is returned to the application so it can be sent to the client.
4. On later requests, the client sends the token back and the backend calls `getCurrentSession`.

The raw token is never stored in the database. Only its hash is stored, so reading the sessions table does not reveal a usable session token.

## Create a session

Signup and signin methods create a session automatically:

```ts
const { user, session, sessionToken } = await auth.signInEmailPassword({
  email: "alice@example.com",
  password: "her-secret-password",
});
```

`sessionToken` is the raw token. `session` is the stored session record, and `user` is the signed-in user.

## Read the current session

```ts
const current = await auth.getCurrentSession(sessionToken);

// current -> {
//   user: {
//     id: "usr_...",
//     email: "alice@example.com",
//     name: "Alice",
//   },
//   session: {
//     id: "ses_...",
//     userId: "usr_...",
//     lastActiveAt: new Date("2026-07-11T..."),
//     expiresAt: new Date("2026-08-10T..."),
//   },
// }

if (!current) {
  return res.status(401).json({ error: "Not signed in" });
}

const { user, session } = current;
```

`getCurrentSession` returns `null` when the token is unknown, expired, revoked, or belongs to a disabled user. It does not throw. A successful check updates `session.lastActiveAt` and extends the idle expiry.

Use `requireCurrentSession` when the request must be authenticated:

```ts
const { user, session } = await auth.requireCurrentSession(sessionToken);
```

It throws `AuthError` with the code `invalid_session` when the token cannot be used.

## List sessions

```ts
const current = await auth.requireCurrentSession(sessionToken);
const sessions = await auth.listSessions({
  actorUserId: current.user.id,
});

// sessions -> [
//   {
//     id: "ses_...",
//     userId: "usr_...",
//     createdAt: new Date("2026-07-11T..."),
//     lastActiveAt: new Date("2026-07-11T..."),
//     expiresAt: new Date("2026-08-10T..."),
//     revokedAt: null,
//   },
// ]
```

Each session includes its ID, creation time, last activity, absolute and idle expiry, optional request metadata, and revocation state. The list includes active, expired, and revoked session records. Use `revokedAt`, `expiresAt`, and `idleExpiresAt` when displaying only active sessions.

## Sign out

```ts
await auth.signOut(sessionToken);
```

Own Auth marks the session as revoked. The token stops working immediately, while the session row remains available for audit and security history.

## Revoke a specific session

Use the current session token and the ID of a session returned by `listSessions`:

```ts
const revoked = await auth.revokeSession({
  sessionToken,
  sessionId,
});
```

Own Auth authenticates `sessionToken` and confirms that `sessionId` belongs to the same user before revoking it. A session owned by another user returns `invalid_session` and is not changed.

This supports active-device screens where a signed-in user can revoke one other session. It can also revoke the current session when its own ID is supplied.

## Revoke every session

```ts
const current = await auth.requireCurrentSession(sessionToken);
const revokedCount = await auth.revokeAllSessions({
  actorUserId: current.user.id,
});
```

This revokes every session for the signed-in user that has not already been revoked. It is useful after a security concern or when the user chooses to sign out every device. Password resets and disabled accounts also revoke all sessions automatically.

## Session metadata

Pass request metadata when signing in or signing up:

```ts
const { user, session, sessionToken } = await auth.signInEmailPassword({
  email,
  password,
  request: {
    ipAddress: req.ip,
    userAgent: req.headers["user-agent"],
  },
});
```

Own Auth stores the IP address and user agent with the session. Applications can use them to help users recognise their active devices.

## Session timeouts

Own Auth applies two expiry limits:

- **Absolute timeout (`ttlMs`)**: The session expires after a fixed duration, regardless of activity. The default is 30 days.
- **Idle timeout (`idleTtlMs`)**: The session expires after a period without a successful session check. The default is 7 days.

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  session: {
    ttlMs: 30 * 24 * 60 * 60 * 1000, // 30 days
    idleTtlMs: 7 * 24 * 60 * 60 * 1000, // 7 days
  },
});
```

The session expires when either limit is reached. `getCurrentSession` extends only the idle expiry. It never extends the absolute expiry.

## Token storage

### On the server

Own Auth hashes session tokens with the token pepper before storing them in Postgres.

### In a web application

Send the token using an `HttpOnly` cookie:

```ts
res.cookie("session", sessionToken, {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  maxAge: 30 * 24 * 60 * 60 * 1000,
});
```

### In a mobile or API application

Return the token to the client and store it using the platform's secure credential storage:

```ts
res.json({ sessionToken });
```

Own Auth returns the token but does not set cookies or choose client storage. This keeps the auth engine independent from application frameworks and client platforms.

## Next step

Learn about [Organisations](/docs/organisations) to add teams, roles, and invites.
