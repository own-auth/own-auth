# Rate Limiting

Own Auth applies built-in rate limits to sensitive authentication entry points. Core limits do not need middleware or separate configuration.

## Built-in limits

| Operation | Identifier | Default limit | Window |
|---|---|---:|---:|
| Sign up | Normalised email | 5 | 10 minutes |
| Password sign in | Normalised email | 10 | 10 minutes |
| Change password | User ID | 5 | 10 minutes |
| TOTP checks for enrollment, login, disabling TOTP, and recovery code regeneration | User ID shared across all four actions and all sessions | 5 | 5 minutes |
| Magic-link request | Normalised email | 5 | 10 minutes |
| Email-verification request | Normalised email | 5 | 10 minutes |
| Password-reset request | Normalised email | 5 | 15 minutes |
| SMS-code request | Normalised phone number | 5 | 15 minutes |
| SMS-code verification | Normalised phone number | 10 | 15 minutes |
| Trusted external-provider sign in | Provider account ID | 20 | 10 minutes |
| OAuth start | IP address, when available | 20 | 10 minutes |
| OAuth callback | IP address, when available | 30 | 10 minutes |
| Google One Tap prepare | IP address, when available | 20 | 10 minutes |
| Google One Tap verify | IP address, when available | 30 | 10 minutes |
| SAML start | IP address and connection, when available | 20 | 10 minutes |
| SAML callback | IP address and connection, when available | 30 | 10 minutes |
| SCIM request | SCIM connection | 1,200 | 1 minute |
| Failed SCIM authentication | IP address, when available | 30 | 1 minute |
| Authorization-server start | IP address, when available | 60 | 10 minutes |
| Authorization-server interaction completion | User ID | 30 | 10 minutes |
| Authorization-server token, revocation, and client introspection endpoints | IP address, otherwise client ID | 120 | 10 minutes |
| Protected-resource introspection | Protected-resource identity | 6,000 | 1 minute |
| Failed protected-resource authentication | IP address, when available | 30 | 1 minute |
| API-key creation | User or organisation owner | 20 | 1 hour |
| Organisation invite | Organisation ID | 10 | 1 hour |

These limits reduce password guessing, credential stuffing, repeated email and SMS sends, excessive invitations, and excessive key creation.

SMS codes allow five wrong guesses by default. MFA challenges also allow five failed attempts by default. These per-credential attempt limits are enforced separately from the shared rate-limit store through `sms.maxAttempts` and `mfa.maxAttempts`.

TOTP also uses one shared per user verification budget. Its allowance is `mfa.maxAttempts` and its window is `mfa.challengeTtlMs`. Every check counts, including successful and replayed codes. The attempt is reserved before decrypting or checking the code. New sessions, enrollments, and login challenges cannot reset it. A store failure rejects the operation before verification or an MFA change.

## What happens when a limit is exceeded

Own Auth throws `AuthError` with:

- `code`: `rate_limited`
- `statusCode`: `429`
- `safeMessage`: `Too many attempts. Try again later.`

```ts
import { isAuthError } from "own-auth";

try {
  await auth.signInEmailPassword({ email, password });
} catch (error) {
  if (isAuthError(error) && error.code === "rate_limited") {
    return res.status(error.statusCode).json({
      error: error.safeMessage,
    });
  }

  throw error;
}
```

`AuthError` does not currently include a `retryAfterMs` value. Do not read or document that field unless the public error contract adds it.

## Default durable store

With the default Postgres setup, Own Auth stores counters in `own_auth_rate_limits` in the same database as the auth data. The Cloudflare D1 adapter uses the same table in D1.

The counters survive server restarts and are shared by every application instance connected to that database. No additional rate-limit configuration is needed for the default setup.

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
});
```

## Configuration

Most built-in core operation limits and windows are not configurable. Protected-resource operators can size remote introspection for their traffic with `authorizationServer.resourceIntrospectionRequestsPerMinute` and `authorizationServer.failedIntrospectionAttemptsPerMinute`. SCIM operators can configure `scim.requestLimit`, `scim.requestWindowMs`, `scim.failedAuthLimit`, and `scim.failedAuthWindowMs`. Authenticated SCIM traffic shares one limit per connection. Failed SCIM authentication is limited only when the handler receives a trusted IP address through `getRequestContext`.

The MFA settings also configure the shared TOTP budget as described above. When supplying custom authentication storage, supply a shared durable `rateLimitStore` too. Process memory cannot preserve counters across application restarts or share them across separate instances.

Plugins may declare their own namespaced endpoint rate limits, but cannot replace or weaken core limits.

## Next step

Set up [Audit logs](/docs/audit-logs) to track auth events, or review the full [Security model](/docs/security-model).
