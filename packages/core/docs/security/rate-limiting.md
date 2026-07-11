# Rate Limiting

Own Auth rate-limits every sensitive operation automatically. You don't configure individual limits, enable middleware, or write rate-limiting code. It's built in.

## Built-in limits

| Operation | Identifier | Default limit | Window |
|---|---|---:|---:|
| Sign up | Normalised email | 5 | 10 minutes |
| Password sign in | Normalised email | 10 | 10 minutes |
| Change password | User ID | 5 | 10 minutes |
| Magic-link request | Normalised email | 5 | 10 minutes |
| Email-verification request | Normalised email | 5 | 10 minutes |
| Password-reset request | Normalised email | 5 | 15 minutes |
| SMS-code request | Normalised phone number | 5 | 15 minutes |
| SMS-code verification | Normalised phone number | 10 | 15 minutes |
| External-provider sign in | Provider account ID | 20 | 10 minutes |
| API-key creation | User or organisation owner | 20 | 1 hour |
| Organisation invite | Organisation ID | 10 | 1 hour |

These limits reduce password guessing, credential stuffing, repeated email and SMS sends, excessive invitations, and excessive key creation.

SMS codes also allow five wrong guesses by default. After that, the code cannot be verified and a new code must be requested. This per-code attempt limit is configured separately through `sms.maxAttempts`.

## What happens when a limit is exceeded

Own Auth throws `AuthError` with:

- `code`: `rate_limited`
- `statusCode`: `429`
- `safeMessage`: `Too many attempts. Try again later.`

```ts
import { AuthError } from "own-auth";

try {
  await auth.signInEmailPassword({ email, password });
} catch (error) {
  if (error instanceof AuthError && error.code === "rate_limited") {
    return res.status(error.statusCode).json({
      error: error.safeMessage,
    });
  }

  throw error;
}
```

`AuthError` does not currently include a `retryAfterMs` value. Do not read or document that field unless the public error contract adds it.

## Default Postgres store

When `DATABASE_URL` is configured, Own Auth stores counters in `own_auth_rate_limits` in the same Postgres database as the auth data.

The counters survive server restarts and are shared by every application instance connected to that database. No additional rate-limit configuration is needed for the default setup.

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
});
```

## Configuration

The built-in operation limits and windows are not configurable. This avoids accidentally weakening authentication protections in the current release.

## Next step

Set up [Audit logs](/docs/audit-logs) to track auth events, or review the full [Security model](/docs/security-model).
