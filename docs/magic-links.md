# Magic Links

Passwordless sign-in via email. The user enters their email, receives a link, clicks it, and they are in. No password to remember, no password to steal.

## Send a magic link

```ts
await auth.requestMagicLink({
  email: "alice@example.com",
});
```

This generates a single-use token, hashes it, stores the hash, and sends an email containing a link with the raw token.

By default, Own Auth also sends a link when the email does not belong to an existing user. The user is created only after the link is verified. Set `allowMagicLinkSignup: false` to allow existing users only.

When new-user signup is disabled, an unknown email returns successfully without sending an email. The internal result uses `expiresAt: null`, so backend endpoints should return their own fixed success response instead of exposing the result directly.

### Errors

| Code | When |
|---|---|
| `rate_limited` | Too many magic-link requests for the email address. |
| `redirect_not_allowed` | The requested redirect URL is not allowed. |

### Email delivery

The email is sent through the configured `emailProvider`, which can use any email service, or through Own Auth Delivery. See [Configuration](/docs/configuration) for setup.

### Link format

With `baseUrl` set to `https://myapp.com`, the email points to the application:

```text
https://myapp.com/auth/magic-link/verify?token=abc123...
```

Or if you use hosted links (for mobile apps):

```text
https://go.own-auth.com/your-app/magic?token=abc123...
```

The hosted page opens the configured mobile app destination. See [Hosted Auth Links](/docs/hosted-auth-links) for setup.

## Verify a magic link

When the user opens the link, extract the token and verify it in the backend:

```ts
const { user, session, sessionToken } = await auth.verifyMagicLink({
  token: tokenFromUrl,
});
```

If the token is valid, it is consumed, a session is created, and the user is signed in. The same token cannot be used again.

### Errors

| Code | When |
|---|---|
| `expired_token` | The link has expired. The default lifetime is 15 minutes. |
| `token_already_used` | The link has already been used. |
| `invalid_token` | The token is malformed, missing, or does not match a magic link. |
| `disabled_user` | The user has been disabled. |

```ts
import { AuthError } from "own-auth";

try {
  const { user, session, sessionToken } = await auth.verifyMagicLink({
    token: tokenFromUrl,
  });
} catch (error) {
  if (!(error instanceof AuthError)) {
    throw error;
  }

  switch (error.code) {
    case "expired_token":
      // Show: This link has expired. Request a new one.
      break;
    case "token_already_used":
      // Show: This link has already been used.
      break;
    case "invalid_token":
      // Show: This link is not valid.
      break;
  }
}
```

## How it works

1. The application calls `requestMagicLink({ email })`.
2. Own Auth generates a random token and hashes it with the token pepper.
3. The hash is stored in `own_auth_tokens` with its type, expiry, email, and user ID when one exists.
4. The raw token is placed in the email link but is never stored.
5. The user opens the link and the application sends the token to its backend.
6. The backend calls `verifyMagicLink({ token })`.
7. Own Auth hashes the incoming token and looks up the matching database record.
8. If the token exists, has not expired, and has not been consumed, Own Auth consumes it and creates a session.

The raw token never exists in the database. Reading `own_auth_tokens` does not reveal a usable magic link.

## Auto-creating users

Magic links create new users by default. The user is created when a valid link is verified, not when the email is sent.

To restrict magic-link sign-in to existing users:

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  allowMagicLinkSignup: false,
});
```

## Configuration

```ts
const appUrl = "https://myapp.com";

const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  baseUrl: appUrl,
  redirectAllowlist: [appUrl],
  tokenTtlMs: {
    magic_link: 15 * 60 * 1000, // 15 minutes
  },
});
```

Keep the lifetime short because a magic link grants access to the account. The default is 15 minutes.

## Next step

Add phone-based login with [Phone login](/docs/phone-login), or learn about [Email verification](/docs/email-verification) for confirming user emails after sign-up.
