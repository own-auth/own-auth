# Password Reset

Let users set a new password when they have forgotten their current one. The user enters their email, receives a reset link, opens it, and enters a new password.

## Send a reset email

```ts
await auth.requestPasswordReset({
  email: "alice@example.com",
});
```

This generates a single-use token and sends an email with a reset link. When the email does not exist, the method returns successfully without sending email. Do not expose its internal `expiresAt` result. Return the same fixed response from the backend for known and unknown email addresses.

## Reset the password

When the user opens the link and reaches the reset form, collect their new password and submit it with the token:

```ts
await auth.resetPassword({
  token: tokenFromUrl,
  newPassword: "her-new-password",
});
```

Own Auth verifies and consumes the token, hashes the new password, updates the user, and revokes every existing session for the account. The user must sign in again with the new password.

### Why all sessions are revoked

If the password was compromised, an active session could belong to an attacker. Revoking every session forces everyone, including a potential attacker, to authenticate again.

### Errors

| Code | When |
|---|---|
| `expired_token` | The link has expired. The default lifetime is one hour. |
| `token_already_used` | The link has already been used. |
| `invalid_token` | The token is malformed, missing, or does not match a password-reset token. |
| `weak_password` | The new password is shorter than the configured minimum length. |

## Full example

### Request page

```ts
const { email } = req.body;

await auth.requestPasswordReset({ email });

res.json({
  message: "If that email exists, we sent a reset link.",
});
```

Always return the same message, whether or not the email belongs to a user.

### Reset page

```ts
import { AuthError } from "own-auth";

const { token, newPassword } = req.body;

try {
  await auth.resetPassword({ token, newPassword });
  res.json({ message: "Password updated. Sign in with your new password." });
} catch (error) {
  if (!(error instanceof AuthError)) {
    throw error;
  }

  switch (error.code) {
    case "expired_token":
      res.status(400).json({ error: "This link has expired. Request a new one." });
      break;
    case "token_already_used":
      res.status(400).json({ error: "This link has already been used." });
      break;
    case "weak_password":
      res.status(400).json({ error: "The new password is too short." });
      break;
    default:
      res.status(400).json({ error: "This reset request is not valid." });
  }
}
```

## Sign in after reset

`resetPassword` does not create a session. After a successful reset, send the user to the sign-in page so they can authenticate with the new password.

## Configuration

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  tokenTtlMs: {
    password_reset: 60 * 60 * 1000, // 1 hour
  },
});
```

Keep the lifetime short because a password-reset token can change the password without the current password.

## Next step

Learn about [Sessions](/docs/sessions) to understand how users stay signed in.
