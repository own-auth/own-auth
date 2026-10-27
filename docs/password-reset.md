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

Own Auth validates the token, hashes the new password, atomically consumes the token, updates the user, and revokes every existing session for the account. A validation or hashing failure leaves the token unused so the reset can be retried. The user must sign in again with the new password.

Every successful password replacement invalidates all earlier reset links, including a link whose verification started before the replacement completed. This applies to password resets and authenticated password changes. Request a fresh link after changing the password. A failed password write leaves existing reset authority unchanged. Upgrading the format of a password hash during sign in preserves reset links.

## Upgrade and storage requirements

Apply core migration `019_password_reset_version` before using this update with Postgres or D1. It invalidates outstanding reset links issued before the upgrade. Users can request a fresh link through the existing reset request action. Existing records cannot establish whether those links survived an earlier password change, so they cannot safely remain valid.

The migration adds an internal password reset version to each user and token. Issuing a reset token captures the current version in the same storage statement. Password replacement advances the user's version in the same atomic operation that writes the password. Verifying a reset checks its recorded version against the current user inside the ownership operation. Older records remain stored without being marked as used. Neither timestamps nor password hash differences decide whether a link remains valid.

Custom adapters must implement `updatePasswordAtomically`, capture `AuthToken.passwordResetVersion` during issuance, and reject unused reset authority from earlier versions during lookup, consumption, and atomic ownership claims. Authenticated replacements and hash upgrades must compare the current stored hash with `expectedPasswordHash` before writing. The `replacement` purpose advances the version even when the resulting hash is identical. The `rehash` purpose preserves the version because it upgrades the format of the same password. Use this operation for password updates instead of a generic user patch.

Keep the version columns and checks when rolling back unrelated changes. Older application code that ignores these versions can accept invalidated links again.

### Why all sessions are revoked

For a pending email, pass the original account's `sessionToken` from trusted request credentials to retain that account. The HTTP handler supplies it automatically. Without original account proof, a pending email with prior credentials or access is assigned a separate verified user ID with only the new password. Earlier credentials and data stay with the original account, which loses the email and its sessions. Already verified accounts retain their ID. See [Email ownership](/docs/security-model#email-ownership).

If the password was compromised, an active session could belong to an attacker. Revoking every session forces everyone, including a potential attacker, to authenticate again.

### Errors

| Code | When |
|---|---|
| `expired_token` | The link has expired. The default lifetime is one hour. |
| `token_already_used` | The link has already been used. |
| `invalid_token` | The token is malformed, missing, or invalidated by a password replacement or the upgrade. |
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
import { isAuthError } from "own-auth";

const { token, newPassword } = req.body;

try {
  await auth.resetPassword({ token, newPassword });
  res.json({ message: "Password updated. Sign in with your new password." });
} catch (error) {
  if (!isAuthError(error)) {
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
