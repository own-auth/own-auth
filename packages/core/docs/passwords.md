# Passwords

Email and password authentication. The most common auth method. Users sign up with an email and a password, and sign in with the same credentials.

## Sign up

```ts
const { user, session, sessionToken } = await auth.signUpEmailPassword({
  email: "alice@example.com",
  password: "her-secret-password",
  name: "Alice",
});
```

This creates a user, hashes the password with Argon2id, creates a session, and returns everything needed to sign the user in immediately.

Send `sessionToken` to the client securely using an `HttpOnly` cookie, a secure header, or the token handling used by the application.

### Fields

| Field | Required | Description |
|---|---|---|
| `email` | Yes | Trimmed and stored lowercase. |
| `password` | Yes | Must meet the minimum length, which defaults to 8 characters. |
| `name` | No | The user's display name. |

### Errors

| Code | When |
|---|---|
| `email_already_exists` | An account with the email already exists. |
| `weak_password` | The password is shorter than the configured minimum. |
| `rate_limited` | Too many sign-up attempts. |

```ts
import { AuthError } from "own-auth";

try {
  const { user, session, sessionToken } = await auth.signUpEmailPassword({
    email,
    password,
    name,
  });
} catch (error) {
  if (!(error instanceof AuthError)) {
    throw error;
  }

  switch (error.code) {
    case "email_already_exists":
      // Show an account-already-exists message.
      break;
    case "weak_password":
      // Show the configured minimum password length.
      break;
  }
}
```

## Sign in

```ts
const { user, session, sessionToken } = await auth.signInEmailPassword({
  email: "alice@example.com",
  password: "her-secret-password",
});
```

Own Auth checks the password against the stored hash. If it matches, it creates a new session and returns the token.

### Errors

| Code | When |
|---|---|
| `invalid_credentials` | The email does not exist or the password is wrong. |
| `disabled_user` | The user has been disabled. |
| `rate_limited` | Too many sign-in attempts. |

`invalid_credentials` is deliberately vague. It never reveals whether the email exists or the password was wrong. This prevents account enumeration.

## Password hashing

Passwords are hashed with Argon2id before storage. This is not configurable. Argon2id is the recommended algorithm for password hashing - it is resistant to GPU attacks, side-channel attacks, and time-memory trade-offs.

Own Auth never stores, logs, or returns plain-text passwords. It uses the raw password only while creating or verifying the hash and does not persist it.

## Changing a password

For authenticated users who want to change their password (not reset it, they know their current password):

```ts
await auth.changePassword({
  sessionToken,
  currentPassword: "old-password",
  newPassword: "new-password",
});
```

Own Auth verifies the current password before updating it. An incorrect current password throws `invalid_credentials`.

After a password change, every other session for the user is revoked. The current session remains valid.

## Password requirements

Configure the minimum password length in the shared Own Auth instance:

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  password: {
    minLength: 10, // default: 8
  },
});
```

Own Auth does not enforce uppercase, number, or symbol rules. Set the minimum length required by the application.

## Next step

Add passwordless login with [Magic links](/docs/magic-links), or learn about [Sessions](/docs/sessions) to understand how users stay signed in.
