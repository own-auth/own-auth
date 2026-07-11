# Email Verification

Confirm that a user owns the email address they signed up with. After sign-up, send a verification email. The user opens the link and their email is marked as verified.

## Send a verification email

```ts
await auth.requestEmailVerification({
  email: "alice@example.com",
});
```

This generates a single-use token, hashes it, and sends an email with a verification link. The link points to your app (or to your hosted page if you use [hosted links](/docs/hosted-auth-links)).

Call it after `signUpEmailPassword` when the application requires email verification:

```ts
const { user, session, sessionToken } = await auth.signUpEmailPassword({
  email,
  password,
  name,
});

await auth.requestEmailVerification({ email });
```

The user is already signed in after sign-up. The application can now show its check-your-email screen.

## Verify the email

When the user opens the link, extract the token and verify it in the backend:

```ts
const user = await auth.verifyEmail({
  token: tokenFromUrl,
});
```

Own Auth consumes the token and sets `user.emailVerifiedAt` to the current time. It does not create another session.

### Errors

| Code | When |
|---|---|
| `expired_token` | The link has expired. The default lifetime is 24 hours. |
| `token_already_used` | The link has already been used. |
| `invalid_token` | The token is malformed, missing, or does not match an email verification token. |

## Checking verification status

```ts
const current = await auth.getCurrentSession(sessionToken);

if (current && !current.user.emailVerifiedAt) {
  // Show a reminder to verify the email address.
}
```

`emailVerifiedAt` is `null` before verification and a `Date` after successful verification.

## Requiring verification

Own Auth does not block sign-in for unverified users. The application decides which features require a verified email address.

```ts
const current = await auth.getCurrentSession(sessionToken);

if (!current) {
  return redirect("/sign-in");
}

if (!current.user.emailVerifiedAt) {
  return redirect("/verify-email");
}

// Continue with the authenticated request.
```

## Resending

Use the same method to send another verification email:

```ts
await auth.requestEmailVerification({ email });
```

Each request creates a new single-use token. Earlier unused links remain valid until they are used or reach their expiry time. Own Auth allows up to five verification-email requests per address every ten minutes.

## How verification tokens are stored

Verification tokens are hashed with the token pepper before storage. The raw token exists only while Own Auth passes it to the email provider. Reading the database does not reveal a usable verification link.

## Configuration

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  tokenTtlMs: {
    email_verification: 24 * 60 * 60 * 1000, // 24 hours
  },
});
```

## Next step

Set up [Password reset](/docs/password-reset) for users who forget their password, or learn about [Sessions](/docs/sessions).
