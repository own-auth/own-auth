# Multi-Factor Authentication

Own Auth supports TOTP authenticator apps, one-time recovery codes, and passkeys as a second factor.

## Configure encryption

TOTP secrets require the shared encryption key ring. Generate a 32-byte base64url key and keep it on the server.

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  encryption: {
    current: {
      id: "2026-01",
      key: process.env.OWN_AUTH_ENCRYPTION_KEY!,
    },
    previous: process.env.OWN_AUTH_PREVIOUS_ENCRYPTION_KEY
      ? [{
          id: "2025-01",
          key: process.env.OWN_AUTH_PREVIOUS_ENCRYPTION_KEY!,
        }]
      : [],
  },
  mfa: {
    issuer: "My App",
  },
});
```

The current key encrypts new records. Previous keys decrypt existing records so Own Auth can re-encrypt them with the current key after a successful read.

## Authenticator attempt limit

All TOTP checks share one budget per user, including enrollment confirmation, login, disabling TOTP, and regenerating recovery codes. The default allows five checks per five minutes. The allowance uses `mfa.maxAttempts` and the window uses `mfa.challengeTtlMs`. Each check reserves an attempt before decrypting or validating a code. Successful checks and replayed codes count too.

Switching sessions, starting another enrollment, or requesting another login challenge does not reset the budget. Requests beyond the allowance return `rate_limited` with HTTP 429. Wait until the existing window expires before trying again. The login challenge also retains its own attempt and expiry checks.

The budget uses the configured `rateLimitStore`. Postgres and D1 persistence helpers supply a database store shared across instances. Applications supplying custom storage must also supply a shared durable rate limit store for production. An unavailable store rejects the operation before checking the code or changing MFA.

## Enroll TOTP

```ts
const enrollment = await auth.beginTotpEnrollment({ sessionToken });
// Show enrollment.uri as a QR code or let the user enter enrollment.secret.

const { recoveryCodes } = await auth.confirmTotpEnrollment({
  sessionToken,
  factorId: enrollment.factorId,
  code: codeFromAuthenticator,
});
```

The factor becomes active only after a valid six-digit code confirms it. Recovery codes are generated at that point and returned once. Store them somewhere safe.

## Handle sign-in results

Passwords, magic links, SMS, OAuth, Google One Tap, and verified external identities return the same result union:

```ts
const result = await auth.signInEmailPassword({ email, password });

if (result.status === "mfa_required") {
  // Keep result.challengeToken on the server.
  return showMfaForm(result.methods, result.expiresAt);
}

const { user, session, sessionToken } = result;
```

No session is created while the result is `mfa_required`.

Complete the challenge with TOTP or a recovery code:

```ts
const completed = await auth.completeMfaWithTotp({
  challengeToken,
  code,
});
```

```ts
const completed = await auth.completeMfaWithRecoveryCode({
  challengeToken,
  code: recoveryCode,
});
```

Completed MFA sessions have `assuranceLevel: "aal2"` and record both authentication methods.

## HTTP and browser clients

The HTTP handler stores the MFA challenge in a temporary HttpOnly cookie. Browser JavaScript receives only `methods` and `expiresAt`:

```ts
const result = await authClient.signInEmailPassword({ email, password });

if (result.status === "mfa_required") {
  await authClient.completeMfaWithTotp({ code });
}
```

The browser client updates current-session state only after `status: "complete"`.

## Recovery codes

Regenerate every recovery code after confirming the current TOTP code:

```ts
const recoveryCodes = await auth.regenerateRecoveryCodes({
  sessionToken,
  code,
});
```

Regeneration invalidates all previous codes. Each recovery code is stored as an independent hash and can be consumed once.

## Disable TOTP

```ts
await auth.disableTotp({ sessionToken, code });
```

Disabling TOTP also invalidates every recovery code. TOTP uses SHA-1, six digits, 30-second periods, and a one-step clock tolerance. A successfully used timestep cannot be reused.
