# Phone Login

Sign in with a phone number and a one-time SMS code. The user enters their phone number, receives a text with a 6-digit code, types it in, and they are signed in.

## Send a verification code

```ts
await auth.requestSmsOtp({
  phone: "+14155551234",
});
```

This generates a random code, hashes it, stores the hash, and sends the code through the configured `smsProvider`. The function does not reveal whether the phone number already belongs to a user.

### Phone number format

Use E.164 format: `+` followed by the country code and number. Examples include `+14155551234`, `+447911123456`, and `+33612345678`.

Own Auth removes spaces, parentheses, dots, and dashes before storing or comparing a phone number. A successfully verified SMS code confirms that the number can receive messages.

## Verify the code

```ts
const { user, session, sessionToken } = await auth.verifySmsOtp({
  phone: "+14155551234",
  code: "483291",
});
```

If the code is valid, Own Auth consumes it, verifies the phone number, creates a session, and signs the user in. The same code cannot be used again.

### Errors

| Code | When |
|---|---|
| `invalid_otp` | The code is wrong, expired, already used, or does not exist. |
| `otp_attempts_exceeded` | The code has reached its maximum number of wrong attempts. |
| `rate_limited` | Too many code requests or verification attempts. |
| `user_not_found` | Phone signup is disabled and the number does not belong to a user. |
| `disabled_user` | The user has been disabled. |

```ts
import { AuthError } from "own-auth";

try {
  const { user, session, sessionToken } = await auth.verifySmsOtp({
    phone,
    code,
  });
} catch (error) {
  if (!(error instanceof AuthError)) {
    throw error;
  }

  switch (error.code) {
    case "invalid_otp":
      // Show: This code is invalid or has expired.
      break;
    case "otp_attempts_exceeded":
      // Show: Too many attempts. Request a new code.
      break;
    case "rate_limited":
      // Show: Too many attempts. Try again later.
      break;
  }
}
```

## Auto-creating users

Phone login creates new users by default. The user is created when a valid code is verified, not when the SMS is sent.

To restrict phone login to existing users:

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  allowPhoneSignup: false,
});
```

## Abuse protection

Own Auth applies rate limits automatically:

- A phone number can request up to 5 codes every 15 minutes.
- A phone number can make up to 10 verification attempts every 15 minutes.
- Each code allows 5 wrong guesses by default. After that, a new code must be requested.

Rate-limit counters are stored in Postgres by default, so the limits continue to work across server restarts and multiple application instances.

## SMS provider

Phone login requires an `smsProvider` that sends the code through the SMS service used by the application.

```ts
import { createOwnAuth, type SmsProvider } from "own-auth";

const smsProvider: SmsProvider = {
  async send(message) {
    await smsClient.send({
      from: "+15550001234",
      to: message.to,
      body: `Your verification code is ${message.code}`,
    });
  },
};

const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  smsProvider,
});
```

Without a configured provider, Own Auth uses `ConsoleSmsProvider` for local development. It records the delivery event but does not send a text message.

## How codes are stored

Codes are hashed with the token pepper before storage, just like magic-link tokens. The raw code exists only while Own Auth passes it to the SMS provider. Reading the database does not reveal a usable code.

## Configuration

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  allowPhoneSignup: true, // default
  sms: {
    otpTtlMs: 10 * 60 * 1000, // 10 minutes
    codeLength: 6, // digits
    maxAttempts: 5, // wrong guesses before blocking the code
  },
  smsProvider,
});
```

## Next step

Learn about [Email verification](/docs/email-verification) to confirm emails after sign-up, or [Sessions](/docs/sessions) to understand how users stay signed in.
