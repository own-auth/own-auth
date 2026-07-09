# own-auth

Framework-independent TypeScript auth with Postgres storage.

## Install

```bash
npm install own-auth
```

## Basic Setup

```bash
export DATABASE_URL=postgres://localhost:5432/own_auth
export OWN_AUTH_TOKEN_PEPPER=replace-with-a-long-random-secret
npx own-auth migrate
```

```ts
import { createOwnAuth } from "own-auth";

export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER
});
```

## Basic Usage

```ts
const signup = await auth.signUpEmailPassword({
  email: "user@example.com",
  password: "secure-password"
});

const current = await auth.requireCurrentSession(signup.sessionToken);

await auth.signOut(signup.sessionToken);
```

## Email and SMS

Pass providers when you need real email or SMS delivery:

```ts
import { createOwnAuth, type EmailProvider, type SmsProvider } from "own-auth";

const emailProvider: EmailProvider = {
  async send(message) {
    await emailClient.send({
      to: message.to,
      subject: "Your secure link",
      html: `<a href="${message.url}">Continue</a>`
    });
  }
};

const smsProvider: SmsProvider = {
  async send(message) {
    await smsClient.send({
      to: message.to,
      body: `Your code is ${message.code}`
    });
  }
};

export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  baseUrl: "https://yourapp.com",
  emailProvider,
  smsProvider
});
```

Without providers, Own Auth writes delivery events to the server console for local development.

## CLI

```bash
npx own-auth migrate
npx own-auth generate --out own-auth.sql
```

## License

MIT
