# OAuth And External Providers

Own Auth supports Google, GitHub, and Apple redirect OAuth. Native provider SDKs and other integrations can keep using the trusted verified-identity method.

## Configure providers

```ts
import { createOwnAuth } from "own-auth";

export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  redirectAllowlist: ["https://app.example.com"],
  oauth: {
    providers: {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID!,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        redirectUri: "https://api.example.com/api/auth/oauth/google/callback",
      },
      github: {
        clientId: process.env.GITHUB_CLIENT_ID!,
        clientSecret: process.env.GITHUB_CLIENT_SECRET!,
        redirectUri: "https://api.example.com/api/auth/oauth/github/callback",
      },
      apple: {
        clientId: process.env.APPLE_CLIENT_ID!,
        teamId: process.env.APPLE_TEAM_ID!,
        keyId: process.env.APPLE_KEY_ID!,
        privateKey: process.env.APPLE_PRIVATE_KEY!,
        redirectUri: "https://api.example.com/api/auth/oauth/apple/callback",
      },
    },
  },
});
```

Register each `redirectUri` with its provider. Apple uses `form_post`; the Own Auth HTTP handler accepts that callback as bounded `application/x-www-form-urlencoded` data.

## Start redirect OAuth

With the browser client:

```ts
await authClient.signInWithOAuth({
  provider: "google",
  destination: "/account",
});
```

With the server API:

```ts
import { createOAuthBrowserCookie } from "own-auth/http";

const authorization = await auth.createOAuthAuthorizationUrl({
  provider: "google",
  destination: "https://app.example.com/account",
});

const headers = new Headers({ location: authorization.url });
headers.append("set-cookie", createOAuthBrowserCookie(
  authorization.state,
  authorization.browserBindingToken,
  authorization.expiresAt,
  new URL(request.url),
));
return new Response(null, { status: 302, headers });
```

The start request and provider callback must use the same auth host so the browser can return its temporary cookie. The HTTP handler completes callbacks, creates the secure session cookie, and returns to the validated destination. The browser client and `POST /oauth/start` manage the temporary cookie automatically.

`createOAuthAuthorizationUrl` returns `state` and a secret `browserBindingToken` in addition to the URL and expiry. The state is derived from that secret, and only the peppered state hash is stored in the existing transaction. Keep the secret out of URLs, response JSON, browser JavaScript, logs, and provider parameters.

For a custom callback, read the proof with `readOAuthBrowserToken(request, state)` from `own-auth/http` and pass it as `browserBindingToken` to `completeOAuthSignIn`. Read `state` from the validated provider callback parameters. Never accept the proof from callback parameters or a request body. Clear the cookie with `clearOAuthBrowserCookie(state, new URL(request.url))` after completion or a consumed provider failure. Applications using their own server session can store each proof there instead, provided it belongs to the initiating browser.

Callbacks without matching browser proof are rejected before state is consumed or the provider is contacted. Cookies are separate for each transaction so concurrent tabs do not replace each other's proof. Over HTTPS they use `HttpOnly`, `Secure`, `SameSite=None`, `Path=/`, and the `__Host-` name prefix without a Domain attribute. `SameSite=None` allows Apple's callback POST from the provider origin. HTTP localhost uses a development cookie with `SameSite=Lax`; use HTTPS for Apple form callbacks.

After upgrading, restart OAuth attempts that were already in progress. Earlier attempts have no browser proof and are rejected. No database migration is required.

## Popup OAuth

```ts
const result = await authClient.signInWithOAuth({
  provider: "github",
  mode: "popup",
});
```

The popup opens synchronously and times out after 120 seconds by default. The callback validates the exact opener origin and sends only `complete`, `mfa_required`, `linked`, or `failure`. OAuth codes, provider tokens, session tokens, and MFA challenge tokens never enter `postMessage`.

## Google One Tap

Prepare a single-use nonce before rendering Google One Tap:

```ts
const { nonce } = await authClient.prepareGoogleOneTap();
```

Pass that nonce to Google Identity Services, then submit the returned credential:

```ts
const result = await authClient.signInWithGoogleOneTap({
  credential,
  nonce,
});
```

The nonce transaction is consumed before the Google credential is verified. The optional `own-auth/google-one-tap` helper coordinates Google Identity Services after the application loads Google's browser script; the neutral client methods work without it.

## Account linking

Explicit linking is the default. If a new provider identity has the same verified email as an existing Own Auth user, sign-in returns `account_linking_required`. Sign the user into the existing account, then start OAuth with `intent: "link"`:

```ts
await authClient.signInWithOAuth({
  provider: "google",
  intent: "link",
  destination: "/account/security",
});
```

Automatic verified-email linking is opt-in:

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  oauth: {
    accountLinking: "verified_email",
    providers: { /* ... */ },
  },
});
```

Unverified emails are never used for account linking. A provider identity already linked to another user returns `oauth_account_conflict`.

Unlink a provider only after another usable authentication method exists:

```ts
await auth.unlinkOAuthProvider({
  actorUserId: user.id,
  provider: "google",
  providerAccountId: googleSubject,
});
```

## Trusted verified identities

Native Google and Apple SDK integrations can verify provider credentials themselves and pass the normalized identity to Own Auth:

```ts
const identity = await nativeProvider.verifyCredential(providerCredential);

const result = await auth.signInWithVerifiedExternalIdentity({
  provider: "google",
  providerAccountId: identity.subject,
  email: identity.email,
  emailVerified: identity.emailVerified,
  name: identity.name,
});
```

`signInWithVerifiedExternalIdentity` does not verify a provider token. Only call it after a trusted backend adapter has verified the signature, issuer, audience, expiry, and nonce where required. It uses the same account collision, linking, MFA, session, and audit rules as redirect OAuth.

## Offline provider access

Provider refresh-token storage is disabled by default. Enable it per provider and configure the shared encryption key ring:

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  encryption: {
    current: {
      id: "2026-01",
      key: process.env.OWN_AUTH_ENCRYPTION_KEY!,
    },
  },
  oauth: {
    providers: {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID!,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        redirectUri: "https://api.example.com/api/auth/oauth/google/callback",
        offlineAccess: true,
      },
    },
  },
});
```

Existing linked users must authenticate with the provider again and grant offline access. Access and refresh tokens are server-only:

```ts
const { accessToken, scopes } = await auth.getExternalAccessToken({
  actorUserId: user.id,
  provider: "google",
});

await auth.revokeExternalProviderAccess({
  actorUserId: user.id,
  provider: "google",
});
```

Own Auth never stores access tokens. Refresh tokens are encrypted and are not exposed by the HTTP handler or browser client.
