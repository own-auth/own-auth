# Device Authorization

Use OAuth 2.0 device authorization for command-line tools, televisions, and other devices where opening a browser or entering credentials is difficult.

The device asks Own Auth for two codes. It keeps the secret device code and shows the short user code. The user enters that short code on a verification page owned by your application, signs in, and approves or denies access. The device then receives tokens from the normal OAuth token endpoint.

## Run The Migration

```bash
npx own-auth migrate
```

Migration `016_device_authorization` adds client grant types and the short-lived device authorization records used by the flow.

## Configure The Authorization Server

Add a verification page URL to the existing authorization-server configuration:

```ts auth.ts
import { createOwnAuth } from "own-auth";

export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  encryption: {
    current: {
      id: "2026-01",
      key: process.env.OWN_AUTH_ENCRYPTION_KEY!,
    },
  },
  authorizationServer: {
    issuer: "https://auth.example.com",
    interactionUrl: "https://auth.example.com/authorize",
    signingKeys: {
      current: {
        id: "2026-01",
        privateKey: process.env.OWN_AUTH_SIGNING_PRIVATE_KEY!,
      },
    },
    deviceAuthorization: {
      verificationUrl: "https://auth.example.com/device",
    },
  },
});
```

`verificationUrl` is your application page. Own Auth provides the protocol and SDK methods, but does not render this page.

| Option | Default | Description |
|---|---:|---|
| `verificationUrl` | Required | HTTPS page where users enter and approve a code. Local HTTP URLs are allowed outside production. |
| `ttlMs` | 10 minutes | Lifetime of the device and user codes. |
| `pollingIntervalSeconds` | 5 seconds | Minimum initial interval between token requests. |

Mount the authorization-server handler as described in [OAuth And OpenID Connect Server](/docs/authorization-server). Enabling device authorization adds `POST /oauth/device/authorize` and advertises it through discovery metadata.

## Create A Device Client

Register the client from trusted server-side administration code:

```ts
import { deviceAuthorizationGrantType } from "own-auth";

const { client } = await auth.authorizationServer.createClient({
  name: "Command Line App",
  clientType: "public",
  applicationType: "native",
  allowedScopes: ["openid", "profile", "email"],
  grantTypes: [deviceAuthorizationGrantType],
});

console.log(client.clientId);
```

A device-only client does not need a redirect URI. Add `"refresh_token"` to `grantTypes` and `"offline_access"` to `allowedScopes` when the client should receive refresh tokens.

## Start And Poll From A Device

The portable client handles the RFC polling interval and `slow_down` responses:

```ts
import { createDeviceFlowClient } from "own-auth/device-authorization";

const deviceClient = createDeviceFlowClient({
  deviceAuthorizationEndpoint: "https://auth.example.com/oauth/device/authorize",
  tokenEndpoint: "https://auth.example.com/oauth/token",
  clientId: process.env.OWN_AUTH_CLIENT_ID!,
});

const pending = await deviceClient.start({
  scope: ["openid", "profile", "email"],
});

console.log(`Open ${pending.verificationUri}`);
console.log(`Enter ${pending.userCode}`);

const tokens = await deviceClient.poll({ authorization: pending });
console.log(tokens.accessToken);
```

`verificationUriComplete` is available when the device can open a URL containing the user code. The user must still sign in and approve the request.

The helper depends on Fetch and Web Crypto. It does not import the auth engine or a database adapter.

## Build The Verification Page

Read the submitted code on your backend:

```ts
const request = await auth.authorizationServer.getDeviceAuthorization({
  userCode,
  sessionToken,
});
```

When the user is signed out, `request.action` is `"sign_in"`. A valid request includes the client display name, application type, optional resource name, and scope labels so the page can explain what is being requested. It never includes the device code, client secrets, database IDs, or tokens. Sign the user in, then load the request again before recording a decision.

For a signed-in user, show those details and approve the selected scopes:

```ts
await auth.authorizationServer.approveDeviceAuthorization({
  userCode,
  sessionToken,
  approvedScopes: ["openid", "profile", "email"],
});
```

Or deny the request:

```ts
await auth.authorizationServer.denyDeviceAuthorization({
  userCode,
  sessionToken,
});
```

Looking up a code does not reserve it for that user. Approval or denial atomically binds the request and records the first decision. If two users decide at the same time, one succeeds and the other receives `AuthError` with `code === "device_authorization_already_decided"`.

The page-facing SDK can return:

| Code | Meaning |
|---|---|
| `device_authorization_invalid` | The code is malformed, unknown, expired, or no longer usable. |
| `device_authorization_already_decided` | Another approval or denial completed first. |
| `invalid_session` | The approval or denial did not include a valid signed-in session. |
| `rate_limited` | Too many code lookups were attempted. |

These are Own Auth SDK errors for your verification page. They are not OAuth token endpoint errors.

## Protocol Errors

The token endpoint returns only RFC 8628 and OAuth errors:

| Error | Meaning |
|---|---|
| `authorization_pending` | The user has not decided yet. |
| `slow_down` | The device polled too quickly and must increase its interval by five seconds. |
| `access_denied` | The user denied the request. |
| `expired_token` | The device authorization expired. |
| `invalid_grant` | The code is unknown, consumed, malformed, or belongs to another client. |

Wrong-client polls and unknown device codes both return `invalid_grant`. Page errors such as `device_authorization_already_decided` never appear at `/oauth/token`.

## DPoP-Bound Tokens

When DPoP is enabled, create one key pair for the grant and pass it to the portable client:

```ts
import { generateDpopKeyPair } from "own-auth/dpop";
import { createDeviceFlowClient } from "own-auth/device-authorization";

const keyPair = await generateDpopKeyPair();

const deviceClient = createDeviceFlowClient({
  deviceAuthorizationEndpoint: "https://auth.example.com/oauth/device/authorize",
  tokenEndpoint: "https://auth.example.com/oauth/token",
  clientId: process.env.OWN_AUTH_CLIENT_ID!,
  dpopKeyPair: keyPair,
});
```

Own Auth binds the authorization to that public-key thumbprint. Every poll needs a fresh proof from the same key. The client cannot switch keys while the flow is pending.

## Security And Cleanup

Device codes and user codes are random and stored only as peppered, purpose-separated hashes. User codes use the RFC consonant alphabet `BCDFGHJKLMNPQRSTVWXZ` and display as `XXXX-XXXX`. Input is trimmed, uppercased, and stripped of ASCII spaces and hyphens before validation.

Starts are limited per client and IP address. User-code lookups are limited per signed-in user and IP address. Polling intervals are enforced in storage, including the persisted five-second `slow_down` increase.

Delete expired records on a daily schedule:

```ts
await auth.authorizationServer.cleanupDeviceAuthorizations({
  olderThan: new Date(),
});
```

Audit events record starts, approvals, denials, and successful token exchanges without raw device codes or user codes.
