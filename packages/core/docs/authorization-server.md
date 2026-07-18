# OAuth And OpenID Connect Authorization Server

Use Own Auth as the OAuth 2.1 and OpenID Connect server for other applications.

This is different from Google, GitHub, or Apple sign-in. External provider sign-in lets users enter your application with another provider. The authorization server lets another application request access to users who already sign in through your Own Auth instance.

## What It Provides

- Authorization code flow with PKCE S256
- OpenID Connect ID tokens signed with RS256
- Opaque access tokens
- Rotating refresh tokens
- Optional DPoP-bound access and refresh tokens
- Token revocation
- Client and protected-resource token introspection
- Resource-bound access and refresh tokens
- OpenID Connect userinfo
- Discovery metadata and JWKS
- Consent, reauthentication, account selection, and AAL2 step-up interactions
- Optional RFC 8628 device authorization for command-line tools and input-limited devices

SCIM and MCP authorization are not authorization-server protocol modes in this release. Organisation SAML sign-in is a separate integration documented in [SAML SSO](/docs/saml).

## Run The Migration

```bash
npx own-auth migrate
```

Migration `011_authorization_server` adds authorization clients, secrets, interactions, grants, codes, access tokens, refresh tokens, and stable OpenID Connect subjects. Migration `012_protected_resources` adds registered resource servers, hashed resource secrets, and token audience bindings. Migration `013_dpop` adds DPoP bindings and proof replay protection. Migration `016_device_authorization` adds client grant types and short-lived device authorization records.

## Configuration

Generate an RSA signing key:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out own-auth-signing-key.pem
```

Generate the shared encryption key if the application does not already have one:

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

```ts
import { readFileSync } from "node:fs";
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
        privateKey: readFileSync(
          process.env.OWN_AUTH_SIGNING_KEY_PATH!,
          "utf8",
        ),
      },
    },
    scopes: {
      "documents:read": {
        label: "Read documents",
        description: "Read documents the user can access.",
      },
    },
    dpop: {},
    deviceAuthorization: {
      verificationUrl: "https://auth.example.com/device",
    },
  },
});
```

`issuer` is the public origin serving the protocol handler. `interactionUrl` is the application page that handles sign-in, account selection, MFA, and consent.

The encryption key protects stored authorization requests and OIDC nonces. The RSA key signs ID tokens. Keep both on the server.

`dpop` enables DPoP support. The default proof lifetime is five minutes with one minute of clock skew. Omit `dpop` when the authorization server will issue only Bearer tokens.

`deviceAuthorization` enables RFC 8628 device authorization. `verificationUrl` is an application-owned page where the user signs in and approves or denies the short code.

## Mount The Protocol Handler

```ts
import { createOwnAuthAuthorizationServerHandler } from "own-auth/authorization-server";
import { auth } from "./auth";

export const authorizationHandler =
  createOwnAuthAuthorizationServerHandler(auth);
```

Pass Web `Request` objects to the handler and return its Web `Response`.

Generate an OpenAPI 3.1 document for these protocol routes from the same package export:

```ts
import {
  createOwnAuthAuthorizationServerOpenApiDocument,
} from "own-auth/authorization-server";

export const openApi =
  createOwnAuthAuthorizationServerOpenApiDocument({
    serverUrl: "https://auth.example.com",
  });
```

The handler serves:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/.well-known/oauth-authorization-server` | OAuth metadata |
| `GET` | `/.well-known/openid-configuration` | OpenID Connect metadata |
| `GET` | `/oauth/authorize` | Start authorization |
| `POST` | `/oauth/device/authorize` | Start device authorization |
| `POST` | `/oauth/token` | Exchange a code or rotate a refresh token |
| `POST` | `/oauth/revoke` | Revoke an access token or refresh grant |
| `POST` | `/oauth/introspect` | Inspect tokens owned by a confidential client or protected resource |
| `GET` or `POST` | `/oauth/userinfo` | Return scoped OpenID Connect claims |
| `GET` | `/oauth/jwks` | Publish signing keys |

The normal `createOwnAuthHandler` routes do not change.

## Create A Client

Create clients from trusted server-side administration code:

```ts
const created = await auth.authorizationServer.createClient({
  name: "Desktop App",
  clientType: "public",
  applicationType: "native",
  redirectUris: ["com.example.desktop://oauth/callback"],
  allowedScopes: ["openid", "profile", "email"],
});

console.log(created.client.clientId);
```

Public clients use PKCE and do not receive a secret.

Device-only clients can omit redirect URIs and use the device grant explicitly. See [Device Authorization](/docs/device-authorization) for client registration, the verification page, polling, DPoP binding, cleanup, and RFC error behavior.

Confidential clients receive a secret once:

```ts
const created = await auth.authorizationServer.createClient({
  name: "Server App",
  clientType: "confidential",
  applicationType: "web",
  redirectUris: ["https://client.example.com/oauth/callback"],
  allowedScopes: ["openid", "profile", "email", "offline_access"],
});

console.log(created.client.clientId);
console.log(created.clientSecret);
```

Store the secret immediately. Only its hash and visible prefix are stored.

## Bind Tokens With DPoP

DPoP binds an access and refresh token to a client-held private key. A copied token cannot be used without a fresh proof signed by the same key.

Enable bound tokens for a client:

```ts
const { client } = await auth.authorizationServer.createClient({
  name: "Native App",
  clientType: "public",
  applicationType: "native",
  redirectUris: ["com.example.app://oauth/callback"],
  allowedScopes: ["openid", "documents:read", "offline_access"],
  dpopBoundAccessTokens: true,
});
```

The OAuth client creates and retains one key pair for the grant:

```ts
import {
  createDpopProof,
  generateDpopKeyPair,
} from "own-auth/dpop";

const keyPair = await generateDpopKeyPair();
```

Keep the private key in secure client storage. Send only `keyPair.jwkThumbprint` as `dpop_jkt` in the authorization request. Send a new proof in the `DPoP` header when exchanging the code:

```ts
const proof = await createDpopProof({
  keyPair,
  method: "POST",
  url: "https://auth.example.com/oauth/token",
});

await fetch("https://auth.example.com/oauth/token", {
  method: "POST",
  headers: {
    "content-type": "application/x-www-form-urlencoded",
    DPoP: proof,
  },
  body: tokenRequestBody,
});
```

Bound token responses use `token_type: "DPoP"`. Refresh requests require a fresh proof from the same key. A refresh token cannot become bound, become unbound, or switch keys.

For a protected API request, bind the proof to the access token and send both headers:

```ts
const apiUrl = "https://api.example.com/documents?draft=true";
const apiProof = await createDpopProof({
  keyPair,
  method: "GET",
  url: apiUrl,
  accessToken,
});

await fetch(apiUrl, {
  headers: {
    Authorization: `DPoP ${accessToken}`,
    DPoP: apiProof,
  },
});
```

The helper uses Web Crypto and does not import Own Auth core, Postgres, D1, or provider code. It works in supported browsers, Workers, and Node.js 20 or later.

## Build The Interaction Page

The protocol handler redirects to `interactionUrl` with an `interaction` query parameter.

Load the interaction from the application's backend:

```ts
const interaction = await auth.authorizationServer.getInteraction({
  interactionToken,
  sessionToken,
});
```

Keep these interaction operations behind the application's normal session and CSRF protections. Do not call them directly from untrusted browser input without authenticating the session.

The `action` is one of:

| Action | Application behavior |
|---|---|
| `sign_in` | Ask the user to sign in. |
| `reauthenticate` | Ask for a fresh sign-in. |
| `select_account` | Show the current account and a "Use another account" option. |
| `mfa` | Complete a configured second factor. |
| `consent` | Show the client and requested scopes. |
| `continue` | Continue without another consent prompt. |

An unauthenticated call returns `client: null` and no scopes. Client details are shown only after a valid Own Auth session is supplied.

`select_account` always renders, even when only one account is currently signed in. Choosing "Use another account" is application UI behavior. Sign out or replace the current session, then approve with the selected account's session.

Approve:

```ts
const result = await auth.authorizationServer.approveInteraction({
  interactionToken,
  sessionToken,
  approvedScopes: ["openid", "profile", "email"],
});

return redirect(result.redirectUrl);
```

Deny:

```ts
const result = await auth.authorizationServer.denyInteraction({
  interactionToken,
  sessionToken,
});

return redirect(result.redirectUrl);
```

The interaction token is hashed in storage and can finish only once.

## Verify Access Tokens

An API using the same Own Auth instance can verify a Bearer access token directly:

```ts
const verified = await auth.authorizationServer.verifyAccessToken({
  accessToken,
  resource: "https://api.example.com/",
  requiredScopes: ["documents:read"],
});

console.log(verified.userId);
```

DPoP verification requires the request method, request URL, and proof header. Use `own-auth/protected-resource` for DPoP-bound tokens even when the API runs beside the authorization server.

APIs running separately use authenticated remote introspection through the lightweight `own-auth/protected-resource` export. See [Protected Resources](/docs/protected-resources) for registration, resource indicators, scope behavior, credential rotation, and the remote verification helper.

## Refresh Token Reuse

Refresh tokens rotate on every use. If the same refresh token is presented again, Own Auth revokes the entire grant family.

When two refresh requests race, one can rotate first. Reuse detection then revokes the newly issued winner as well. Both callers must return to the authorization flow. This prevents a stolen refresh token from winning a race against the legitimate client.

## Introspection Boundary

Confidential clients can inspect only access and refresh tokens issued to that client. Registered protected resources can inspect only access tokens whose resource matches their exact identifier.

Tokens issued to another client return:

```json
{
  "active": false
}
```

Tokens for another client or protected resource return the same inactive response. Introspection does not reveal the token's real owner or audience.

## DPoP Replay Cleanup

Own Auth stores only a peppered hash derived from the public-key thumbprint and proof ID. It never stores the proof JWT, public JWK, proof ID, or access token in the replay table.

Proof rows expire after the configured proof lifetime plus clock skew. Delete expired rows on a schedule:

```ts
await auth.authorizationServer.cleanupDpopProofs();
```

## Signing Key Rotation

Move the old public key to `previous` and make the new private key current:

```ts
const signingKeys = {
  current: {
    id: "2027-01",
    privateKey: newPrivateKey,
  },
  previous: [
    {
      id: "2026-01",
      publicKey: oldPublicKey,
    },
  ],
};
```

New ID tokens use the current key. JWKS continues publishing previous public keys so relying parties can verify unexpired tokens issued before rotation.

## Delete Users

OIDC subjects are stable and are never reassigned. Deleting a user deletes that user's subject. A relying party that stored the old subject keeps a permanent dead reference rather than matching a future user.
