# OAuth And OpenID Connect Authorization Server

Use Own Auth as the OAuth 2.1 and OpenID Connect server for other applications.

This is different from Google, GitHub, or Apple sign-in. External provider sign-in lets users enter your application with another provider. The authorization server lets another application request access to users who already sign in through your Own Auth instance.

## What It Provides

- Authorization code flow with PKCE S256
- OpenID Connect ID tokens signed with RS256
- Opaque access tokens
- Rotating refresh tokens
- Token revocation
- Same-client token introspection
- OpenID Connect userinfo
- Discovery metadata and JWKS
- Consent, reauthentication, account selection, and AAL2 step-up interactions

Device authorization, protected-resource registration, DPoP, SAML, SCIM, and MCP authorization are not part of this release.

## Run The Migration

```bash
npx own-auth migrate
```

Migration `011_authorization_server` adds authorization clients, secrets, interactions, grants, codes, access tokens, refresh tokens, and stable OpenID Connect subjects.

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
  },
});
```

`issuer` is the public origin serving the protocol handler. `interactionUrl` is the application page that handles sign-in, account selection, MFA, and consent.

The encryption key protects stored authorization requests and OIDC nonces. The RSA key signs ID tokens. Keep both on the server.

## Mount The Protocol Handler

```ts
import { createOwnAuthAuthorizationServerHandler } from "own-auth/authorization-server";
import { auth } from "./auth";

export const authorizationHandler =
  createOwnAuthAuthorizationServerHandler(auth);
```

Pass Web `Request` objects to the handler and return its Web `Response`.

The handler serves:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/.well-known/oauth-authorization-server` | OAuth metadata |
| `GET` | `/.well-known/openid-configuration` | OpenID Connect metadata |
| `GET` | `/oauth/authorize` | Start authorization |
| `POST` | `/oauth/token` | Exchange a code or rotate a refresh token |
| `POST` | `/oauth/revoke` | Revoke an access token or refresh grant |
| `POST` | `/oauth/introspect` | Inspect a confidential client's own tokens |
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

Applications serving APIs can verify an Own Auth access token directly:

```ts
const verified = await auth.authorizationServer.verifyAccessToken({
  accessToken,
  requiredScopes: ["documents:read"],
});

console.log(verified.userId);
```

This is the resource-server integration for applications using the same Own Auth instance. Separate protected-resource registration is not implemented yet.

## Refresh Token Reuse

Refresh tokens rotate on every use. If the same refresh token is presented again, Own Auth revokes the entire grant family.

When two refresh requests race, one can rotate first. Reuse detection then revokes the newly issued winner as well. Both callers must return to the authorization flow. This prevents a stolen refresh token from winning a race against the legitimate client.

## Introspection Boundary

Only confidential clients can call introspection. A client can inspect only access and refresh tokens issued to that same client.

Tokens issued to another client return:

```json
{
  "active": false
}
```

Broader resource-server introspection is intentionally deferred.

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
