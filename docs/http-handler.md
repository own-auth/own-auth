# HTTP Handler

Expose Own Auth through one framework-neutral handler built on the standard Web `Request` and `Response` APIs.

## Create the handler

```ts auth-handler.ts
import { createOwnAuthHandler } from "own-auth/http";

import { auth } from "./auth";

export const authHandler = createOwnAuthHandler(auth);
```

Mount `authHandler` at `/api/auth/*`. Frameworks that use Web `Request` and `Response` objects can call it directly.

```ts app/api/auth/[...path]/route.ts
import { authHandler } from "../../../../../auth-handler";

export const GET = authHandler;
export const POST = authHandler;
```

The auth engine remains framework-independent. The handler only translates HTTP requests into existing Own Auth methods.

## Protocol Handlers

The application auth API, OAuth and OpenID Connect server, and SCIM server use separate handlers because they have different authentication, content-type, and error contracts.

```ts handlers.ts
import { createOwnAuthAuthorizationServerHandler } from "own-auth/authorization-server";
import { createOwnAuthHandler } from "own-auth/http";
import { createOwnAuthScimHandler } from "own-auth/scim";

import { auth } from "./auth";

export const authHandler = createOwnAuthHandler(auth);
export const authorizationServerHandler =
  createOwnAuthAuthorizationServerHandler(auth);
export const scimHandler = createOwnAuthScimHandler(auth);
```

Mount only the optional protocol handlers configured by the application:

| Handler | Default mount |
|---|---|
| `authHandler` | `/api/auth/*` |
| `authorizationServerHandler` | `/oauth/*` and `/.well-known/*` as documented by the authorization server |
| `scimHandler` | `/scim/v2/*` |

These handlers share the same `auth` instance and storage. They do not call one another.

## Endpoints

| Method | Path | Operation |
|---|---|---|
| `POST` | `/api/auth/sign-up/email` | Sign up with email and password |
| `POST` | `/api/auth/sign-in/email` | Sign in with email and password |
| `GET` | `/api/auth/session` | Get the current session |
| `POST` | `/api/auth/sign-out` | Sign out |
| `POST` | `/api/auth/password/change` | Change the current password |
| `POST` | `/api/auth/magic-link/request` | Send a magic link |
| `POST` | `/api/auth/magic-link/verify` | Verify a magic link |
| `POST` | `/api/auth/email-verification/request` | Send a verification link |
| `POST` | `/api/auth/email-verification/verify` | Verify an email address |
| `POST` | `/api/auth/password-reset/request` | Send a password reset link |
| `POST` | `/api/auth/password-reset/confirm` | Reset a password |
| `POST` | `/api/auth/sms/request` | Send an SMS code |
| `POST` | `/api/auth/sms/verify` | Verify an SMS code |
| `POST` | `/api/auth/invitations/accept` | Accept an organisation invitation |
| `POST` | `/api/auth/oauth/start` | Start redirect or popup OAuth |
| `GET` | `/api/auth/oauth/google/callback` | Complete Google OAuth |
| `GET` | `/api/auth/oauth/github/callback` | Complete GitHub OAuth |
| `GET` | `/api/auth/oauth/apple/callback` | Complete an Apple query callback |
| `POST` | `/api/auth/oauth/apple/callback` | Complete an Apple `form_post` callback |
| `POST` | `/api/auth/oauth/google/one-tap/prepare` | Create a Google One Tap nonce transaction |
| `POST` | `/api/auth/oauth/google/one-tap/verify` | Verify a Google One Tap credential |
| `POST` | `/api/auth/oauth/unlink` | Unlink a provider from the current user |
| `POST` | `/api/auth/saml/start` | Start SAML sign-in or identity linking and return the identity-provider URL |
| `POST` | `/api/auth/saml/acs` | Complete a SAML form-post callback |
| `GET` | `/api/auth/saml/metadata?connectionId=...` | Return service-provider metadata for one connection |
| `POST` | `/api/auth/mfa/totp/complete` | Complete MFA with TOTP |
| `POST` | `/api/auth/mfa/recovery/complete` | Complete MFA with a recovery code |
| `POST` | `/api/auth/mfa/totp/enroll` | Begin TOTP enrollment |
| `POST` | `/api/auth/mfa/totp/confirm` | Confirm TOTP and create recovery codes |
| `POST` | `/api/auth/mfa/totp/disable` | Disable TOTP |
| `POST` | `/api/auth/mfa/recovery/regenerate` | Replace all recovery codes |
| `POST` | `/api/auth/passkeys/register/options` | Create passkey registration options |
| `POST` | `/api/auth/passkeys/register/verify` | Verify passkey registration |
| `POST` | `/api/auth/passkeys/authenticate/options` | Create passkey authentication options |
| `POST` | `/api/auth/passkeys/authenticate/verify` | Verify passkey authentication or MFA |
| `GET` | `/api/auth/passkeys` | List the current user's passkeys |
| `POST` | `/api/auth/passkeys/rename` | Rename a passkey |
| `POST` | `/api/auth/passkeys/revoke` | Revoke a passkey |
| configured | `/api/auth/plugins/{plugin-id}/...` | Run a namespaced plugin endpoint |

The exported `ownAuthEndpointContract` contains each route's method, path, request schema, response schema, session behavior, and auth error codes.

JSON request bodies are limited to 64 KiB by default. Change `maxRequestBodyBytes` only when an application genuinely needs a different limit.

## Request context

Pass a trusted client IP from the framework or hosting adapter so IP-based OAuth and One Tap limits can run. The handler does not trust forwarding headers by default because applications differ in which proxies they trust.

```ts
export const authHandler = createOwnAuthHandler(auth, {
  getRequestContext(request) {
    return {
      ipAddress: getTrustedClientIp(request),
      userAgent: request.headers.get("user-agent") ?? undefined,
    };
  },
});
```

Do not copy an arbitrary `X-Forwarded-For` value directly. Resolve the address through the framework or platform's trusted-proxy configuration.

## Sessions

Completed signup, signin, magic-link verification, phone login, OAuth, One Tap, SAML, and passkey authentication set an `HttpOnly` session cookie. The JSON response never contains the raw session token, password hash, or session-token hash.

Magic link verification, email verification, and password reset use the existing session cookie or bearer credential to prove access to a pending account. A JSON body cannot supply this proof. If mailbox verification instead creates a separate verified owner, the old account's sessions are revoked. Email verification clears an obsolete cookie and does not create a session. Use the returned user ID. See [Email ownership](/docs/security-model#email-ownership).

The default cookie is:

```text
own_auth_session; Path=/; HttpOnly; SameSite=Lax
```

`Secure` is added automatically over HTTPS. It can only be disabled on localhost. Cookie-authenticated requests and `Authorization: Bearer <session-token>` requests use the same session verification path.

Customize the cookie when creating the handler:

```ts
export const authHandler = createOwnAuthHandler(auth, {
  cookie: {
    name: "session",
    sameSite: "strict",
  },
});
```

## MFA challenges

When a first factor succeeds for a user with MFA enabled, the handler does not set a session cookie. It stores the pending challenge in a separate temporary `HttpOnly` cookie and returns only the available methods and expiry:

```json
{
  "status": "mfa_required",
  "methods": ["totp", "recovery_code", "passkey"],
  "expiresAt": "2026-07-14T12:00:00.000Z"
}
```

The default challenge cookie is `own_auth_mfa`. It is cleared after successful MFA, signout, or password reset. Browser JavaScript never receives the challenge token.

## OAuth callbacks

Google and GitHub use GET callbacks. Apple supports GET and its required `application/x-www-form-urlencoded` POST callback. Apple form bodies are always limited to 64 KiB, even when `maxRequestBodyBytes` is larger.

`POST /oauth/start` sets a separate temporary browser proof cookie for each transaction. Callbacks require the matching cookie before consuming state or exchanging the provider code. The cookie is cleared after completion, including provider failures. The proof never appears in the start JSON or popup messages. HTTPS cookies use `HttpOnly`, `Secure`, `SameSite=None`, `Path=/`, and a `__Host-` name prefix without a Domain attribute, so Apple form callbacks can return the proof. HTTP localhost uses `SameSite=Lax` for development; Apple form callbacks require HTTPS. Start and callback requests must use the same auth host.

Redirect callbacks set the session or MFA cookie and return to the transaction's validated destination. Popup callbacks post only `complete`, `mfa_required`, `linked`, or `failure` to the exact stored opener origin. They never post OAuth codes, provider tokens, session tokens, or MFA challenge tokens.

Provider and account resolution failures are returned through the popup message or redirect query parameters. Missing or mismatched browser proof returns `oauth_transaction_invalid` directly, without setting a session or exposing transaction details. Malformed, expired, reused, and rate limited callbacks also return direct HTTP errors.

## SAML callbacks

SAML is available only when the auth instance uses `createSaml` from `own-auth/saml`. `POST /saml/start` returns an identity-provider URL instead of redirecting automatically, so server code and the TypeScript client can choose when navigation happens.

The assertion consumer service accepts only `application/x-www-form-urlencoded` POST bodies and always limits them to 64 KiB. It validates the SAML transaction before setting a session or temporary MFA cookie. The response then redirects to the transaction's validated destination with only `own_auth_status` and, on failure, a generic `own_auth_error` value. Raw SAML responses, relay state, subjects, session tokens, and MFA challenge tokens are never placed in the redirect URL.

Service-provider metadata is connection-specific. Give the identity provider the exact metadata URL returned for that connection:

```text
https://auth.example.com/api/auth/saml/metadata?connectionId=samlc_...
```

See [SAML SSO](/docs/saml) for setup and connection behavior.

## SCIM Handler

SCIM is available only when the auth instance includes `scim: {}`. The separate handler from `own-auth/scim` authenticates requests with a connection-scoped SCIM bearer token instead of an application session.

```ts
import { createOwnAuthScimHandler } from "own-auth/scim";

export const scimHandler = createOwnAuthScimHandler(auth, {
  getRequestContext(request) {
    return {
      ipAddress: getTrustedClientIp(request),
      userAgent: request.headers.get("user-agent") ?? undefined,
    };
  },
});
```

The handler supports SCIM User discovery, creation, listing, filtering, reads, replacement, PATCH updates, and deletion under `/scim/v2`. Request bodies must use `application/scim+json` and are limited to 256 KiB by default.

SCIM errors use the RFC 7644 error shape rather than the application auth error shape. Generate its separate OpenAPI document with `createOwnAuthScimOpenApiDocument`.

See [SCIM Provisioning](/docs/scim) for setup, endpoints, ETags, lifecycle behavior, and security rules.

## CSRF protection

Mutation requests from a browser must come from the same origin as the handler. Add a frontend origin only when the frontend and auth API use different HTTPS origins:

```ts
export const authHandler = createOwnAuthHandler(auth, {
  trustedOrigins: ["https://app.example.com"],
});
```

HTTPS origins and local development origins are accepted. Cookie-authenticated mutation requests without an `Origin` header are rejected. Server and native clients can use a bearer session without browser cookie behavior.

## Errors

Every failure uses the same response shape:

```json
{
  "error": {
    "code": "invalid_credentials",
    "message": "Invalid email or password"
  }
}
```

| Status | Meaning |
|---|---|
| `400` | Invalid input, token, redirect, or request format |
| `401` | Invalid credentials, session, token, or code |
| `403` | Disabled user, missing permission, or failed CSRF check |
| `404` | Route or required resource not found |
| `409` | Existing email, member, key, or invitation conflict |
| `413` | Request body is larger than the configured limit |
| `415` | Request uses an unsupported content type |
| `429` | Rate limit or OTP attempt limit reached |
| `500` | Unexpected server failure with a safe public message |
| `502` | OAuth provider request failed |
| `504` | A plugin before-hook timed out |

Catch `OwnAuthClientError` in client code to read the typed `code`, `message`, and HTTP `status`.

## OpenAPI

Generate an OpenAPI 3.1 document from the same endpoint contract:

```ts
import { createOwnAuthOpenApiDocument } from "own-auth/http";

const openapi = createOwnAuthOpenApiDocument({
  title: "My App Auth API",
  version: "1.0.0",
  serverUrl: "https://api.example.com",
});
```

Generate the SCIM document separately:

```ts
import { createOwnAuthScimOpenApiDocument } from "own-auth/scim";

const scimOpenApi = createOwnAuthScimOpenApiDocument({
  title: "My App SCIM API",
});
```

When the handler uses a custom cookie name, pass the same value as `sessionCookieName`.

Request schemas, response schemas, operation IDs, and endpoint error codes come from `ownAuthEndpointContract`. There is no second route definition to keep in sync.

The core document remains stable and excludes plugin routes. Generate the configured plugin document separately:

```ts
import { createConfiguredOwnAuthOpenApiDocument } from "own-auth";

const openapi = createConfiguredOwnAuthOpenApiDocument(plugins);
console.log(openapi["x-own-auth-plugin-fingerprint"]);
```

The fingerprint covers the core version and complete configured plugin endpoint contract. Regenerate plugin clients when it changes.
