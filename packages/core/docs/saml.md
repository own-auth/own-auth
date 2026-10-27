# SAML SSO

Add organisation-scoped SAML 2.0 sign-in to Own Auth. Own Auth acts as the service provider. Each organisation can connect its identity provider without changing the application's normal password, OAuth, magic-link, or MFA flows.

Own Auth supports service-provider-initiated sign-in with Redirect binding for the authentication request and POST binding for the signed response.

## Run The Migration

```bash
npx own-auth migrate
```

Migration `014_saml` adds SAML connections, short-lived authentication transactions, and assertion replay records.

## Configure SAML

```ts auth.ts
import { createOwnAuth } from "own-auth";
import { createSaml } from "own-auth/saml";

export const auth = createOwnAuth({
  baseUrl: "https://auth.example.com",
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  saml: createSaml(),
});
```

The default SAML endpoints use `/api/auth`. When the HTTP handler uses another base path, pass the same path to `createSaml`:

```ts
const saml = createSaml({ basePath: "/auth" });
const handler = createOwnAuthHandler(auth, { basePath: "/auth" });
```

`createSaml` is exported separately so applications that do not use SAML never load the XML and SAML protocol dependency.

Keep the application lockfile's XML parser resolution patched. This repository resolves `@xmldom/xmldom@0.8.15` for `@node-saml/node-saml`, `xml-crypto`, and `xml-encryption`. The [parser maintainer's release notes](https://github.com/xmldom/xmldom/releases/tag/0.8.15) describe fixes for excessive parsing time and memory use. Applications upgrading Own Auth must also update their own affected transitive resolutions and audit their production dependencies. An older application lockfile can keep an affected parser even when its parent library accepts the patched version.

The built-in Postgres, Cloudflare D1, and in-memory adapters implement SAML persistence. A custom adapter must implement the exported `SamlCapableStorage` contract. Own Auth fails when SAML is configured with storage that does not provide that capability.

## Create A Connection

Only an organisation owner can create or manage a SAML connection. The first connection also requires that owner to have a non-SAML sign-in method, so a configuration mistake cannot lock every owner out.

```ts
const connection = await auth.saml.createConnection({
  organisationId: organisation.id,
  actorUserId: currentUser.id,
  name: "Company SSO",
  idpEntityId: "https://idp.example.com/saml/metadata",
  ssoUrl: "https://idp.example.com/saml/sso",
  idpCertificates: [process.env.IDP_SIGNING_CERTIFICATE!],
  attributeMapping: {
    email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
  },
  jitProvisioning: {
    enabled: true,
    defaultRole: "member",
  },
});
```

`attributeMapping.subject` defaults to the assertion's `NameID`. Set it only when the identity provider uses another stable attribute as its subject.

The generated connection key and the identity provider entity ID are immutable. Update certificates, URLs, attribute mappings, account-linking behavior, or JIT settings with `auth.saml.updateConnection`. Disable a connection instead of deleting and reusing its identity.

## Configure The Identity Provider

Use the connection ID to load the service-provider metadata:

```text
https://auth.example.com/api/auth/saml/metadata?connectionId=samlc_...
```

The metadata contains the exact service-provider entity ID and assertion consumer service URL for that connection. Configure the identity provider from this metadata instead of entering those values independently.

The assertion consumer service endpoint is:

```text
https://auth.example.com/api/auth/saml/acs
```

Own Auth accepts up to ten identity-provider signing certificates on one connection. Keep the old and new certificates configured together during certificate rotation, then remove the old certificate after the identity provider finishes rotating.

## Start Sign-In

The application chooses the SAML connection. Own Auth does not discover a connection from an email domain.

```ts
const { url } = await auth.saml.createSignInUrl({
  connectionId: connection.id,
  destination: "/dashboard",
  request: {
    ipAddress: trustedClientIp,
    userAgent: request.headers.get("user-agent") ?? undefined,
  },
});

return Response.redirect(url);
```

The destination must pass the normal `redirectAllowlist` rules. When the identity provider posts the response to the assertion consumer service, the handler validates it, sets the session or MFA cookie, and returns to that destination.

Browser applications can use the TypeScript client:

```ts
await authClient.signInWithSaml({
  connectionId: connection.id,
  destination: "/dashboard",
});
```

## Link An Existing User

Explicit account linking is the default. If a signed assertion contains an email that already belongs to a user, Own Auth returns `account_linking_required` instead of linking silently.

After that user signs in through another method, start a linking flow:

```ts
const { url } = await auth.saml.createLinkUrl({
  connectionId: connection.id,
  actorUserId: currentUser.id,
  destination: "/account/security",
});
```

The browser client provides the matching helper:

```ts
await authClient.linkSaml({
  connectionId: connection.id,
  destination: "/account/security",
});
```

Set `accountLinking: "verified_email"` on a connection only when the identity provider's signed email attribute is trusted to identify the same person. An untrusted or missing email is never used for automatic linking or JIT provisioning.

Unlink an identity only after the user has another usable authentication method:

```ts
await auth.saml.unlinkIdentity({
  connectionId: connection.id,
  actorUserId: currentUser.id,
});
```

## JIT Provisioning

With JIT provisioning enabled, a first SAML sign-in can atomically create:

- the Own Auth user
- the hashed SAML account identity
- a non-owner organisation membership
- the corresponding audit events

The configured default role must exist in the application's authorization configuration and cannot be `owner`. Own Auth does not trust role or group assertions from the identity provider. A member who was removed from the organisation is not silently re-added by a later SAML sign-in.

Without JIT provisioning, the user must already have an active membership in the organisation.

## Request Signing

Identity providers that require signed authentication requests can use RSA-SHA256 request signing:

```ts
const connection = await auth.saml.createConnection({
  // ...connection fields
  requestSigning: {
    privateKey: process.env.SAML_REQUEST_SIGNING_PRIVATE_KEY!,
    certificate: process.env.SAML_REQUEST_SIGNING_CERTIFICATE!,
  },
});
```

Request signing requires the shared `encryption` key ring. Own Auth encrypts the private key with the `saml-request-signing` purpose and never returns it from connection reads.

## MFA

SAML is an `aal1` first factor. A user with Own Auth MFA enabled receives `mfa_required`, and no session is created until TOTP, a recovery code, or a passkey completes the challenge.

## HTTP Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/auth/saml/start` | Start sign-in or identity linking and return the identity-provider URL |
| `POST` | `/api/auth/saml/acs` | Receive the identity provider's form-post response |
| `GET` | `/api/auth/saml/metadata?connectionId=...` | Return service-provider metadata for one connection |

The SAML routes return `404` when SAML is not configured. The assertion consumer service accepts only `application/x-www-form-urlencoded` bodies and enforces a 64 KiB limit.

## Security Model

Own Auth:

- requires a valid response-level or assertion-level signature from one of the connection's trusted certificates
- checks the issuer, audience, destination, recipient, request ID, time window, and stable subject
- rejects SHA-1 signature and digest algorithms
- stores only peppered, purpose-separated hashes of request IDs, relay state, assertion IDs, and SAML subjects
- atomically consumes the transaction and assertion replay record before identity or session work
- limits starts to 20 per IP and connection per 10 minutes and callbacks to 30 per IP and connection per 10 minutes when an IP is available
- keeps precise protocol diagnostics server-side while redirects expose only a generic SAML failure
- excludes raw SAML responses, assertions, subjects, certificates, private keys, and relay state from audit metadata

SAML identities are stored under a provider such as `saml.saml_...`. The provider account ID is a domain-separated hash of the connection key and assertion subject. Own Auth does not store the raw `NameID`. A future support lookup by raw `NameID` would therefore require both the connection and the raw value so the same hash can be recomputed.

## Current Scope

This release does not include identity-provider-initiated sign-in, single logout, encrypted assertions, remote metadata fetching, group or role mapping, SCIM provisioning, or an Own Auth identity-provider mode.
