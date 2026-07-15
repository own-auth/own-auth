# API Keys

## Create a key

```ts
const current = await auth.requireCurrentSession(sessionToken);

const { apiKey, rawKey } = await auth.createApiKey({
  actorUserId: current.user.id,
  name: "Production",
  scopes: ["read", "write"],
});

// rawKey            -> "oa_a8f2c1d9_..."
// apiKey.id         -> "key_x1y2z3..."
// apiKey.keyPrefix  -> "a8f2c1d9"
// apiKey.name       -> "Production"
// apiKey.scopes     -> ["read", "write"]
// apiKey.createdAt  -> Date
```

`rawKey` is the complete API key. It is returned only by `createApiKey` and cannot be recovered later. Show it once with a copy action and tell the user to store it securely.

Own Auth stores the visible `keyPrefix` and a hash of the complete key. It never stores the raw key.

### Create an organisation key

```ts
const { apiKey, rawKey } = await auth.createApiKey({
  name: "Production integration",
  organisationId,
  actorUserId: currentUser.id,
  scopes: ["reports:read", "reports:write"],
  expiresAt: new Date("2027-01-01T00:00:00.000Z"),
});
```

Own Auth requires the actor to have `manage_api_keys` permission for the organisation. Key creation is rate-limited and writes an `api_key.created` audit event.

## List a user's keys

```ts
const current = await auth.requireCurrentSession(sessionToken);
const keys = await auth.listApiKeys({
  actorUserId: current.user.id,
});

// keys -> [
//   {
//     id: "key_...",
//     keyPrefix: "abc12345",
//     name: "Production",
//     scopes: ["read", "write"],
//     status: "active",
//     createdAt: new Date("2026-07-11T..."),
//     lastUsedAt: null,
//   },
// ]
```

Returns metadata only. The raw key and its stored hash are never returned.

### List an organisation's keys

```ts
const keys = await auth.listApiKeys({
  organisationId,
  actorUserId: currentUser.id,
});

// keys -> [
//   {
//     id: "key_...",
//     keyPrefix: "abc12345",
//     name: "Production",
//     scopes: ["read", "write"],
//     status: "active",
//   },
// ]
```

Use `keyPrefix`, `name`, `scopes`, `status`, `createdAt`, `lastUsedAt`, and `expiresAt` when displaying keys.

Without `organisationId`, Own Auth returns only the actor's keys. With `organisationId`, Own Auth requires the actor to have `manage_api_keys` permission for that organisation.

## Verify a key

Read the key from the incoming request on the backend and pass it to `verifyApiKey`:

```ts
const authorization = request.headers.get("authorization") ?? "";
const rawKey = authorization.replace(/^Bearer\s+/i, "");

const { apiKey, user, organisation } = await auth.verifyApiKey(rawKey);
```

Own Auth checks the key format, hashes the incoming value, compares the hash, rejects revoked or expired keys, updates `lastUsedAt`, and writes an audit event. Personal keys also stop authenticating when their owning user is missing or disabled; organisation keys stop authenticating when their organisation is missing or disabled. The result contains the key metadata and its associated user or organisation.

Invalid keys throw `AuthError` rather than returning `null`:

```ts
import { AuthError } from "own-auth";

try {
  const verified = await auth.verifyApiKey(rawKey);
  // Continue with verified.apiKey, verified.user, or verified.organisation.
} catch (error) {
  if (error instanceof AuthError && error.code === "api_key_invalid") {
    return res.status(401).json({ error: "Invalid API key" });
  }
  throw error;
}
```

### Errors

| Code | When |
|---|---|
| `api_key_invalid` | The key is missing, malformed, unknown, or does not match the stored hash. |
| `api_key_revoked` | The key is revoked, or its owning user or organisation is no longer active. |
| `api_key_expired` | The key has passed its expiry time. |
| `insufficient_scope` | The key does not include every required scope. |

## Scopes

Scopes define what an API key can do. They are plain strings. Own Auth stores and returns them, but the application decides what they mean.

API-key scopes are separate from organisation role permissions. Configure organisation access through `authorization`, then decide in application code whether an API-key scope maps to the same product action.

```ts
const current = await auth.requireCurrentSession(sessionToken);

const { rawKey } = await auth.createApiKey({
  actorUserId: current.user.id,
  name: "Read only",
  scopes: ["read"],
});

const { rawKey: fullKey } = await auth.createApiKey({
  actorUserId: current.user.id,
  name: "Full access",
  scopes: ["read", "write", "delete"],
});
```

Define scopes based on the product. Common patterns include `read` and `write`, `api:read` and `api:write`, or resource-specific scopes such as `users:read` and `billing:write`.

If no scopes are provided, the key has no scopes. The application decides whether a scopeless key has full access or no access.

### Require scopes

Pass the scopes required by the operation as the second argument:

```ts
const verified = await auth.verifyApiKey(rawKey, ["read"]);
```

Own Auth throws `insufficient_scope` when any required scope is missing.

### Wildcard scope

The `*` scope satisfies every scope check.

```ts
const { rawKey } = await auth.createApiKey({
  name: "Administrative integration",
  organisationId,
  actorUserId: currentUser.id,
  scopes: ["*"],
});
```

Reserve wildcard keys for tightly controlled integrations. Prefer narrow scopes for normal use.

## Revoke a key

```ts
const revoked = await auth.revokeApiKey({
  keyPrefix: apiKey.keyPrefix,
  actorUserId: currentUser.id,
});
```

The key stops authenticating immediately. Revocation cannot be reversed, so the user must create a new key when access is needed again.

Own Auth checks that the actor owns a user key or has `manage_api_keys` permission for an organisation key before revoking it.

## Expire a key

Set `expiresAt` when creating a key that should stop working automatically. An expired key is not marked as revoked, but verification rejects it with `api_key_expired`.

## Rotate a key

Rotation is a three-step process:

1. Create a new key.
2. Update the integration to use the new raw key.
3. Revoke the old key after the integration is working.

Keeping both keys active briefly allows an integration to move without downtime.

## Key format

Application API keys use this format:

```text
oa_<visible-prefix>_<secret>
```

| Part | Description |
|---|---|
| `oa` | Identifies the value as an Own Auth application API key. |
| `<visible-prefix>` | Locates the stored key record without exposing the secret. |
| `<secret>` | A cryptographically random base64url value. |

The visible prefix is stored as `keyPrefix`. The complete raw key is hashed with the token pepper before storage.

## Security

- **Stored hashed:** Database access alone does not reveal a usable API key.
- **Shown once:** Only `createApiKey` returns the raw key.
- **Never logged:** Audit events identify keys by record ID and never include the raw key.
- **Scoped:** `verifyApiKey` can require explicit scopes for each operation.
- **Revocable:** Revoked keys stop working immediately while their history remains available.
- **Creation limited:** Each user or organisation can create up to 20 keys per hour.

## Next step

Learn about the [Security Model](/docs/security-model), or use [Audit Logs](/docs/audit-logs) to review API-key creation, use, and revocation events.
