# OAuth Transaction Derivation

This note documents an intentional difference from OAuth implementations that store state, PKCE verifier, and nonce as separate database values.

Own Auth generates a 256 bit random browser proof and derives state as SHA256 of `"own-auth:oauth:browser:v1:" + browserBindingToken`. It stores only the peppered hash of that state. The state is sent to the provider and comes back through the callback. The proof stays in the initiating browser's protected cookie or application server session and is never sent to the provider.

The existing transaction cannot identify the initiating browser before a first session exists. The temporary cookie supplies that missing proof without adding another transaction store or changing the durable adapter schema. Cookie names include the state so independent attempts do not overwrite each other. HTTPS cookies use the `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=None`, and `Path=/` without a Domain attribute. HTTP localhost uses an unprefixed development cookie with `SameSite=Lax`. Apple's form callback needs HTTPS.

The PKCE verifier and OIDC nonce are deterministic HMAC-SHA256 derivations of the raw state:

```text
PKCE verifier = HMAC(raw state, "own-auth:oauth:pkce:v1")
OIDC nonce    = HMAC(raw state, "own-auth:oauth:nonce:v1")
```

The domain labels make the values independent. The verifier and nonce are intentionally never persisted, which removes two callback secrets from storage without weakening their entropy.

At callback time Own Auth:

1. reads browser proof from the protected cookie or application server session
2. requires a correctly formatted proof and compares its derived state with the returned state using a constant time comparison
3. hashes the returned state with the token pepper
4. atomically consumes the matching transaction
5. rejects missing, expired, consumed, or provider mismatched transactions
6. derives the PKCE verifier and nonce from the state
7. exchanges the authorization code and verifies the provider response
8. clears the transaction's browser cookie on completion or a consumed provider failure

State is consumed before code exchange. A failed provider exchange therefore burns that transaction and cannot be replayed.

Missing or mismatched browser proof fails before transaction consumption or provider access, so another browser cannot burn a valid transaction. Older transactions without browser proof must be restarted after upgrading. Google One Tap continues to use its existing nonce transaction and JSON origin checks.

Do not replace this helper with stored verifier or nonce columns unless the transaction threat model and migration contract are deliberately changed.
