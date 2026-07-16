# Authorization Server Cryptography

Authorization interactions store only a hash of the browser-visible interaction token.

The request payload and OIDC nonce use the shared encryption key ring with a dedicated HKDF label:

```text
own-auth:authorization-request:v1
```

Authenticated metadata separates full authorization requests from OIDC nonce records. This purpose must not be reused for TOTP secrets or external-provider refresh credentials.

ID tokens use RS256. The current private key signs new tokens. JWKS publishes the current public key and configured previous public keys.

Access and refresh tokens are opaque random values. Only peppered hashes are stored.

Refresh rotation is a storage-level atomic operation. Reuse revokes the grant and every access and refresh token in its family, including a replacement token created by a concurrent winning request.
