import { AuthError } from "./errors.js";
import { requireEncryptionKeyRing } from "./encryption.js";
import { requireOAuthProvider } from "./oauth-registry.js";
import type { Account, ExternalAccountProvider } from "./types.js";
import type {
  GetExternalAccessTokenInput,
  ExternalAccessTokenResult,
  RevokeExternalProviderAccessInput
} from "./auth-engine-types.js";
import { audit, requireActiveUser, type AuthEngineContext } from "./auth-engine-internals.js";
import { traceOAuthProvider } from "./telemetry.js";

const oauthRefreshEncryptionPurpose = "oauth-refresh" as const;

export async function getExternalAccessToken(
  ctx: AuthEngineContext,
  input: GetExternalAccessTokenInput
): Promise<ExternalAccessTokenResult> {
  const account = await requireOwnedProviderAccount(ctx, input);
  const credential = await ctx.storage.getOAuthCredentialByAccountId(account.id);
  if (!credential) {
    throw missingCredential();
  }
  const encryption = requireEncryptionKeyRing(ctx.encryption, "OAuth offline access");
  const encryptionMetadata = oauthRefreshEncryptionMetadata(account);
  const provider = requireOAuthProvider(ctx.oauthProviders, input.provider);
  const refresh = provider.refresh?.bind(provider);
  if (!refresh) {
    throw new AuthError("validation_error", "This OAuth provider cannot refresh access", 400);
  }
  const decrypted = await encryption.decrypt(
    {
      ciphertext: credential.ciphertext,
      nonce: credential.nonce,
      encryptionKeyId: credential.encryptionKeyId
    },
    oauthRefreshEncryptionPurpose,
    encryptionMetadata
  );
  const refreshed = await traceOAuthProvider(input.provider, "refresh", () =>
    refresh(decrypted.plaintext)
  );
  const scopes = refreshed.scopes.length > 0 ? refreshed.scopes : credential.scopes;
  const replacement = refreshed.refreshToken ?? decrypted.plaintext;
  if (refreshed.refreshToken || decrypted.needsRotation) {
    const encrypted = await encryption.encrypt(
      replacement,
      oauthRefreshEncryptionPurpose,
      encryptionMetadata
    );
    const updatedAt = new Date();
    const rotated = await ctx.storage.rotateOAuthCredential(
      credential.id,
      credential.ciphertext,
      {
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        encryptionKeyId: encrypted.encryptionKeyId,
        scopes,
        updatedAt,
        rotatedAt: refreshed.refreshToken ? updatedAt : credential.rotatedAt
      }
    );
    if (!rotated) {
      throw new AuthError(
        "oauth_provider_error",
        "Provider credentials changed during refresh. Try again.",
        409
      );
    }
  }
  await audit(ctx, {
    eventType: "oauth.credential_refreshed",
    actorUserId: input.actorUserId,
    targetUserId: input.actorUserId,
    context: input.request,
    metadata: { provider: input.provider }
  });
  return {
    accessToken: refreshed.accessToken,
    scopes
  };
}

export async function revokeExternalProviderAccess(
  ctx: AuthEngineContext,
  input: RevokeExternalProviderAccessInput
): Promise<void> {
  const account = await requireOwnedProviderAccount(ctx, input);
  const credential = await ctx.storage.getOAuthCredentialByAccountId(account.id);
  if (!credential) {
    throw missingCredential();
  }
  const encryption = requireEncryptionKeyRing(ctx.encryption, "OAuth offline access");
  const encryptionMetadata = oauthRefreshEncryptionMetadata(account);
  const provider = requireOAuthProvider(ctx.oauthProviders, input.provider);
  const revoke = provider.revoke?.bind(provider);
  if (revoke) {
    const decrypted = await encryption.decrypt(
      {
        ciphertext: credential.ciphertext,
        nonce: credential.nonce,
        encryptionKeyId: credential.encryptionKeyId
      },
      oauthRefreshEncryptionPurpose,
      encryptionMetadata
    );
    await traceOAuthProvider(input.provider, "revoke", () =>
      revoke(decrypted.plaintext)
    );
  }
  if (!await ctx.storage.deleteOAuthCredentialByAccountId(account.id)) {
    throw missingCredential();
  }
  await audit(ctx, {
    eventType: "oauth.credential_revoked",
    actorUserId: input.actorUserId,
    targetUserId: input.actorUserId,
    context: input.request,
    metadata: { provider: input.provider }
  });
}

function oauthRefreshEncryptionMetadata(account: Account): Record<string, string> {
  return { accountId: account.id, provider: account.provider };
}

async function requireOwnedProviderAccount(
  ctx: AuthEngineContext,
  input: {
    actorUserId: string;
    provider: ExternalAccountProvider;
    providerAccountId?: string;
  }
): Promise<Account> {
  await requireActiveUser(ctx, input.actorUserId);
  const accounts = await ctx.storage.listAccountsByUserId(input.actorUserId);
  const matches = accounts.filter(
    (account) =>
      account.provider === input.provider &&
      (!input.providerAccountId || account.providerAccountId === input.providerAccountId)
  );
  if (matches.length !== 1) {
    throw missingCredential();
  }
  return matches[0] as Account;
}

function missingCredential(): AuthError {
  return new AuthError(
    "external_credential_missing",
    "Authenticate with this provider again to grant offline access",
    404
  );
}
