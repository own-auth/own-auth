import { createId, randomBase64Url } from "./crypto.js";
import { requireEncryptionKeyRing } from "./encryption.js";
import { AuthError, isAuthError } from "./errors.js";
import {
  createOAuthBrowserBinding,
  deriveOAuthSecrets,
  matchesOAuthBrowserBinding
} from "./oauth-derivation.js";
import { requireOAuthProvider } from "./oauth-registry.js";
import { OAuthCallbackError } from "./oauth-types.js";
import { normalizeTrustedWebOrigin } from "./url-security.js";
import type { Account, ExternalAccountProvider, RequestContext } from "./types.js";
import {
  minute,
  type CompleteOAuthSignInInput,
  type CreateOAuthAuthorizationUrlInput,
  type GoogleOneTapInput,
  type OAuthAuthorizationResult,
  type OAuthCompletionResult,
  type PrepareGoogleOneTapInput,
  type PreparedGoogleOneTap
} from "./auth-engine-types.js";
import {
  assertRedirectAllowed,
  audit,
  hash,
  rateLimit,
  type AuthEngineContext
} from "./auth-engine-internals.js";
import {
  createExternalProviderSession,
  resolveExternalIdentity
} from "./auth-engine-external.js";
import { traceOAuthProvider } from "./telemetry.js";

const oauthTransactionTtlMs = 10 * minute;

export async function createOAuthAuthorizationUrl(
  ctx: AuthEngineContext,
  input: CreateOAuthAuthorizationUrlInput
): Promise<OAuthAuthorizationResult> {
  const provider = requireOAuthProvider(ctx.oauthProviders, input.provider);
  await rateLimitByIp(ctx, "oauth-start", input.request?.ipAddress, 20, 10 * minute);
  assertRedirectAllowed(ctx, input.destination);
  const mode = input.mode ?? "redirect";
  const openerOrigin = mode === "popup" ? requireOpenerOrigin(ctx, input.openerOrigin) : null;
  const intent = input.intent ?? "sign_in";
  if (intent === "link" && !input.actorUserId) {
    throw new AuthError("validation_error", "actorUserId is required to link a provider", 400);
  }

  const { state, browserBindingToken } = createOAuthBrowserBinding();
  const { codeVerifier, nonce } = await deriveOAuthSecrets(state);
  const codeChallenge = await import("oauth4webapi").then((oauth) =>
    oauth.calculatePKCECodeChallenge(codeVerifier)
  );
  const now = new Date();
  const expiresAt = new Date(now.getTime() + oauthTransactionTtlMs);
  await ctx.storage.createOAuthTransaction({
    id: createId("oat"),
    provider: input.provider,
    flowKind: "redirect",
    intent,
    stateHash: hash(ctx, state),
    destination: input.destination ?? null,
    interactionMode: mode,
    openerOrigin,
    userId: input.actorUserId ?? null,
    expiresAt,
    consumedAt: null,
    createdAt: now
  });
  const url = await traceOAuthProvider(input.provider, "authorization", () =>
    provider.createAuthorizationUrl({ state, codeChallenge, nonce })
  );
  await audit(ctx, {
    eventType: "oauth.started",
    actorUserId: input.actorUserId ?? null,
    targetUserId: input.actorUserId ?? null,
    context: input.request,
    metadata: { provider: input.provider, intent, mode }
  });
  return { url: url.toString(), expiresAt, state, browserBindingToken };
}

export async function completeOAuthSignIn(
  ctx: AuthEngineContext,
  input: CompleteOAuthSignInInput
): Promise<OAuthCompletionResult> {
  const provider = requireOAuthProvider(ctx.oauthProviders, input.provider);
  await rateLimitByIp(ctx, "oauth-callback", input.request?.ipAddress, 30, 10 * minute);
  const state = input.callbackParameters.get("state");
  if (!state || !matchesOAuthBrowserBinding(state, input.browserBindingToken)) {
    await auditOAuthFailure(ctx, input.provider, "oauth_transaction_invalid", input.request);
    throw new AuthError("oauth_transaction_invalid", "OAuth transaction is invalid", 400);
  }
  const transaction = await ctx.storage.consumeOAuthTransaction(
    hash(ctx, state),
    "redirect",
    new Date()
  );
  if (!transaction || transaction.provider !== input.provider) {
    await auditOAuthFailure(
      ctx,
      input.provider,
      "oauth_transaction_invalid",
      input.request,
      transaction?.userId ?? null
    );
    throw new AuthError("oauth_transaction_invalid", "OAuth transaction is invalid or expired", 400);
  }

  try {
    const { codeVerifier, nonce } = await deriveOAuthSecrets(state);
    const exchanged = await traceOAuthProvider(input.provider, "exchange", () =>
      provider.exchangeCode({
        callbackParameters: input.callbackParameters,
        state,
        codeVerifier,
        nonce
      })
    );
    if (transaction.expiresAt.getTime() <= Date.now()) {
      throw new AuthError("oauth_transaction_invalid", "OAuth transaction is invalid or expired", 400);
    }
    const resolved = await resolveExternalIdentity(ctx, exchanged.identity, {
      authorityExpiresAt: transaction.expiresAt,
      intent: transaction.intent,
      userId: transaction.userId ?? undefined,
      request: input.request
    });
    if (provider.offlineAccess && exchanged.refreshToken) {
      await storeProviderCredential(ctx, resolved.account, exchanged.refreshToken, exchanged.scopes);
    }
    if (transaction.intent === "link") {
      return completionMetadata(transaction, {
        status: "linked",
        account: resolved.account
      });
    }

    const session = await createExternalProviderSession(
      ctx,
      resolved.user,
      input.provider,
      input.request,
      transaction.expiresAt
    );
    await audit(ctx, {
      eventType: "oauth.signed_in",
      actorUserId: resolved.user.id,
      targetUserId: resolved.user.id,
      context: input.request,
      metadata: { provider: input.provider, mode: transaction.interactionMode }
    });
    return completionMetadata(transaction, session);
  } catch (error) {
    const knownError = isAuthError(error) ? error : null;
    await auditOAuthFailure(
      ctx,
      input.provider,
      knownError?.code ?? "oauth_provider_error",
      input.request,
      transaction.userId
    );
    const authError = knownError
      ? knownError
      : new AuthError("oauth_provider_error", "OAuth sign-in failed", 502);
    throw new OAuthCallbackError(
      authError.code,
      authError.safeMessage,
      authError.statusCode,
      {
        destination: transaction.destination,
        interactionMode: transaction.interactionMode,
        openerOrigin: transaction.openerOrigin
      },
      error
    );
  }
}

export async function prepareGoogleOneTap(
  ctx: AuthEngineContext,
  input: PrepareGoogleOneTapInput = {}
): Promise<PreparedGoogleOneTap> {
  const provider = requireOAuthProvider(ctx.oauthProviders, "google");
  if (!provider.verifyCredential) {
    throw new AuthError("validation_error", "Google One Tap is not configured", 400);
  }
  await rateLimitByIp(ctx, "one-tap-start", input.request?.ipAddress, 20, 10 * minute);
  const nonce = randomBase64Url(32);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + oauthTransactionTtlMs);
  await ctx.storage.createOAuthTransaction({
    id: createId("oat"),
    provider: "google",
    flowKind: "one_tap",
    intent: "sign_in",
    stateHash: hash(ctx, nonce),
    destination: null,
    interactionMode: "redirect",
    openerOrigin: null,
    userId: null,
    expiresAt,
    consumedAt: null,
    createdAt: now
  });
  await audit(ctx, {
    eventType: "oauth.started",
    context: input.request,
    metadata: { provider: "google", flow: "one_tap" }
  });
  return { nonce, expiresAt };
}

export async function signInWithGoogleOneTap(
  ctx: AuthEngineContext,
  input: GoogleOneTapInput
): Promise<OAuthCompletionResult> {
  const provider = requireOAuthProvider(ctx.oauthProviders, "google");
  const verifyCredential = provider.verifyCredential?.bind(provider);
  if (!verifyCredential) {
    throw new AuthError("validation_error", "Google One Tap is not configured", 400);
  }
  await rateLimitByIp(ctx, "one-tap-verify", input.request?.ipAddress, 30, 10 * minute);
  const transaction = await ctx.storage.consumeOAuthTransaction(
    hash(ctx, input.nonce),
    "one_tap",
    new Date()
  );
  if (!transaction || transaction.provider !== "google") {
    await auditOAuthFailure(
      ctx,
      "google",
      "oauth_transaction_invalid",
      input.request,
      transaction?.userId ?? null,
      "one_tap"
    );
    throw new AuthError("oauth_transaction_invalid", "One Tap transaction is invalid or expired", 400);
  }
  try {
    const identity = await traceOAuthProvider("google", "verify_credential", () =>
      verifyCredential(input.credential, input.nonce)
    );
    if (transaction.expiresAt.getTime() <= Date.now()) {
      throw new AuthError("oauth_transaction_invalid", "One Tap transaction is invalid or expired", 400);
    }
    const resolved = await resolveExternalIdentity(ctx, identity, {
      authorityExpiresAt: transaction.expiresAt,
      intent: "sign_in",
      request: input.request
    });
    const session = await createExternalProviderSession(ctx, resolved.user, "google", input.request, transaction.expiresAt);
    await audit(ctx, {
      eventType: "oauth.signed_in",
      actorUserId: resolved.user.id,
      targetUserId: resolved.user.id,
      context: input.request,
      metadata: { provider: "google", flow: "one_tap" }
    });
    return completionMetadata(transaction, session);
  } catch (error) {
    await auditOAuthFailure(
      ctx,
      "google",
      isAuthError(error) ? error.code : "oauth_provider_error",
      input.request,
      null,
      "one_tap"
    );
    throw error;
  }
}

async function auditOAuthFailure(
  ctx: AuthEngineContext,
  provider: ExternalAccountProvider,
  error: string,
  request?: RequestContext,
  userId: string | null = null,
  flow?: "one_tap"
): Promise<void> {
  await audit(ctx, {
    eventType: "oauth.failed",
    actorUserId: userId,
    targetUserId: userId,
    context: request,
    metadata: { provider, error, ...(flow ? { flow } : {}) }
  });
}

async function storeProviderCredential(
  ctx: AuthEngineContext,
  account: Account,
  refreshToken: string,
  scopes: string[]
): Promise<void> {
  const encryption = requireEncryptionKeyRing(ctx.encryption, "OAuth offline access");
  const encrypted = await encryption.encrypt(refreshToken, "oauth-refresh", {
    accountId: account.id,
    provider: account.provider
  });
  const now = new Date();
  const existing = await ctx.storage.getOAuthCredentialByAccountId(account.id);
  await ctx.storage.upsertOAuthCredential({
    id: existing?.id ?? createId("oac"),
    accountId: account.id,
    provider: account.provider as ExternalAccountProvider,
    ciphertext: encrypted.ciphertext,
    nonce: encrypted.nonce,
    encryptionKeyId: encrypted.encryptionKeyId,
    scopes,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
    rotatedAt: existing ? now : null
  });
  await audit(ctx, {
    eventType: "oauth.credential_stored",
    actorUserId: account.userId,
    targetUserId: account.userId,
    metadata: { provider: account.provider }
  });
}

function completionMetadata<T extends object>(
  transaction: {
    destination: string | null;
    interactionMode: "redirect" | "popup";
    openerOrigin: string | null;
  },
  result: T
): T & {
  destination: string | null;
  interactionMode: "redirect" | "popup";
  openerOrigin: string | null;
} {
  return {
    ...result,
    destination: transaction.destination,
    interactionMode: transaction.interactionMode,
    openerOrigin: transaction.openerOrigin
  };
}

function requireOpenerOrigin(ctx: AuthEngineContext, value?: string): string {
  const origin = value ? normalizeTrustedWebOrigin(value) : null;
  if (!origin) {
    throw new AuthError("redirect_not_allowed", "Popup opener origin is not allowed", 400);
  }
  assertRedirectAllowed(ctx, origin);
  return origin;
}

async function rateLimitByIp(
  ctx: AuthEngineContext,
  action: string,
  ipAddress: string | undefined,
  limit: number,
  windowMs: number
): Promise<void> {
  if (ipAddress) {
    await rateLimit(ctx, action, ipAddress, limit, windowMs);
  }
}
