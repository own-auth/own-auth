import { AuthError } from "./errors.js";
import { createId } from "./crypto.js";
import { isValidEmailAddress, normalizeEmail } from "./normalise.js";
import {
  isExternalAccountProvider,
  type VerifiedProviderIdentity
} from "./oauth-types.js";
import type { Account, ExternalAccountProvider, RequestContext, User } from "./types.js";
import {
  minute,
  type LinkOAuthProviderInput,
  type SignInResult,
  type UnlinkOAuthProviderInput,
  type VerifiedExternalIdentityInput
} from "./auth-engine-types.js";
import {
  accountFor,
  assertUserEnabled,
  audit,
  createAuditEvent,
  rateLimit,
  requireActiveUser,
  requireValidEmail,
  userFor,
  type AuthEngineContext
} from "./auth-engine-internals.js";
import { completeFirstFactor } from "./auth-engine-mfa.js";
import { prepareAuthEventWrite } from "./webhook-outbox.js";

export async function signInWithVerifiedExternalIdentity(
  ctx: AuthEngineContext,
  input: VerifiedExternalIdentityInput
): Promise<SignInResult> {
  const identity = normalizeTrustedIdentity(input);
  await rateLimit(ctx, `external-${identity.provider}`, identity.providerAccountId, 20, 10 * minute);
  const resolved = await resolveExternalIdentity(ctx, identity, {
    intent: "sign_in",
    request: input.request,
    metadata: input.metadata
  });
  return createExternalProviderSession(ctx, resolved.user, identity.provider, input.request);
}

export async function linkOAuthProvider(
  ctx: AuthEngineContext,
  input: LinkOAuthProviderInput
): Promise<Account> {
  const actor = await requireActiveUser(ctx, input.actorUserId);
  const identity = normalizeTrustedIdentity(input);
  const resolved = await resolveExternalIdentity(ctx, identity, {
    intent: "link",
    userId: actor.id,
    request: input.request
  });
  return resolved.account;
}

export async function unlinkOAuthProvider(
  ctx: AuthEngineContext,
  input: UnlinkOAuthProviderInput
): Promise<void> {
  const user = await requireActiveUser(ctx, input.actorUserId);
  const provider = normalizeExternalProvider(input.provider);
  const account = await ctx.storage.getAccountByProvider(provider, input.providerAccountId);
  if (!account || account.userId !== user.id) {
    throw new AuthError("invalid_credentials", "External provider account not found", 404);
  }
  const removed = await ctx.storage.removeAuthenticationMethodAtomically({
    operationId: createId("op"),
    userId: user.id,
    method: { kind: "account", id: account.id },
    event: prepareAuthEventWrite(ctx, createAuditEvent({
      eventType: "external_provider.unlinked",
      actorUserId: user.id,
      targetUserId: user.id,
      request: input.request,
      metadata: { provider }
    }))
  });
  if (removed === "last_method") {
    throw new AuthError(
      "authentication_method_required",
      "Add another sign-in method before unlinking this provider",
      409
    );
  }
  if (removed === "not_found") {
    throw new AuthError("invalid_credentials", "External provider account not found", 404);
  }
}

export async function resolveExternalIdentity(
  ctx: AuthEngineContext,
  identity: VerifiedProviderIdentity,
  input: {
    intent: "sign_in" | "link";
    userId?: string;
    request?: RequestContext;
    metadata?: Record<string, unknown>;
  }
): Promise<{ user: User; account: Account }> {
  const existingAccount = await ctx.storage.getAccountByProvider(
    identity.provider,
    identity.providerAccountId
  );
  if (existingAccount) {
    if (input.intent === "link" && existingAccount.userId !== input.userId) {
      throw new AuthError(
        "oauth_account_conflict",
        "This provider account is linked to another user",
        409
      );
    }
    const user = await ctx.storage.getUserById(existingAccount.userId);
    if (!user) {
      throw new AuthError("invalid_credentials", "Invalid external provider account", 401);
    }
    assertUserEnabled(user);
    return { user, account: existingAccount };
  }

  const email = verifiedEmail(identity);
  if (input.intent === "link") {
    if (!input.userId) {
      throw new AuthError("validation_error", "userId is required when linking a provider", 400);
    }
    const user = await requireActiveUser(ctx, input.userId);
    const account = await createLinkedAccount(ctx, user, identity, email, input.request);
    return { user, account };
  }

  if (!email) {
    throw new AuthError(
      "oauth_verified_email_required",
      "A verified provider email is required to create an account",
      409
    );
  }
  const existingUser = await ctx.storage.getUserByEmail(email);
  if (existingUser) {
    assertUserEnabled(existingUser);
    if (ctx.oauthAccountLinking !== "verified_email") {
      throw new AuthError(
        "account_linking_required",
        "Sign in to the existing account before linking this provider",
        409
      );
    }
    const account = await createLinkedAccount(ctx, existingUser, identity, email, input.request);
    return { user: existingUser, account };
  }

  return createExternalUserAndAccount(ctx, identity, email, input);
}

function normalizeTrustedIdentity(input: VerifiedExternalIdentityInput): VerifiedProviderIdentity {
  const provider = normalizeExternalProvider(input.provider);
  const providerAccountId = input.providerAccountId.trim();
  if (!providerAccountId) {
    throw new AuthError("validation_error", "providerAccountId is required", 400);
  }
  const email = input.email === undefined ? null : requireValidEmail(input.email);
  if (email && input.emailVerified !== true) {
    throw new AuthError("validation_error", "External provider email must be verified", 400);
  }
  return {
    provider,
    providerAccountId,
    email,
    emailVerified: input.emailVerified === true,
    name: input.name ?? null,
    imageUrl: input.imageUrl ?? null
  };
}

function normalizeExternalProvider(provider: string): ExternalAccountProvider {
  if (isExternalAccountProvider(provider)) {
    return provider;
  }
  throw new AuthError("validation_error", "Unsupported external provider", 400);
}

function verifiedEmail(identity: VerifiedProviderIdentity): string | null {
  if (!identity.email || !identity.emailVerified) {
    return null;
  }
  const email = normalizeEmail(identity.email);
  if (!isValidEmailAddress(email)) {
    throw new AuthError(
      "oauth_verified_email_required",
      "A valid verified provider email is required to create an account",
      409
    );
  }
  return email;
}

async function createLinkedAccount(
  ctx: AuthEngineContext,
  user: User,
  identity: VerifiedProviderIdentity,
  email: string | null,
  request?: RequestContext
): Promise<Account> {
  try {
    const account = await ctx.storage.createAccount(
      accountFor(user.id, identity.provider, identity.providerAccountId, email, null, new Date())
    );
    await auditLinked(ctx, user.id, identity.provider, request);
    return account;
  } catch (error) {
    const existing = await ctx.storage.getAccountByProvider(
      identity.provider,
      identity.providerAccountId
    );
    if (existing?.userId === user.id) return existing;
    if (existing) {
      throw new AuthError(
        "oauth_account_conflict",
        "This provider account is linked to another user",
        409
      );
    }
    throw error;
  }
}

async function createExternalUserAndAccount(
  ctx: AuthEngineContext,
  identity: VerifiedProviderIdentity,
  email: string,
  input: { request?: RequestContext; metadata?: Record<string, unknown> }
): Promise<{ user: User; account: Account }> {
  const now = new Date();
  const user = userFor({
    email,
    emailVerifiedAt: now,
    phone: null,
    phoneVerifiedAt: null,
    passwordHash: null,
    name: identity.name ?? undefined,
    imageUrl: identity.imageUrl ?? undefined,
    metadata: input.metadata
  }, now);
  const accountInput = accountFor(
    user.id,
    identity.provider,
    identity.providerAccountId,
    email,
    null,
    now
  );
  try {
    const account = await ctx.storage.createUserAndAccount(user, accountInput);
    await audit(ctx, {
      eventType: "user.signed_up",
      actorUserId: user.id,
      targetUserId: user.id,
      context: input.request,
      metadata: { provider: identity.provider }
    });
    await auditLinked(ctx, user.id, identity.provider, input.request);
    return { user, account };
  } catch (error) {
    const account = await ctx.storage.getAccountByProvider(
      identity.provider,
      identity.providerAccountId
    );
    if (account) {
      const winner = await ctx.storage.getUserById(account.userId);
      if (winner) {
        return { user: winner, account };
      }
    }

    const existingUser = await ctx.storage.getUserByEmail(email);
    if (existingUser) {
      assertUserEnabled(existingUser);
      if (ctx.oauthAccountLinking !== "verified_email") {
        throw new AuthError(
          "account_linking_required",
          "Sign in to the existing account before linking this provider",
          409
        );
      }
      const linkedAccount = await createLinkedAccount(
        ctx,
        existingUser,
        identity,
        email,
        input.request
      );
      return { user: existingUser, account: linkedAccount };
    }
    throw error;
  }
}

async function auditLinked(
  ctx: AuthEngineContext,
  userId: string,
  provider: ExternalAccountProvider,
  request?: RequestContext
): Promise<void> {
  await audit(ctx, {
    eventType: "external_provider.linked",
    actorUserId: userId,
    targetUserId: userId,
    context: request,
    metadata: { provider }
  });
}

export async function createExternalProviderSession(
  ctx: AuthEngineContext,
  user: User,
  provider: ExternalAccountProvider,
  request?: RequestContext
): Promise<SignInResult> {
  assertUserEnabled(user);
  return completeFirstFactor(ctx, user, provider, request);
}
