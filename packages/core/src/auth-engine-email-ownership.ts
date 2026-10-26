import { createId } from "./crypto.js";
import { AuthError, isAuthError } from "./errors.js";
import type { AtomicEmailOwnershipInput } from "./auth-storage-atomic.js";
import type { RequestContext, User } from "./types.js";
import {
  accountFor,
  assertUserEnabled,
  audit,
  hash,
  userFor,
  type AuthEngineContext
} from "./auth-engine-internals.js";

export async function claimEmailOwnership(
  ctx: AuthEngineContext,
  input: {
    user: User | null;
    email: string;
    proof: AtomicEmailOwnershipInput["proof"];
    sessionToken?: string;
    passwordHash?: string;
    verifiedAccountId?: string;
    request?: RequestContext;
    metadata?: Record<string, unknown>;
  }
): Promise<User> {
  if (input.user?.emailVerifiedAt &&
    !(input.proof.kind === "token" && input.proof.type === "password_reset")) {
    assertUserEnabled(input.user);
    if (input.proof.kind === "provider") return input.user;
  }
  const now = new Date();
  const replacement = userFor({
    email: input.email,
    emailVerifiedAt: now,
    phone: null,
    phoneVerifiedAt: null,
    passwordHash: input.passwordHash ?? null
  }, now);
  const operation: AtomicEmailOwnershipInput = {
    operationId: createId("op"),
    sourceUserId: input.user?.id ?? null,
    email: input.email,
    verifiedAt: now,
    replacementUser: replacement,
    replacementAccount: accountFor(
      replacement.id,
      input.passwordHash ? "password" : "magic_link",
      input.email,
      input.email,
      null,
      now
    ),
    proof: input.proof,
    sessionTokenHash: input.sessionToken ? hash(ctx, input.sessionToken) : null,
    passwordHash: input.passwordHash,
    verifiedAccountId: input.verifiedAccountId
  };
  let outcome;
  try {
    outcome = await ctx.storage.claimEmailOwnershipAtomically(operation);
  } catch (error) {
    // A concurrent first claim can win the unique email before this statement inserts.
    if (input.user || !isAuthError(error) || error.code !== "email_already_exists") throw error;
    outcome = null;
  }
  if (!outcome && !input.user) {
    const concurrentOwner = await ctx.storage.getUserByEmail(input.email);
    if (concurrentOwner) {
      operation.sourceUserId = concurrentOwner.id;
      outcome = await ctx.storage.claimEmailOwnershipAtomically(operation);
    }
  }
  if (!outcome) {
    if (input.proof.kind === "token") {
      const token = await ctx.storage.getTokenByHash(input.proof.tokenHash, input.proof.type);
      if (token?.usedAt) throw new AuthError("token_already_used", "Token has already been used", 401);
      if (token && token.expiresAt <= new Date()) throw new AuthError("expired_token", "Token has expired", 401);
    }
    throw new AuthError("invalid_token", "Email ownership proof is invalid or expired", 401);
  }
  const { user } = outcome;
  if (operation.sourceUserId) {
    for (const member of outcome.reassignedMemberships) {
      await ctx.cloud?.recordEmailMembershipReassigned(operation.sourceUserId, member, input.request);
      await audit(ctx, {
        eventType: "email.membership_reassigned",
        targetUserId: user.id,
        organisationId: member.organisationId,
        context: input.request,
        metadata: { membershipId: member.id, previousUserId: operation.sourceUserId }
      });
    }
  }
  for (const session of outcome.revokedSessions) {
    await ctx.cloud?.recordSessionRevoked(session, input.request);
    await audit(ctx, {
      eventType: "session.revoked",
      targetUserId: session.userId,
      context: input.request,
      metadata: { sessionId: session.id, reason: "email_ownership_changed" }
    });
  }
  if (outcome.created && operation.sourceUserId) {
    await audit(ctx, {
      eventType: "email.removed",
      actorUserId: user.id,
      targetUserId: operation.sourceUserId,
      context: input.request,
      metadata: { reason: "ownership_proved_by_another_account" }
    });
  }
  if (outcome.created) {
    await audit(ctx, {
      eventType: "user.signed_up",
      actorUserId: user.id,
      targetUserId: user.id,
      context: input.request,
      metadata: { provider: input.proof.kind === "token" ? input.proof.type : "external" }
    });
  }
  if (outcome.verified) {
    await audit(ctx, {
      eventType: "email.verified",
      actorUserId: user.id,
      targetUserId: user.id,
      context: input.request,
      metadata: input.metadata
    });
  }
  return user;
}
