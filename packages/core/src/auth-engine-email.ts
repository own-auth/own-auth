import { AuthError } from "./errors.js";
import { normalizeEmail } from "./normalise.js";
import type { User } from "./types.js";
import {
  minute,
  type DeliveryResult,
  type RequestEmailVerificationInput,
  type RequestTokenInput,
  type ResetPasswordInput,
  type SignInResult,
  type VerifyTokenInput
} from "./auth-engine-types.js";
import {
  assertRedirectAllowed,
  audit,
  getUsableToken,
  hashPasswordInput,
  type AuthEngineContext
} from "./auth-engine-internals.js";
import { completeFirstFactor } from "./auth-engine-mfa.js";
import { requestEmailToken } from "./auth-engine-email-token.js";
import { revokeAllSessionsForUser } from "./auth-engine-sessions.js";
import { claimEmailOwnership } from "./auth-engine-email-ownership.js";

export async function requestMagicLink(
  ctx: AuthEngineContext,
  input: RequestTokenInput
): Promise<DeliveryResult> {
  assertRedirectAllowed(ctx, input.redirectUrl);

  return requestEmailToken(ctx, {
    email: input.email,
    tokenType: "magic_link",
    emailType: "magic_link",
    urlPath: "/auth/magic-link/verify",
    auditEvent: "magic_link.requested",
    rateLimitKey: "magic-link",
    rateLimitMax: 5,
    rateLimitWindowMs: 10 * minute,
    extraUrlParams: { redirect_url: input.redirectUrl },
    allowMissing: ctx.allowMagicLinkSignup,
    request: input.request
  });
}

export async function verifyMagicLink(
  ctx: AuthEngineContext,
  input: VerifyTokenInput
): Promise<SignInResult> {
  const token = await getUsableToken(ctx, input.token, "magic_link");
  let candidate = token.userId ? await ctx.storage.getUserById(token.userId) : null;

  if (!candidate && !token.userId && token.email) {
    candidate = await ctx.storage.getUserByEmail(token.email);
  }

  if (!token.email || (!candidate && (token.userId || !ctx.allowMagicLinkSignup))) {
    throw new AuthError("invalid_token", "Invalid token", 401);
  }
  if (candidate) requireMatchingTokenEmail(candidate, token.email);
  const user = await claimEmailOwnership(ctx, {
    user: candidate,
    email: token.email,
    proof: { kind: "token", tokenHash: token.tokenHash, type: "magic_link" },
    sessionToken: input.sessionToken,
    request: input.request
  });

  await audit(ctx, {
    eventType: "magic_link.used",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request
  });
  return completeFirstFactor(ctx, user, "magic_link", input.request);
}

export async function requestEmailVerification(
  ctx: AuthEngineContext,
  input: RequestEmailVerificationInput
): Promise<DeliveryResult> {
  return requestEmailToken(ctx, {
    email: input.email,
    tokenType: "email_verification",
    emailType: "email_verification",
    urlPath: "/auth/email/verify",
    auditEvent: "email_verification.requested",
    rateLimitKey: "email-verification",
    rateLimitMax: 5,
    rateLimitWindowMs: 10 * minute,
    request: input.request
  });
}

export async function verifyEmail(
  ctx: AuthEngineContext,
  input: VerifyTokenInput
): Promise<User> {
  const token = await getUsableToken(ctx, input.token, "email_verification");
  const user = token.userId ? await ctx.storage.getUserById(token.userId) : null;

  if (!user) {
    throw new AuthError("invalid_token", "Invalid token", 401);
  }
  const email = requireMatchingTokenEmail(user, token.email);

  return claimEmailOwnership(ctx, {
    user,
    email,
    proof: { kind: "token", tokenHash: token.tokenHash, type: "email_verification" },
    sessionToken: input.sessionToken,
    request: input.request
  });
}

export async function requestPasswordReset(
  ctx: AuthEngineContext,
  input: RequestEmailVerificationInput
): Promise<DeliveryResult> {
  return requestEmailToken(ctx, {
    email: input.email,
    tokenType: "password_reset",
    emailType: "password_reset",
    urlPath: "/auth/password/reset",
    auditEvent: "password_reset.requested",
    rateLimitKey: "password-reset",
    rateLimitMax: 5,
    rateLimitWindowMs: 15 * minute,
    request: input.request
  });
}

export async function resetPassword(
  ctx: AuthEngineContext,
  input: ResetPasswordInput
): Promise<User> {
  const candidate = await getUsableToken(ctx, input.token, "password_reset");
  const user = candidate.userId
    ? await ctx.storage.getUserById(candidate.userId)
    : null;

  if (!user) {
    throw new AuthError("invalid_token", "Invalid token", 401);
  }
  const email = requireMatchingTokenEmail(user, candidate.email);

  const passwordHash = await hashPasswordInput(ctx, input.newPassword);
  const updatedUser = await claimEmailOwnership(ctx, {
    user,
    email,
    proof: { kind: "token", tokenHash: candidate.tokenHash, type: "password_reset" },
    passwordHash,
    sessionToken: input.sessionToken,
    request: input.request
  });
  await revokeAllSessionsForUser(ctx, updatedUser.id, "password_reset");

  await audit(ctx, {
    eventType: "password.changed",
    actorUserId: updatedUser.id,
    targetUserId: updatedUser.id,
    context: input.request
  });

  return updatedUser;
}

function requireMatchingTokenEmail(user: User, tokenEmail: string | null): string {
  if (
    !tokenEmail ||
    !user.email ||
    normalizeEmail(user.email) !== normalizeEmail(tokenEmail)
  ) {
    throw new AuthError("invalid_token", "Invalid token", 401);
  }
  return tokenEmail;
}
