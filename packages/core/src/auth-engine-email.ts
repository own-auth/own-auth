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
  assertUserEnabled,
  audit,
  consumeToken,
  getUsableToken,
  hashPasswordInput,
  type AuthEngineContext
} from "./auth-engine-internals.js";
import { completeFirstFactor } from "./auth-engine-mfa.js";
import { requestEmailToken } from "./auth-engine-email-token.js";
import { revokeAllSessionsForUser } from "./auth-engine-sessions.js";
import { createUser } from "./auth-engine-users.js";

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
  const token = await consumeToken(ctx, input.token, "magic_link");
  let user = token.userId ? await ctx.storage.getUserById(token.userId) : null;

  if (!user && token.email) {
    user = await ctx.storage.getUserByEmail(token.email);
  }

  if (!user && token.email && ctx.allowMagicLinkSignup) {
    user = await createUser(ctx, { email: token.email });
  }

  if (!user) {
    throw new AuthError("invalid_token", "Invalid token", 401);
  }
  requireMatchingTokenEmail(user, token.email);

  assertUserEnabled(user);

  if (!user.emailVerifiedAt && token.email) {
    user = requireTokenUser(await ctx.storage.updateUser(user.id, {
      emailVerifiedAt: new Date(),
      updatedAt: new Date()
    }));
  }

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
  const token = await consumeToken(ctx, input.token, "email_verification");
  const user = token.userId ? await ctx.storage.getUserById(token.userId) : null;

  if (!user) {
    throw new AuthError("invalid_token", "Invalid token", 401);
  }
  requireMatchingTokenEmail(user, token.email);

  const updatedUser = requireTokenUser(await ctx.storage.updateUser(user.id, {
    emailVerifiedAt: new Date(),
    updatedAt: new Date()
  }));

  await audit(ctx, {
    eventType: "email.verified",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request
  });

  return updatedUser;
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
  requireMatchingTokenEmail(user, candidate.email);

  const passwordHash = await hashPasswordInput(ctx, input.newPassword);
  await consumeToken(ctx, input.token, "password_reset");
  const updatedUser = requireTokenUser(await ctx.storage.updateUser(user.id, {
    passwordHash,
    updatedAt: new Date()
  }));
  await revokeAllSessionsForUser(ctx, user.id, "password_reset");

  await audit(ctx, {
    eventType: "password.changed",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request
  });

  return updatedUser;
}

function requireMatchingTokenEmail(user: User, tokenEmail: string | null): void {
  if (
    !tokenEmail ||
    !user.email ||
    normalizeEmail(user.email) !== normalizeEmail(tokenEmail)
  ) {
    throw new AuthError("invalid_token", "Invalid token", 401);
  }
}

function requireTokenUser(user: User | null): User {
  if (!user) {
    throw new AuthError("invalid_token", "Invalid token", 401);
  }
  return user;
}
