import { AuthError } from "./errors.js";
import type { User } from "./types.js";
import {
  minute,
  type DeliveryResult,
  type RequestEmailVerificationInput,
  type RequestTokenInput,
  type ResetPasswordInput,
  type SessionResult,
  type VerifyTokenInput
} from "./auth-engine-types.js";
import {
  assertRedirectAllowed,
  assertUserEnabled,
  audit,
  consumeToken,
  createSession,
  hashPasswordInput,
  type AuthEngineContext
} from "./auth-engine-internals.js";
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
): Promise<SessionResult> {
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

  assertUserEnabled(user);

  if (!user.emailVerifiedAt && token.email) {
    user = (await ctx.storage.updateUser(user.id, {
      emailVerifiedAt: new Date(),
      updatedAt: new Date()
    })) ?? user;
  }

  const result = await createSession(ctx, user, input.request);

  await audit(ctx, {
    eventType: "magic_link.used",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request
  });
  await audit(ctx, {
    eventType: "user.signed_in",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request,
    metadata: { method: "magic_link" }
  });

  return result;
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

  const updatedUser = await ctx.storage.updateUser(user.id, {
    emailVerifiedAt: new Date(),
    updatedAt: new Date()
  });

  await audit(ctx, {
    eventType: "email.verified",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request
  });

  return updatedUser ?? user;
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
  const token = await consumeToken(ctx, input.token, "password_reset");
  const user = token.userId ? await ctx.storage.getUserById(token.userId) : null;

  if (!user) {
    throw new AuthError("invalid_token", "Invalid token", 401);
  }

  const passwordHash = await hashPasswordInput(ctx, input.newPassword);
  const updatedUser = await ctx.storage.updateUser(user.id, {
    passwordHash,
    updatedAt: new Date()
  });
  await revokeAllSessionsForUser(ctx, user.id, "password_reset");

  await audit(ctx, {
    eventType: "password.changed",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request
  });

  return updatedUser ?? user;
}
