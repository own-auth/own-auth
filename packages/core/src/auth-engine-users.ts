import { AuthError } from "./errors.js";
import { normalizeEmail } from "./normalise.js";
import type { RequestContext, User } from "./types.js";
import {
  minute,
  type ChangePasswordInput,
  type CreateUserInput,
  type SessionResult,
  type SignInEmailPasswordInput,
  type SignUpEmailPasswordInput,
  type SignInResult,
  type UserStatusInput
} from "./auth-engine-types.js";
import {
  accountFor,
  assertUserEnabled,
  audit,
  hashPasswordInput,
  rateLimit,
  requireValidEmail,
  requireValidPhone,
  userFor,
  type AuthEngineContext
} from "./auth-engine-internals.js";
import { completeFirstFactor } from "./auth-engine-mfa.js";
import {
  requireCurrentSession,
  revokeAllSessionsForUser,
  revokeOtherSessions
} from "./auth-engine-sessions.js";
import type { CloudCommandPayload } from "./cloud-types.js";

export async function createUser(ctx: AuthEngineContext, input: CreateUserInput): Promise<User> {
  const email = input.email === undefined ? null : requireValidEmail(input.email);
  const phone = input.phone === undefined ? null : requireValidPhone(input.phone);

  if (email && (await ctx.storage.getUserByEmail(email))) {
    throw new AuthError("email_already_exists", "A user already exists with that email", 409);
  }

  if (phone && (await ctx.storage.getUserByPhone(phone))) {
    throw new AuthError("phone_already_exists", "A user already exists with that phone", 409);
  }

  const now = new Date();
  const passwordHash = input.password === undefined
    ? null
    : await hashPasswordInput(ctx, input.password);
  const user = await ctx.storage.createUser(
    userFor({
      email,
      emailVerifiedAt: null,
      phone,
      phoneVerifiedAt: null,
      passwordHash,
      name: input.name,
      imageUrl: input.imageUrl,
      metadata: input.metadata
    },
    now
    )
  );

  if (email && passwordHash) {
    await ctx.storage.createAccount(accountFor(user.id, "password", email, email, null, now));
  }

  if (email && !passwordHash) {
    await ctx.storage.createAccount(accountFor(user.id, "magic_link", email, email, null, now));
  }

  if (phone) {
    await ctx.storage.createAccount(accountFor(user.id, "phone", phone, null, phone, now));
  }

  return user;
}

export async function signUpEmailPassword(
  ctx: AuthEngineContext,
  input: SignUpEmailPasswordInput
): Promise<SessionResult> {
  const email = normalizeEmail(input.email);
  await rateLimit(ctx, "signup", email, 5, 10 * minute);

  const user = await createUser(ctx, {
    email,
    password: input.password,
    name: input.name,
    metadata: input.metadata
  });

  await audit(ctx, {
    eventType: "user.signed_up",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request,
    metadata: { provider: "password" }
  });

  const result = await completeFirstFactor(ctx, user, "password", input.request);
  if (result.status !== "complete") {
    throw new Error("A new user cannot require an existing MFA factor");
  }
  return result;
}

export async function signInEmailPassword(
  ctx: AuthEngineContext,
  input: SignInEmailPasswordInput
): Promise<SignInResult> {
  const email = normalizeEmail(input.email);
  await rateLimit(ctx, "signin", email, 10, 10 * minute);

  const user = await ctx.storage.getUserByEmail(email);
  if (!user?.passwordHash) {
    throw new AuthError("invalid_credentials", "Invalid email or password", 401);
  }

  assertUserEnabled(user);

  if (!(await ctx.passwordHasher.verify(input.password, user.passwordHash))) {
    throw new AuthError("invalid_credentials", "Invalid email or password", 401);
  }

  let authenticatedUser = user;
  if (ctx.passwordHasher.needsRehash(user.passwordHash)) {
    const rehashedUser = await ctx.storage.updateUser(user.id, {
      passwordHash: await ctx.passwordHasher.hash(input.password),
      updatedAt: new Date()
    });
    if (!rehashedUser) {
      throw new AuthError("invalid_credentials", "Invalid email or password", 401);
    }
    authenticatedUser = rehashedUser;
  }

  return completeFirstFactor(ctx, authenticatedUser, "password", input.request);
}

export async function changePassword(
  ctx: AuthEngineContext,
  input: ChangePasswordInput
): Promise<User> {
  const currentSession = await requireCurrentSession(ctx, input.sessionToken);
  const { user } = currentSession;
  await rateLimit(ctx, "change-password", user.id, 5, 10 * minute);

  if (!user.passwordHash) {
    throw new AuthError("invalid_credentials", "Invalid current password", 401);
  }

  if (!(await ctx.passwordHasher.verify(input.currentPassword, user.passwordHash))) {
    throw new AuthError("invalid_credentials", "Invalid current password", 401);
  }

  const updatedUser = await ctx.storage.updateUser(user.id, {
    passwordHash: await hashPasswordInput(ctx, input.newPassword),
    updatedAt: new Date()
  });
  if (!updatedUser) {
    throw new AuthError("invalid_session", "Invalid or expired session", 401);
  }

  await revokeOtherSessions(
    ctx,
    user.id,
    currentSession.session.id,
    "password_changed"
  );

  await audit(ctx, {
    eventType: "password.changed",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request
  });

  return updatedUser;
}

export async function disableUser(ctx: AuthEngineContext, input: UserStatusInput): Promise<User> {
  return setUserDisabled(ctx, input, true);
}

export async function enableUser(ctx: AuthEngineContext, input: UserStatusInput): Promise<User> {
  return setUserDisabled(ctx, input, false);
}

export async function executeCloudUserCommand(
  ctx: AuthEngineContext,
  input: CloudCommandPayload
): Promise<void> {
  if (input.action === "user.revoke-sessions") {
    await revokeAllSessionsForUser(
      ctx,
      input.userId,
      "cloud_command",
      input.initiatedBy
    );
    return;
  }
  const disabled = input.action === "user.disable";
  const result = await setUserDisabledState(ctx, {
    userId: input.userId,
    disabled,
    actorUserId: input.initiatedBy,
    sessionRevokeReason: "cloud_command"
  });
  if (!result.changed) return;
  await audit(ctx, {
    eventType: disabled ? "user.disabled" : "user.re_enabled",
    actorUserId: input.initiatedBy,
    targetUserId: input.userId,
    metadata: { reason: input.reason, source: "cloud" }
  });
}

async function setUserDisabled(
  ctx: AuthEngineContext,
  input: UserStatusInput,
  disabled: boolean
): Promise<User> {
  const action = disabled ? "disable" : "enable";
  if (input.actorUserId !== input.userId) {
    throw new AuthError(
      "permission_denied",
      `Users can only ${action} their own account`,
      403
    );
  }

  const result = await setUserDisabledState(ctx, {
    userId: input.userId,
    disabled,
    actorUserId: input.actorUserId,
    request: input.request
  });
  if (!result.changed) return result.user;

  await audit(ctx, {
    eventType: disabled ? "user.disabled" : "user.re_enabled",
    actorUserId: input.actorUserId,
    targetUserId: input.userId,
    context: input.request,
    metadata: { reason: input.reason ?? "manual" }
  });

  return result.user;
}

interface SetUserDisabledStateInput {
  userId: string;
  disabled: boolean;
  actorUserId: string;
  request?: RequestContext;
  sessionRevokeReason?: string;
}

export async function setUserDisabledState(
  ctx: AuthEngineContext,
  input: SetUserDisabledStateInput
): Promise<{ user: User; changed: boolean }> {
  const user = await ctx.storage.getUserById(input.userId);
  if (!user) {
    throw new AuthError("user_not_found", "User not found", 404);
  }
  if (Boolean(user.disabledAt) === input.disabled) {
    return { user, changed: false };
  }

  const now = new Date();
  const updated = await ctx.storage.updateUser(user.id, {
    disabledAt: input.disabled ? now : null,
    updatedAt: now
  });
  if (!updated) throw new AuthError("user_not_found", "User not found", 404);

  if (input.disabled) {
    await revokeAllSessionsForUser(
      ctx,
      user.id,
      input.sessionRevokeReason ?? "user_disabled",
      input.actorUserId,
      input.request
    );
  }

  return { user: updated, changed: true };
}
