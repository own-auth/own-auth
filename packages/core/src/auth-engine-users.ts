import { AuthError } from "./errors.js";
import {
  createId,
  hashPassword,
  passwordNeedsRehash,
  verifyPassword
} from "./crypto.js";
import { normalizeEmail, normalizePhone } from "./normalise.js";
import type { User } from "./types.js";
import {
  minute,
  type ChangePasswordInput,
  type CreateUserInput,
  type SignInEmailPasswordInput,
  type SignUpEmailPasswordInput,
  type SessionResult,
  type UserStatusInput
} from "./auth-engine-types.js";
import {
  accountFor,
  assertUserEnabled,
  audit,
  cloneMetadata,
  createSession,
  hashPasswordInput,
  markUserLoggedIn,
  rateLimit,
  type AuthEngineContext
} from "./auth-engine-internals.js";
import {
  requireCurrentSession,
  revokeAllSessionsForUser,
  revokeOtherSessions
} from "./auth-engine-sessions.js";

export async function createUser(ctx: AuthEngineContext, input: CreateUserInput): Promise<User> {
  const email = input.email ? normalizeEmail(input.email) : null;
  const phone = input.phone ? normalizePhone(input.phone) : null;

  if (email && (await ctx.storage.getUserByEmail(email))) {
    throw new AuthError("email_already_exists", "A user already exists with that email", 409);
  }

  if (phone && (await ctx.storage.getUserByPhone(phone))) {
    throw new AuthError("phone_already_exists", "A user already exists with that phone", 409);
  }

  const now = new Date();
  const passwordHash = input.password ? await hashPasswordInput(ctx, input.password) : null;
  const user = await ctx.storage.createUser({
    id: createId("usr"),
    email,
    emailVerifiedAt: null,
    phone,
    phoneVerifiedAt: null,
    passwordHash,
    name: input.name ?? null,
    imageUrl: input.imageUrl ?? null,
    disabledAt: null,
    metadata: cloneMetadata(input.metadata),
    createdAt: now,
    updatedAt: now,
    lastLoginAt: null
  });

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
    context: input.request
  });

  const result = await createSession(ctx, user, input.request);
  return { ...result, user: await markUserLoggedIn(ctx, user) };
}

export async function signInEmailPassword(
  ctx: AuthEngineContext,
  input: SignInEmailPasswordInput
): Promise<SessionResult> {
  const email = normalizeEmail(input.email);
  await rateLimit(ctx, "signin", email, 10, 10 * minute);

  const user = await ctx.storage.getUserByEmail(email);
  if (!user?.passwordHash) {
    throw new AuthError("invalid_credentials", "Invalid email or password", 401);
  }

  assertUserEnabled(user);

  if (!(await verifyPassword(input.password, user.passwordHash))) {
    throw new AuthError("invalid_credentials", "Invalid email or password", 401);
  }

  let authenticatedUser = user;
  if (passwordNeedsRehash(user.passwordHash)) {
    authenticatedUser = (await ctx.storage.updateUser(user.id, {
      passwordHash: await hashPassword(input.password),
      updatedAt: new Date()
    })) ?? user;
  }

  const activeUser = await markUserLoggedIn(ctx, authenticatedUser);
  const result = await createSession(ctx, activeUser, input.request);

  await audit(ctx, {
    eventType: "user.signed_in",
    actorUserId: activeUser.id,
    targetUserId: activeUser.id,
    context: input.request
  });

  return result;
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

  if (!(await verifyPassword(input.currentPassword, user.passwordHash))) {
    throw new AuthError("invalid_credentials", "Invalid current password", 401);
  }

  const updatedUser = await ctx.storage.updateUser(user.id, {
    passwordHash: await hashPasswordInput(ctx, input.newPassword),
    updatedAt: new Date()
  });

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

  return updatedUser ?? user;
}

export async function disableUser(ctx: AuthEngineContext, input: UserStatusInput): Promise<User> {
  if (input.actorUserId !== input.userId) {
    throw new AuthError("permission_denied", "Users can only disable their own account", 403);
  }

  const user = await ctx.storage.getUserById(input.userId);
  if (!user) {
    throw new AuthError("user_not_found", "User not found", 404);
  }

  if (user.disabledAt) {
    return user;
  }

  const now = new Date();
  const updatedUser = await ctx.storage.updateUser(input.userId, {
    disabledAt: now,
    updatedAt: now
  });

  await revokeAllSessionsForUser(
    ctx,
    input.userId,
    "user_disabled",
    input.actorUserId,
    input.request
  );

  await audit(ctx, {
    eventType: "user.disabled",
    actorUserId: input.actorUserId,
    targetUserId: input.userId,
    context: input.request
  });

  return updatedUser ?? user;
}

export async function enableUser(ctx: AuthEngineContext, input: UserStatusInput): Promise<User> {
  if (input.actorUserId !== input.userId) {
    throw new AuthError("permission_denied", "Users can only enable their own account", 403);
  }

  const user = await ctx.storage.getUserById(input.userId);
  if (!user) {
    throw new AuthError("user_not_found", "User not found", 404);
  }

  if (!user.disabledAt) {
    return user;
  }

  const updatedUser = await ctx.storage.updateUser(input.userId, {
    disabledAt: null,
    updatedAt: new Date()
  });

  await audit(ctx, {
    eventType: "user.re_enabled",
    actorUserId: input.actorUserId,
    targetUserId: input.userId,
    context: input.request
  });

  return updatedUser ?? user;
}
