import { AuthError } from "./errors.js";
import { createId, randomBase64Url } from "./crypto.js";
import { enforceRateLimit } from "./rate-limit.js";
import type {
  Account,
  AuditEventType,
  JsonRecord,
  RequestContext,
  User
} from "./types.js";
import type { SessionResult } from "./auth-engine-types.js";
import type { AuthEngineContext } from "./auth-engine-context.js";
import { hash } from "./auth-engine-token-helpers.js";

export async function audit(
  ctx: AuthEngineContext,
  input: {
    eventType: AuditEventType;
    actorUserId?: string | null;
    targetUserId?: string | null;
    organisationId?: string | null;
    apiKeyId?: string | null;
    context?: RequestContext;
    metadata?: JsonRecord;
  }
): Promise<void> {
  await ctx.storage.createAuditEvent({
    id: createId("evt"),
    eventType: input.eventType,
    actorUserId: input.actorUserId ?? null,
    targetUserId: input.targetUserId ?? null,
    organisationId: input.organisationId ?? null,
    apiKeyId: input.apiKeyId ?? null,
    ipAddress: input.context?.ipAddress ?? null,
    userAgent: input.context?.userAgent ?? null,
    metadata: cloneMetadata(input.metadata),
    createdAt: new Date()
  });
}

export async function createSession(
  ctx: AuthEngineContext,
  user: User,
  context?: RequestContext
): Promise<SessionResult> {
  assertUserEnabled(user);

  const sessionToken = randomBase64Url(32);
  const now = new Date();
  const session = await ctx.storage.createSession({
    id: createId("ses"),
    userId: user.id,
    tokenHash: hash(ctx, sessionToken),
    createdAt: now,
    lastActiveAt: now,
    expiresAt: new Date(now.getTime() + ctx.sessionTtlMs),
    idleExpiresAt: new Date(now.getTime() + ctx.sessionIdleTtlMs),
    ipAddress: context?.ipAddress ?? null,
    userAgent: context?.userAgent ?? null,
    revokedAt: null,
    revokeReason: null
  });

  await audit(ctx, {
    eventType: "session.created",
    actorUserId: user.id,
    targetUserId: user.id,
    context,
    metadata: { sessionId: session.id }
  });

  return { user, session, sessionToken };
}

export async function markUserLoggedIn(ctx: AuthEngineContext, user: User): Promise<User> {
  const updatedUser = await ctx.storage.updateUser(user.id, {
    lastLoginAt: new Date(),
    updatedAt: new Date()
  });

  return updatedUser ?? user;
}

export function accountFor(
  userId: string,
  provider: Account["provider"],
  providerAccountId: string,
  providerEmail: string | null,
  providerPhone: string | null,
  now: Date
): Account {
  return {
    id: createId("acct"),
    userId,
    provider,
    providerAccountId,
    providerEmail,
    providerPhone,
    createdAt: now,
    updatedAt: now
  };
}

export function userFor(
  input: {
    email: string | null;
    emailVerifiedAt: Date | null;
    phone: string | null;
    phoneVerifiedAt: Date | null;
    passwordHash: string | null;
    name?: string;
    imageUrl?: string;
    metadata?: JsonRecord;
  },
  now: Date
): User {
  return {
    id: createId("usr"),
    email: input.email,
    emailVerifiedAt: input.emailVerifiedAt,
    phone: input.phone,
    phoneVerifiedAt: input.phoneVerifiedAt,
    passwordHash: input.passwordHash,
    name: input.name ?? null,
    imageUrl: input.imageUrl ?? null,
    disabledAt: null,
    metadata: cloneMetadata(input.metadata),
    createdAt: now,
    updatedAt: now,
    lastLoginAt: null
  };
}

export async function rateLimit(
  ctx: AuthEngineContext,
  action: string,
  identifier: string,
  limit: number,
  windowMs: number
): Promise<void> {
  await enforceRateLimit(ctx.rateLimitStore, {
    key: `${action}:${identifier}`,
    limit,
    windowMs
  });
}

export function assertUserEnabled(user: User): void {
  if (user.disabledAt) {
    throw new AuthError("disabled_user", "User is disabled", 403);
  }
}

export async function requireActiveUser(
  ctx: AuthEngineContext,
  userId: string
): Promise<User> {
  const user = await ctx.storage.getUserById(userId);
  if (!user) {
    throw new AuthError("user_not_found", "User not found", 404);
  }
  assertUserEnabled(user);
  return user;
}

export async function uniqueOrganisationSlug(
  ctx: AuthEngineContext,
  baseSlug: string
): Promise<string> {
  let candidate = baseSlug;
  let attempt = 1;

  while (await ctx.storage.getOrganisationBySlug(candidate)) {
    attempt += 1;
    candidate = `${baseSlug}-${attempt}`;
  }

  return candidate;
}

export function cloneMetadata(metadata?: JsonRecord): JsonRecord {
  return metadata ? structuredClone(metadata) : {};
}
