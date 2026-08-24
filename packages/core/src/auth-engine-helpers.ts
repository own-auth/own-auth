import { AuthError, isAuthError } from "./errors.js";
import { createId, randomBase64Url } from "./crypto.js";
import { enforceRateLimit } from "./rate-limit.js";
import type {
  Account,
  AuditEvent,
  AuditEventType,
  JsonRecord,
  RequestContext,
  User
} from "./types.js";
import type { SessionResult } from "./auth-engine-types.js";
import type { AuthEngineContext } from "./auth-engine-context.js";
import { hash } from "./auth-engine-token-helpers.js";
import { recordAuthEvent } from "./webhook-outbox.js";
import { isRecord } from "./value-guards.js";
import {
  isValidEmailAddress,
  isValidE164Phone,
  normalizeEmail,
  normalizePhone
} from "./normalise.js";

export function requestContextFrom(input: unknown): RequestContext {
  return isRecord(input) && isRecord(input.request)
    ? input.request as RequestContext
    : {};
}

export function createAuditEvent(input: {
  eventType: AuditEventType;
  actorUserId?: string | null;
  targetUserId?: string | null;
  organisationId?: string | null;
  apiKeyId?: string | null;
  request?: RequestContext;
  metadata?: JsonRecord;
  now?: Date;
}): AuditEvent {
  return {
    id: createId("evt"),
    eventType: input.eventType,
    actorUserId: input.actorUserId ?? null,
    targetUserId: input.targetUserId ?? null,
    organisationId: input.organisationId ?? null,
    apiKeyId: input.apiKeyId ?? null,
    ipAddress: input.request?.ipAddress ?? null,
    userAgent: input.request?.userAgent ?? null,
    metadata: cloneMetadata(input.metadata),
    createdAt: input.now ?? new Date()
  };
}

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
  const event = createAuditEvent({
    eventType: input.eventType,
    actorUserId: input.actorUserId ?? null,
    targetUserId: input.targetUserId ?? null,
    organisationId: input.organisationId ?? null,
    apiKeyId: input.apiKeyId ?? null,
    request: input.context,
    metadata: input.metadata
  });
  await recordAuthEvent(ctx, event);
}

export function auditSignedIn(
  ctx: AuthEngineContext,
  userId: string,
  method: string,
  request: RequestContext | undefined,
  assuranceLevel: "aal1" | "aal2"
): Promise<void> {
  return audit(ctx, {
    eventType: "user.signed_in",
    actorUserId: userId,
    targetUserId: userId,
    context: request,
    metadata: { method, assuranceLevel }
  });
}

export async function createSession(
  ctx: AuthEngineContext,
  user: User,
  context?: RequestContext,
  authenticationMethods: string[] = ["password"],
  assuranceLevel: "aal1" | "aal2" = "aal1"
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
    revokeReason: null,
    authenticationMethods,
    assuranceLevel,
    authenticatedAt: now
  });

  await audit(ctx, {
    eventType: "session.created",
    actorUserId: user.id,
    targetUserId: user.id,
    context,
    metadata: { sessionId: session.id }
  });

  return { status: "complete", user, session, sessionToken };
}

export async function markUserLoggedIn(ctx: AuthEngineContext, user: User): Promise<User> {
  const updatedUser = await ctx.storage.updateUser(user.id, {
    lastLoginAt: new Date(),
    updatedAt: new Date()
  });

  if (!updatedUser || updatedUser.disabledAt) {
    throw new AuthError("invalid_credentials", "Authentication failed", 401);
  }
  return updatedUser;
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
  try {
    await enforceRateLimit(ctx.rateLimitStore, {
      key: `${action}:${identifier}`,
      limit,
      windowMs
    });
  } catch (error) {
    if (isAuthError(error) && error.code === "rate_limited") {
      await ctx.cloud?.recordRateLimit(action, limit, windowMs);
    }
    throw error;
  }
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

export function requireValidEmail(value: string): string {
  const email = normalizeEmail(value);
  if (!isValidEmailAddress(email)) {
    throw new AuthError("validation_error", "Email address is invalid", 400);
  }
  return email;
}

export function requireValidPhone(value: string): string {
  const phone = normalizePhone(value);
  if (!isValidE164Phone(phone)) {
    throw new AuthError(
      "validation_error",
      "Phone numbers must use E.164 format",
      400
    );
  }
  return phone;
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
