import { AuthError } from "./errors.js";
import { isExpired } from "./normalise.js";
import type {
  ListSessionsInput,
  RevokeAllSessionsInput,
  RevokeSessionInput
} from "./auth-engine-types.js";
import type { CurrentSession, RequestContext, Session } from "./types.js";
import {
  audit,
  hash,
  requireActiveUser,
  type AuthEngineContext
} from "./auth-engine-internals.js";

export async function getCurrentSession(
  ctx: AuthEngineContext,
  sessionToken: string
): Promise<CurrentSession | null> {
  const tokenHash = hash(ctx, sessionToken);
  const session = await ctx.storage.getSessionByTokenHash(tokenHash);
  const now = new Date();

  if (
    !session ||
    session.revokedAt ||
    isExpired(session.expiresAt, now) ||
    isExpired(session.idleExpiresAt, now)
  ) {
    return null;
  }

  const user = await ctx.storage.getUserById(session.userId);
  if (!user || user.disabledAt) {
    return null;
  }

  const updatedSession = await ctx.storage.updateSession(session.id, {
    lastActiveAt: now,
    idleExpiresAt: new Date(now.getTime() + ctx.sessionIdleTtlMs)
  });

  return {
    session: updatedSession ?? session,
    user
  };
}

export async function requireCurrentSession(
  ctx: AuthEngineContext,
  sessionToken: string
): Promise<CurrentSession> {
  const currentSession = await getCurrentSession(ctx, sessionToken);

  if (!currentSession) {
    throw new AuthError("invalid_session", "Invalid or expired session", 401);
  }

  return currentSession;
}

export async function signOut(
  ctx: AuthEngineContext,
  sessionToken: string,
  context?: RequestContext
): Promise<void> {
  const tokenHash = hash(ctx, sessionToken);
  const session = await ctx.storage.getSessionByTokenHash(tokenHash);

  if (!session || session.revokedAt) {
    return;
  }

  const now = new Date();
  await ctx.storage.updateSession(session.id, {
    revokedAt: now,
    revokeReason: "user_logout"
  });
  await audit(ctx, {
    eventType: "user.signed_out",
    actorUserId: session.userId,
    targetUserId: session.userId,
    context
  });
  await audit(ctx, {
    eventType: "session.revoked",
    actorUserId: session.userId,
    targetUserId: session.userId,
    context,
    metadata: { reason: "user_logout" }
  });
}

export async function revokeSession(
  ctx: AuthEngineContext,
  input: RevokeSessionInput
): Promise<Session> {
  const current = await requireCurrentSession(ctx, input.sessionToken);
  const sessions = await ctx.storage.listSessionsByUserId(current.user.id);
  const target = sessions.find((session) => session.id === input.sessionId);

  if (!target) {
    throw new AuthError("invalid_session", "Session not found", 404);
  }

  if (target.revokedAt) {
    return target;
  }

  const revokedAt = new Date();
  const revoked = await ctx.storage.updateSession(target.id, {
    revokedAt,
    revokeReason: "user_revoked"
  });

  if (!revoked) {
    throw new AuthError("invalid_session", "Session not found", 404);
  }

  await audit(ctx, {
    eventType: "session.revoked",
    actorUserId: current.user.id,
    targetUserId: current.user.id,
    context: input.request,
    metadata: {
      reason: "user_revoked",
      sessionId: revoked.id
    }
  });

  return revoked;
}

export async function revokeAllSessions(
  ctx: AuthEngineContext,
  input: RevokeAllSessionsInput
): Promise<number> {
  await requireActiveUser(ctx, input.actorUserId);
  return revokeAllSessionsForUser(
    ctx,
    input.actorUserId,
    "user_revoked_all",
    input.actorUserId,
    input.request
  );
}

export async function revokeAllSessionsForUser(
  ctx: AuthEngineContext,
  userId: string,
  reason: string,
  actorUserId = userId,
  context?: RequestContext
): Promise<number> {
  const revoked = await revokeSessions(ctx, userId, reason);

  await audit(ctx, {
    eventType: "session.revoked_all",
    actorUserId,
    targetUserId: userId,
    context,
    metadata: { reason, revoked }
  });

  return revoked;
}

export async function revokeOtherSessions(
  ctx: AuthEngineContext,
  userId: string,
  currentSessionId: string,
  reason = "other_sessions_revoked"
): Promise<number> {
  const revoked = await revokeSessions(
    ctx,
    userId,
    reason,
    (session) => session.id !== currentSessionId
  );

  await audit(ctx, {
    eventType: "session.revoked_other",
    actorUserId: userId,
    targetUserId: userId,
    metadata: { reason, revoked }
  });

  return revoked;
}

async function revokeSessions(
  ctx: AuthEngineContext,
  userId: string,
  reason: string,
  include: (session: Session) => boolean = () => true
): Promise<number> {
  const sessions = await ctx.storage.listSessionsByUserId(userId);
  const revokedAt = new Date();
  let revoked = 0;

  for (const session of sessions) {
    if (!session.revokedAt && include(session)) {
      await ctx.storage.updateSession(session.id, { revokedAt, revokeReason: reason });
      revoked += 1;
    }
  }

  return revoked;
}

export async function listSessions(
  ctx: AuthEngineContext,
  input: ListSessionsInput
): Promise<Session[]> {
  await requireActiveUser(ctx, input.actorUserId);
  return ctx.storage.listSessionsByUserId(input.actorUserId);
}
