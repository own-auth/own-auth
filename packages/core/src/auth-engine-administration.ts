import {
  isAdministrationCapableStorage,
  type AdministrationAction,
  type AdministrationAuditEventPage,
  type AdministrationPage,
  type AdministrationSession,
  type AdministrationUser,
  type AdministrationUserMutationInput,
  type GetAdministrationUserInput,
  type ListAdministrationUserAuditEventsInput,
  type ListAdministrationUserSessionsInput,
  type ListAdministrationUsersInput
} from "./administration.js";
import { decodeBase64Url, encodeBase64Url } from "./encoding.js";
import { safeEqual } from "./crypto.js";
import { AuthError, isAuthError } from "./errors.js";
import type { StoragePageCursor } from "./storage.js";
import type { Session, User } from "./types.js";
import type { AuthEngineContext } from "./auth-engine-context.js";
import { audit, rateLimit, requireActiveUser } from "./auth-engine-helpers.js";
import { hash } from "./auth-engine-token-helpers.js";
import { revokeAllSessionsForUser } from "./auth-engine-sessions.js";
import { setUserDisabledState } from "./auth-engine-users.js";
import type { AuthOperationRunner } from "./auth-operation-runner.js";
import * as erasure from "./auth-engine-user-erasure.js";
import type { AdministrationEraseUserInput, AdministrationUserErasureOperationInput, UserErasureResult } from "./user-erasure.js";

const defaultPageLimit = 50;
const maximumPageLimit = 100;
const maximumQueryLength = 200;
const maximumReasonLength = 500;
const maximumCursorLength = 1_024;
const administrationRateLimit = 120;
const administrationRateWindowMs = 60_000;
const cursorDomain = "own-auth:administration:cursor:v1";

export class OwnAuthAdministration {
  eraseUser(input: AdministrationEraseUserInput): Promise<UserErasureResult> {
    return this.execute("admin.eraseUser", input, () => erasure.eraseAdministrationUser(this.ctx, input));
  }
  getUserErasure(input: AdministrationUserErasureOperationInput): Promise<UserErasureResult> {
    return this.execute("admin.getUserErasure", input, () => erasure.getAdministrationUserErasure(this.ctx, input));
  }
  resumeUserErasure(input: AdministrationUserErasureOperationInput): Promise<UserErasureResult> {
    return this.execute("admin.resumeUserErasure", input, () => erasure.resumeAdministrationUserErasure(this.ctx, input));
  }
  constructor(
    private readonly ctx: AuthEngineContext,
    private readonly execute: AuthOperationRunner
  ) {}

  listUsers(
    input: ListAdministrationUsersInput
  ): Promise<AdministrationPage<AdministrationUser>> {
    return this.execute("admin.listUsers", input, () => listUsers(this.ctx, input));
  }

  getUser(input: GetAdministrationUserInput): Promise<AdministrationUser> {
    return this.execute("admin.getUser", input, () => getUser(this.ctx, input));
  }

  listUserSessions(
    input: ListAdministrationUserSessionsInput
  ): Promise<AdministrationSession[]> {
    return this.execute("admin.listUserSessions", input, () =>
      listUserSessions(this.ctx, input));
  }

  listUserAuditEvents(
    input: ListAdministrationUserAuditEventsInput
  ): Promise<AdministrationAuditEventPage> {
    return this.execute("admin.listUserAuditEvents", input, () =>
      listUserAuditEvents(this.ctx, input));
  }

  disableUser(input: AdministrationUserMutationInput): Promise<AdministrationUser> {
    return this.execute("admin.disableUser", input, () => disableUser(this.ctx, input));
  }

  enableUser(input: AdministrationUserMutationInput): Promise<AdministrationUser> {
    return this.execute("admin.enableUser", input, () => enableUser(this.ctx, input));
  }

  revokeUserSessions(input: AdministrationUserMutationInput): Promise<number> {
    return this.execute("admin.revokeUserSessions", input, () =>
      revokeUserSessions(this.ctx, input));
  }
}

async function listUsers(
  ctx: AuthEngineContext,
  input: ListAdministrationUsersInput
): Promise<AdministrationPage<AdministrationUser>> {
  await authorize(ctx, input, "users:list");
  const limit = pageLimit(input.limit);
  const status = input.status ?? "all";
  const query = normalizeQuery(input.query);

  if (query) {
    const exact = await findExactUser(ctx, query);
    if (exact) {
      const items = matchesStatus(exact, status) ? [toAdministrationUser(exact)] : [];
      await auditRead(ctx, "admin.users_listed", input.actorUserId, null, items.length, input.request);
      return { items, nextCursor: null };
    }
  }

  const rows = await administrationStorage(ctx).listUsers({
    query,
    status,
    cursor: decodeCursor(ctx, input.cursor),
    limit: limit + 1
  });
  const page = pageFromRows(ctx, rows, limit);
  const items = page.items.map(toAdministrationUser);
  await auditRead(ctx, "admin.users_listed", input.actorUserId, null, items.length, input.request);
  return {
    items,
    nextCursor: page.nextCursor
  };
}

async function getUser(
  ctx: AuthEngineContext,
  input: GetAdministrationUserInput
): Promise<AdministrationUser> {
  await authorize(ctx, input, "users:read", input.userId);
  const user = await requireTargetUser(ctx, input.userId);
  await auditRead(ctx, "admin.user_viewed", input.actorUserId, user.id, 1, input.request);
  return toAdministrationUser(user);
}

async function listUserSessions(
  ctx: AuthEngineContext,
  input: ListAdministrationUserSessionsInput
): Promise<AdministrationSession[]> {
  await authorize(ctx, input, "sessions:list", input.userId);
  const user = await requireTargetUser(ctx, input.userId);
  const sessions = await ctx.storage.listSessionsByUserId(user.id);
  const result = sessions
    .sort(compareNewestFirst)
    .map((session) => toAdministrationSession(session, user.disabledAt));
  await auditRead(ctx, "admin.sessions_listed", input.actorUserId, user.id, result.length, input.request);
  return result;
}

async function listUserAuditEvents(
  ctx: AuthEngineContext,
  input: ListAdministrationUserAuditEventsInput
): Promise<AdministrationAuditEventPage> {
  await authorize(ctx, input, "audit:list", input.userId);
  await requireTargetUser(ctx, input.userId);
  const limit = pageLimit(input.limit);
  const rows = await ctx.storage.listAuditEvents({
    userId: input.userId,
    cursor: decodeCursor(ctx, input.cursor),
    limit: limit + 1
  });
  const page = pageFromRows(ctx, rows, limit);
  await auditRead(ctx, "admin.audit_events_listed", input.actorUserId, input.userId, page.items.length, input.request);
  return page;
}

async function disableUser(
  ctx: AuthEngineContext,
  input: AdministrationUserMutationInput
): Promise<AdministrationUser> {
  return setAdministrationUserDisabled(ctx, input, true);
}

async function enableUser(
  ctx: AuthEngineContext,
  input: AdministrationUserMutationInput
): Promise<AdministrationUser> {
  return setAdministrationUserDisabled(ctx, input, false);
}

async function setAdministrationUserDisabled(
  ctx: AuthEngineContext,
  input: AdministrationUserMutationInput,
  disabled: boolean
): Promise<AdministrationUser> {
  await authorize(ctx, input, disabled ? "users:disable" : "users:enable", input.userId);
  const reason = mutationReason(input.reason);
  const result = await setUserDisabledState(ctx, {
    userId: input.userId,
    disabled,
    actorUserId: input.actorUserId,
    request: input.request,
    sessionRevokeReason: "administration_user_disabled"
  });
  if (!result.changed) return toAdministrationUser(result.user);

  await audit(ctx, {
    eventType: disabled ? "user.disabled" : "user.re_enabled",
    actorUserId: input.actorUserId,
    targetUserId: input.userId,
    context: input.request,
    metadata: { source: "administration", reason }
  });
  return toAdministrationUser(result.user);
}

async function revokeUserSessions(
  ctx: AuthEngineContext,
  input: AdministrationUserMutationInput
): Promise<number> {
  await authorize(ctx, input, "sessions:revoke", input.userId);
  const reason = mutationReason(input.reason);
  await requireTargetUser(ctx, input.userId);
  const revoked = await revokeAllSessionsForUser(
    ctx,
    input.userId,
    "administration_revoked_all",
    input.actorUserId,
    input.request
  );
  await audit(ctx, {
    eventType: "admin.sessions_revoked",
    actorUserId: input.actorUserId,
    targetUserId: input.userId,
    context: input.request,
    metadata: { reason, revoked }
  });
  return revoked;
}

async function authorize(
  ctx: AuthEngineContext,
  input: { actorUserId: string; request?: { ipAddress?: string; userAgent?: string } },
  action: AdministrationAction,
  targetUserId?: string,
  erasureContext: { operationId?: string; organisationId?: string } = {}
): Promise<void> {
  if (typeof input.actorUserId !== "string" || !input.actorUserId.trim()) {
    throw new AuthError("validation_error", "actorUserId is required", 400);
  }
  if (!ctx.administration) {
    throw new AuthError(
      "administration_not_configured",
      "Administration is not configured",
      404
    );
  }
  await rateLimit(
    ctx,
    "administration",
    input.actorUserId,
    administrationRateLimit,
    administrationRateWindowMs
  );
  const actor = await requireActiveUser(ctx, input.actorUserId);
  let allowed = false;
  try {
    allowed = await ctx.administration.authorize({
      actor: Object.freeze(toAdministrationUser(actor)),
      action,
      targetUserId,
      ...erasureContext
    });
  } catch {
    allowed = false;
  }
  if (!allowed) {
    throw new AuthError("permission_denied", "Administration access denied", 403);
  }
}

export { authorize as authorizeAdministration };

function toAdministrationUser(user: User): AdministrationUser {
  return {
    id: user.id,
    email: user.email,
    emailVerifiedAt: copyDate(user.emailVerifiedAt),
    phone: user.phone,
    phoneVerifiedAt: copyDate(user.phoneVerifiedAt),
    name: user.name,
    imageUrl: user.imageUrl,
    disabledAt: copyDate(user.disabledAt),
    metadata: structuredClone(user.metadata),
    createdAt: new Date(user.createdAt),
    updatedAt: new Date(user.updatedAt),
    lastLoginAt: copyDate(user.lastLoginAt)
  };
}

function toAdministrationSession(
  session: Session,
  disabledAt: Date | null
): AdministrationSession {
  return {
    id: session.id,
    userId: session.userId,
    createdAt: new Date(session.createdAt),
    lastActiveAt: new Date(session.lastActiveAt),
    expiresAt: new Date(session.expiresAt),
    idleExpiresAt: new Date(session.idleExpiresAt),
    ipAddress: session.ipAddress,
    userAgent: session.userAgent,
    revokedAt: copyDate(session.revokedAt),
    revokeReason: session.revokeReason,
    authenticationMethods: [...session.authenticationMethods],
    assuranceLevel: session.assuranceLevel,
    authenticatedAt: new Date(session.authenticatedAt),
    effectiveStatus: sessionStatus(session, disabledAt)
  };
}

async function findExactUser(
  ctx: AuthEngineContext,
  query: string
): Promise<User | null> {
  const byId = await ctx.storage.getUserById(query);
  if (byId || !/^\+\d{6,15}$/u.test(query)) return byId;
  return ctx.storage.getUserByPhone(query);
}

async function requireTargetUser(ctx: AuthEngineContext, userId: string): Promise<User> {
  if (typeof userId !== "string" || !userId.trim()) {
    throw new AuthError("validation_error", "userId is required", 400);
  }
  const user = await ctx.storage.getUserById(userId);
  if (!user) throw new AuthError("user_not_found", "User not found", 404);
  return user;
}

async function auditRead(
  ctx: AuthEngineContext,
  eventType: "admin.audit_events_listed" | "admin.sessions_listed" | "admin.user_viewed" | "admin.users_listed",
  actorUserId: string,
  targetUserId: string | null,
  resultCount: number,
  request?: { ipAddress?: string; userAgent?: string }
): Promise<void> {
  await audit(ctx, {
    eventType,
    actorUserId,
    targetUserId,
    context: request,
    metadata: { resultCount }
  });
}

function normalizeQuery(value: string | undefined): string | undefined {
  if (value !== undefined && typeof value !== "string") {
    throw new AuthError("validation_error", "query must be a string", 400);
  }
  const query = value?.trim();
  if (!query) return undefined;
  if (query.length > maximumQueryLength) {
    throw new AuthError("validation_error", "query is too long", 400);
  }
  return query;
}

function mutationReason(value: string): string {
  if (typeof value !== "string") {
    throw new AuthError("validation_error", "reason must be a string", 400);
  }
  const reason = value.trim();
  if (!reason || reason.length > maximumReasonLength) {
    throw new AuthError(
      "validation_error",
      `reason must be between 1 and ${maximumReasonLength} characters`,
      400
    );
  }
  return reason;
}

function pageLimit(value: number | undefined): number {
  const limit = value ?? defaultPageLimit;
  if (!Number.isInteger(limit) || limit < 1 || limit > maximumPageLimit) {
    throw new AuthError(
      "validation_error",
      `limit must be between 1 and ${maximumPageLimit}`,
      400
    );
  }
  return limit;
}

function pageFromRows<Item extends StoragePageCursor>(
  ctx: AuthEngineContext,
  rows: Item[],
  limit: number
): AdministrationPage<Item> {
  const hasNext = rows.length > limit;
  const items = hasNext ? rows.slice(0, limit) : rows;
  const last = items.at(-1);
  return {
    items,
    nextCursor: hasNext && last ? encodeCursor(ctx, last) : null
  };
}

function encodeCursor(ctx: AuthEngineContext, value: StoragePageCursor): string {
  const payload = JSON.stringify({
    version: 1,
    createdAt: value.createdAt.toISOString(),
    id: value.id
  });
  const encoded = encodeBase64Url(new TextEncoder().encode(payload));
  const signature = hash(ctx, `${cursorDomain}:${encoded}`);
  return `${encoded}.${signature}`;
}

function decodeCursor(
  ctx: AuthEngineContext,
  value: string | undefined
): StoragePageCursor | undefined {
  if (!value) return undefined;
  if (typeof value !== "string" || value.length > maximumCursorLength) throw invalidCursor();
  const [encoded, signature, extra] = value.split(".");
  if (!encoded || !signature || extra) throw invalidCursor();
  const expected = hash(ctx, `${cursorDomain}:${encoded}`);
  if (!safeEqual(signature, expected)) throw invalidCursor();
  try {
    const decoded = new TextDecoder().decode(decodeBase64Url(encoded));
    const payload = JSON.parse(decoded) as Record<string, unknown>;
    if (
      payload.version !== 1 ||
      typeof payload.createdAt !== "string" ||
      typeof payload.id !== "string" ||
      !payload.id ||
      payload.id.length > 200
    ) {
      throw invalidCursor();
    }
    const createdAt = new Date(payload.createdAt);
    if (Number.isNaN(createdAt.getTime())) throw invalidCursor();
    return { createdAt, id: payload.id };
  } catch (error) {
    if (isAuthError(error)) throw error;
    throw invalidCursor();
  }
}

function invalidCursor(): AuthError {
  return new AuthError("validation_error", "Invalid pagination cursor", 400);
}

function administrationStorage(ctx: AuthEngineContext) {
  if (!isAdministrationCapableStorage(ctx.storage)) {
    throw new AuthError(
      "administration_not_configured",
      "Administration is not configured",
      404
    );
  }
  return ctx.storage;
}

function matchesStatus(user: User, status: "active" | "disabled" | "all"): boolean {
  return status === "all" || (status === "disabled") === Boolean(user.disabledAt);
}

function sessionStatus(
  session: Session,
  disabledAt: Date | null
): AdministrationSession["effectiveStatus"] {
  if (session.revokedAt) return "revoked";
  if (disabledAt) return "disabled_user";
  const now = Date.now();
  return session.expiresAt.getTime() <= now || session.idleExpiresAt.getTime() <= now
    ? "expired"
    : "active";
}

function compareNewestFirst(left: Session, right: Session): number {
  return right.createdAt.getTime() - left.createdAt.getTime() || right.id.localeCompare(left.id);
}

function copyDate(value: Date | null): Date | null {
  return value ? new Date(value) : null;
}
