import { AuthError } from "./errors.js";
import type { AuthEngineContext } from "./auth-engine-context.js";
import type { User } from "./types.js";
import { requireCurrentSession } from "./auth-engine-sessions.js";
import { getMfaMethods } from "./auth-engine-mfa.js";
import { rateLimit } from "./auth-engine-helpers.js";
import { hash } from "./auth-engine-token-helpers.js";
import { authorizeAdministration } from "./auth-engine-administration.js";
import { maximumCloudSecurityCacheAgeMs } from "./cloud-runtime-helpers.js";
import {
  isUserErasureCapableStorage, requireResumableUserErasure, userErasureResult,
  type AdministrationEraseUserInput, type AdministrationUserErasureOperationInput,
  type EraseUserInput, type UserErasureOperationInput, type UserErasureResult,
  type AtomicUserErasureInput, type StoredUserErasure, type UserErasureStorage
} from "./user-erasure.js";

const operationIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function validateErasureOperationId(value: string): void {
  if (typeof value !== "string" || !operationIdPattern.test(value)) {
    throw new AuthError("validation_error", "operationId must be an independently generated UUID", 400);
  }
}

function requireUserErasureStorage(ctx: AuthEngineContext): UserErasureStorage {
  if (!isUserErasureCapableStorage(ctx.storage)) {
    throw new AuthError("user_erasure_unsupported", "The configured storage does not support complete user erasure", 409);
  }
  return ctx.storage.userErasureStorage;
}

function preflight(ctx: AuthEngineContext): string[] {
  const unsupported = ctx.erasurePlugins.filter((plugin) => !plugin.userErasure).map((p) => `plugin:${p.id}`);
  if (!ctx.rateLimitStore.eraseUser) unsupported.push("rate_limits");
  if (unsupported.length) throw new AuthError("user_erasure_unsupported", "Configured Own Auth stores must support user erasure", 409, { stores: unsupported });
  return ["rate_limits", ...ctx.erasurePlugins.filter((p) => p.userErasure?.personalData)
    .map((p) => `plugin:${p.id}@${p.version}`)];
}

export async function eraseUser(ctx: AuthEngineContext, input: EraseUserInput): Promise<UserErasureResult> {
  validateErasureOperationId(input.operationId);
  if (input.confirmation !== "erase") throw new AuthError("validation_error", "Confirm permanent account erasure", 400);
  const current = await requireCurrentSession(ctx, input.sessionToken);
  const now = Date.now();
  const authenticatedAt = current.session.authenticatedAt.getTime();
  const requireMfa = (await getMfaMethods(ctx, current.user.id)).length > 0;
  if (!Number.isFinite(authenticatedAt) || authenticatedAt > now || now - authenticatedAt > ctx.userErasureMaxAuthenticationAgeMs ||
    (requireMfa && current.session.assuranceLevel !== "aal2")) {
    throw new AuthError("reauthentication_required", "Sign in again before erasing this account", 401);
  }
  await rateLimit(ctx, "user-erasure", current.user.id, 5, 15 * 60_000);
  return startUserErasure(ctx, current.user, input, now, {
    sessionTokenHash: hash(ctx, input.sessionToken),
    authenticatedAfter: new Date(now - ctx.userErasureMaxAuthenticationAgeMs), requireMfa
  });
}

export async function eraseAdministrationUser(ctx: AuthEngineContext, input: AdministrationEraseUserInput): Promise<UserErasureResult> {
  await authorizeAdministration(ctx, input, "users:erase", input.userId);
  validateErasureOperationId(input.operationId);
  if (typeof input.reason !== "string" || !input.reason.trim() || input.reason.length > 500) {
    throw new AuthError("validation_error", "A reason containing 1 to 500 characters is required", 400);
  }
  for (const resolution of input.organisations ?? []) {
    await authorizeAdministration(ctx, input, "organisations:resolve-erasure", input.userId, {
      organisationId: resolution.organisationId
    });
  }
  const storage = requireUserErasureStorage(ctx);
  const previous = await storage.get(input.operationId) ?? await storage.findByUser(input.userId);
  if (previous) {
    requireResumableUserErasure(previous, input.userId);
    return resumeUserErasure(ctx, { operationId: previous.operationId });
  }
  const user = await ctx.storage.getUserById(input.userId);
  if (!user) throw new AuthError("user_not_found", "User not found", 404);
  return startUserErasure(ctx, user, input, Date.now());
}

async function startUserErasure(
  ctx: AuthEngineContext, user: User,
  input: Pick<EraseUserInput, "operationId" | "organisations">, now: number,
  authentication: Pick<AtomicUserErasureInput, "sessionTokenHash" | "authenticatedAfter" | "requireMfa"> = {}
): Promise<UserErasureResult> {
  const storage = requireUserErasureStorage(ctx);
  const record = await storage.eraseAtomically({
    operationId: input.operationId, userId: user.id, expectedUpdatedAt: user.updatedAt,
    organisations: input.organisations ?? [], pendingStores: preflight(ctx),
    protectedUntil: ctx.cloud ? now + maximumCloudSecurityCacheAgeMs : now, now,
    cloudEvent: ctx.cloud?.prepareUserErasure(user.id) ?? null,
    ...authentication
  });
  return resumeUserErasure(ctx, { operationId: record.operationId }, record);
}

export async function getUserErasure(ctx: AuthEngineContext, input: UserErasureOperationInput): Promise<UserErasureResult> {
  validateErasureOperationId(input.operationId);
  const record = await requireUserErasureStorage(ctx).finish(input.operationId, Date.now());
  if (!record) throw new AuthError("erasure_operation_not_found", "Erasure operation not found", 404);
  return userErasureResult(record);
}

export async function resumeUserErasure(ctx: AuthEngineContext, input: UserErasureOperationInput, committed?: StoredUserErasure): Promise<UserErasureResult> {
  validateErasureOperationId(input.operationId);
  const storage = requireUserErasureStorage(ctx);
  const record = committed ?? await storage.get(input.operationId);
  if (!record) throw new AuthError("erasure_operation_not_found", "Erasure operation not found", 404);
  if (record.subject) {
    for (const store of record.pendingStores) {
      try {
        const subject = Object.freeze(structuredClone(record.subject));
        if (store === "rate_limits") {
          if (!ctx.rateLimitStore.eraseUser) continue;
          await ctx.rateLimitStore.eraseUser(subject);
        } else {
          const plugin = ctx.erasurePlugins.find((p) => `plugin:${p.id}@${p.version}` === store);
          if (!plugin?.userErasure?.personalData) continue;
          await plugin.userErasure.erase(subject);
        }
        await storage.settleStore(record.operationId, store);
      } catch {
        console.warn(JSON.stringify({ operation: "user_erasure", operationId: record.operationId,
          store, errorClass: "CleanupError", message: "Own Auth cleanup failed", retry: "pending" }));
      }
    }
    ctx.cloud?.forgetErasedUser(record.subject.userId);
  }
  try {
    if (record.cloudEventId && !record.cloudComplete && ctx.cloud) await ctx.cloud.flushOutbox();
    return await getUserErasure(ctx, input);
  } catch (error) {
    if (!committed) throw error;
    console.warn(JSON.stringify({ operation: "user_erasure", operationId: record.operationId,
      errorClass: "CleanupError", message: "Own Auth completion could not be confirmed", retry: "pending" }));
    return userErasureResult(record);
  }
}

export async function getAdministrationUserErasure(ctx: AuthEngineContext, input: AdministrationUserErasureOperationInput): Promise<UserErasureResult> {
  await authorizeAdministration(ctx, input, "erasures:read", undefined, { operationId: input.operationId });
  return getUserErasure(ctx, input);
}

export async function resumeAdministrationUserErasure(ctx: AuthEngineContext, input: AdministrationUserErasureOperationInput): Promise<UserErasureResult> {
  await authorizeAdministration(ctx, input, "erasures:resume", undefined, { operationId: input.operationId });
  return resumeUserErasure(ctx, input);
}
