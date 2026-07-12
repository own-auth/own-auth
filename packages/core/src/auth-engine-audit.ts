import { AuthError } from "./errors.js";
import type {
  CleanupAuditLogsInput,
  ListAuditEventsInput
} from "./auth-engine-types.js";
import type { AuditEvent } from "./types.js";
import {
  requireActiveUser,
  type AuthEngineContext
} from "./auth-engine-internals.js";
import { requirePermission } from "./auth-engine-organisation-access.js";

export async function listAuditEvents(
  ctx: AuthEngineContext,
  input: ListAuditEventsInput
): Promise<AuditEvent[]> {
  if (input.organisationId) {
    await requirePermission(
      ctx,
      input.organisationId,
      input.actorUserId,
      "view_audit_events"
    );
    return ctx.storage.listAuditEvents({
      userId: input.userId,
      organisationId: input.organisationId,
      apiKeyId: input.apiKeyId
    });
  }

  if (input.userId && input.userId !== input.actorUserId) {
    throw new AuthError("permission_denied", "Users can only view their own audit events", 403);
  }

  await requireActiveUser(ctx, input.actorUserId);
  return ctx.storage.listAuditEvents({
    userId: input.actorUserId,
    apiKeyId: input.apiKeyId
  });
}

export async function cleanupAuditLogs(
  ctx: AuthEngineContext,
  input: CleanupAuditLogsInput
): Promise<number> {
  if (!(input.olderThan instanceof Date) || Number.isNaN(input.olderThan.getTime())) {
    throw new AuthError("validation_error", "olderThan must be a valid date", 400);
  }

  return ctx.storage.deleteAuditEventsBefore(input.olderThan);
}
