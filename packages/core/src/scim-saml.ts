import type { AuthEngineContext } from "./auth-engine-context.js";
import { claimEmailOwnership } from "./auth-engine-email-ownership.js";
import type { ScimUser } from "./scim-types.js";
import type { RequestContext, User } from "./types.js";

export async function findPairedSamlUser(
  ctx: AuthEngineContext,
  samlConnectionId: string,
  normalizedEmail: string
): Promise<ScimUser | null> {
  if (!ctx.scimStorage) return null;
  return ctx.scimStorage.findActiveUserBySamlConnection(samlConnectionId, normalizedEmail);
}

export async function verifyPairedSamlEmail(
  ctx: AuthEngineContext,
  input: {
    samlConnectionId: string;
    resource: ScimUser | null;
    user: User;
    normalizedEmail: string | null;
    verifiedAccountId: string;
    request?: RequestContext;
    originalActorUserId?: string;
  }
): Promise<User> {
  const { samlConnectionId, resource, user, normalizedEmail, verifiedAccountId, request, originalActorUserId } = input;
  if (!resource || !normalizedEmail || resource.userId !== user.id || user.email !== normalizedEmail || user.emailVerifiedAt) {
    return user;
  }
  const connection = await ctx.scimStorage?.getConnectionById(resource.connectionId);
  if (!connection || connection.samlConnectionId !== samlConnectionId || connection.disabledAt) {
    return user;
  }
  return claimEmailOwnership(ctx, {
    user,
    email: normalizedEmail,
    proof: { kind: "provider", originalActorUserId, samlOrganisationId: connection.organisationId },
    verifiedAccountId,
    request,
    metadata: { method: "saml", samlConnectionId, scimConnectionId: connection.id }
  });
}
