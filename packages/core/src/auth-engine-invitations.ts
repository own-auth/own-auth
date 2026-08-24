import { AuthError } from "./errors.js";
import { createId } from "./crypto.js";
import { isExpired } from "./normalise.js";
import type { Invitation } from "./types.js";
import {
  hour,
  type AcceptInviteInput,
  type AcceptInviteResult,
  type InvitationResult,
  type InviteMemberInput,
  type ListInvitationsInput,
  type RevokeInvitationInput
} from "./auth-engine-types.js";
import {
  audit,
  buildUrl,
  createAuditEvent,
  getUsableToken,
  issueToken,
  rateLimit,
  requireActiveUser,
  requireValidEmail,
  type AuthEngineContext
} from "./auth-engine-internals.js";
import {
  requireActiveOrganisation,
  requireConfiguredRole,
  requirePermission
} from "./auth-engine-organisation-access.js";
import { captureCloudDeliveryFailure, sendEmail } from "./auth-engine-delivery.js";
import { prepareAuthEventWrite, recordCommittedAuthEvent } from "./webhook-outbox.js";

export async function inviteMember(
  ctx: AuthEngineContext,
  input: InviteMemberInput<string>
): Promise<InvitationResult<string>> {
  const inviter = await requirePermission(
    ctx,
    input.organisationId,
    input.invitedByUserId,
    "invite_members"
  );
  const role = input.role ?? "member";
  requireConfiguredRole(ctx, role);
  if (role === "owner" && inviter.role !== "owner") {
    throw new AuthError("permission_denied", "Only owners can invite another owner", 403);
  }

  const email = requireValidEmail(input.email);
  const invitedUser = await ctx.storage.getUserByEmail(email);
  if (invitedUser) {
    const existingMember = await ctx.storage.getOrganisationMember(
      input.organisationId,
      invitedUser.id
    );
    if (existingMember?.status === "active") {
      throw new AuthError("already_member", "User is already a member", 409);
    }
  }

  const existingInvitation = await ctx.storage.getPendingInvitationByOrganisationAndEmail(
    input.organisationId,
    email
  );
  if (existingInvitation) {
    if (!isExpired(existingInvitation.expiresAt)) {
      throw new AuthError("invite_exists", "A pending invitation already exists", 409);
    }
    await ctx.storage.updateInvitation(existingInvitation.id, { status: "expired" });
  }

  await rateLimit(ctx, "organisation-invite", input.organisationId, 10, hour);

  const now = new Date();
  const issued = await issueToken(ctx, "organisation_invite", {
    userId: null,
    email,
    organisationId: input.organisationId,
    ttlMs: ctx.tokenTtls.organisation_invite
  });
  const invitation = await ctx.storage.createInvitation({
    id: createId("inv"),
    tokenId: issued.token.id,
    organisationId: input.organisationId,
    email,
    phone: null,
    role,
    invitedByUserId: input.invitedByUserId,
    status: "pending",
    expiresAt: issued.token.expiresAt,
    acceptedAt: null,
    revokedAt: null,
    createdAt: now
  });
  const url = buildUrl(ctx, "/auth/invitations/accept", { token: issued.rawToken });

  const deliveryFailure = await captureCloudDeliveryFailure(() => sendEmail(ctx, {
    to: email,
    recipientUserId: invitedUser?.id,
    type: "organisation_invite",
    token: issued.rawToken,
    url,
    expiresAt: issued.token.expiresAt
  }));

  await audit(ctx, {
    eventType: "member.invited",
    actorUserId: input.invitedByUserId,
    organisationId: input.organisationId,
    context: input.request,
    metadata: { email, role: invitation.role, invitationId: invitation.id }
  });

  const result: InvitationResult<string> = {
    invitation,
    delivery: deliveryFailure
      ? { status: "failed", reason: deliveryFailure }
      : { status: "sent" }
  };
  if (ctx.exposeRawTokens) {
    result.token = issued.rawToken;
    result.url = url;
  }

  return result;
}

export async function acceptInvite(
  ctx: AuthEngineContext,
  input: AcceptInviteInput
): Promise<AcceptInviteResult<string>> {
  if (!input.userId) {
    throw new AuthError("invalid_session", "Sign in to accept the invitation", 401);
  }

  const token = await getUsableToken(ctx, input.token, "organisation_invite");
  const organisationId = token.organisationId;
  if (!organisationId) {
    throw new AuthError("invalid_token", "Invalid token", 401);
  }
  const organisation = await requireActiveOrganisation(ctx, organisationId);

  const user = await requireActiveUser(ctx, input.userId);

  if (!token.email || user.email !== token.email) {
    throw new AuthError("permission_denied", "Invitation does not belong to this user", 403);
  }

  const pendingInvitation = await ctx.storage.getInvitationByTokenId(token.id);
  if (
    !pendingInvitation ||
    pendingInvitation.organisationId !== organisationId ||
    pendingInvitation.email !== token.email
  ) {
    throw new AuthError("invalid_token", "Invalid token", 401);
  }

  if (pendingInvitation.status !== "pending") {
    throw new AuthError("invalid_token", "Invalid token", 401);
  }

  if (isExpired(pendingInvitation.expiresAt)) {
    await ctx.storage.updateInvitation(pendingInvitation.id, { status: "expired" });
    throw new AuthError("expired_token", "Invitation has expired", 401);
  }

  requireConfiguredRole(ctx, pendingInvitation.role);
  const now = new Date();
  const auditEvent = createAuditEvent({
    eventType: "invite.accepted",
    actorUserId: user.id,
    targetUserId: user.id,
    organisationId,
    request: input.request,
    metadata: { invitationId: pendingInvitation.id },
    now
  });
  const accepted = await ctx.storage.acceptInvitationAtomically({
    operationId: createId("op"),
    tokenId: token.id,
    tokenHash: token.tokenHash,
    invitationId: pendingInvitation.id,
    userId: user.id,
    memberId: createId("mem"),
    acceptedAt: now,
    event: prepareAuthEventWrite(ctx, auditEvent)
  });
  if (!accepted) {
    await getUsableToken(ctx, input.token, "organisation_invite");
    throw new AuthError("invalid_token", "Invalid token", 401);
  }
  await recordCommittedAuthEvent(ctx, auditEvent);

  return { organisation, member: accepted.member };
}

export async function revokeInvitation(
  ctx: AuthEngineContext,
  input: RevokeInvitationInput
): Promise<Invitation<string>> {
  const invitation = await ctx.storage.getInvitationById(input.invitationId);
  if (!invitation) {
    throw new AuthError("invitation_not_found", "Invitation not found", 404);
  }

  await requirePermission(ctx, invitation.organisationId, input.actorUserId, "invite_members");

  if (invitation.status !== "pending") {
    throw new AuthError("invitation_not_pending", "Invitation is not pending", 409);
  }

  const now = new Date();
  const auditEvent = createAuditEvent({
    eventType: "invite.revoked",
    actorUserId: input.actorUserId,
    organisationId: invitation.organisationId,
    request: input.request,
    metadata: { invitationId: invitation.id, email: invitation.email },
    now
  });
  const updatedInvitation = await ctx.storage.revokeInvitationAtomically({
    operationId: createId("op"),
    invitationId: input.invitationId,
    revokedAt: now,
    event: prepareAuthEventWrite(ctx, auditEvent)
  });
  if (!updatedInvitation) {
    throw new AuthError("invitation_not_pending", "Invitation is not pending", 409);
  }
  await recordCommittedAuthEvent(ctx, auditEvent);

  return updatedInvitation;
}

export async function listInvitations(
  ctx: AuthEngineContext,
  input: ListInvitationsInput
): Promise<Invitation<string>[]> {
  await requirePermission(
    ctx,
    input.organisationId,
    input.actorUserId,
    "invite_members"
  );
  return ctx.storage.listInvitationsByOrganisationId(input.organisationId);
}
