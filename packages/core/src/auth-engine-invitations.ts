import { AuthError } from "./errors.js";
import { createId } from "./crypto.js";
import { isExpired, normalizeEmail } from "./normalise.js";
import type { Invitation, OrganisationMember } from "./types.js";
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
  consumeToken,
  getUsableToken,
  issueToken,
  rateLimit,
  requireActiveUser,
  type AuthEngineContext
} from "./auth-engine-internals.js";
import {
  requireActiveOrganisation,
  requirePermission
} from "./auth-engine-organisations.js";

export async function inviteMember(
  ctx: AuthEngineContext,
  input: InviteMemberInput
): Promise<InvitationResult> {
  await requirePermission(ctx, input.organisationId, input.invitedByUserId, "invite_members");

  const email = normalizeEmail(input.email);
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
    role: input.role ?? "member",
    invitedByUserId: input.invitedByUserId,
    status: "pending",
    expiresAt: issued.token.expiresAt,
    acceptedAt: null,
    revokedAt: null,
    createdAt: now
  });
  const url = buildUrl(ctx, "/auth/invitations/accept", { token: issued.rawToken });

  await ctx.emailProvider.send({
    to: email,
    type: "organisation_invite",
    token: issued.rawToken,
    url,
    expiresAt: issued.token.expiresAt
  });

  await audit(ctx, {
    eventType: "member.invited",
    actorUserId: input.invitedByUserId,
    organisationId: input.organisationId,
    context: input.request,
    metadata: { email, role: invitation.role, invitationId: invitation.id }
  });

  const result: InvitationResult = { invitation };
  if (ctx.exposeRawTokens) {
    result.token = issued.rawToken;
    result.url = url;
  }

  return result;
}

export async function acceptInvite(
  ctx: AuthEngineContext,
  input: AcceptInviteInput
): Promise<AcceptInviteResult> {
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

  await consumeToken(ctx, input.token, "organisation_invite");

  const now = new Date();
  let member = await ctx.storage.getOrganisationMember(organisationId, user.id);
  if (member) {
    member = (await ctx.storage.updateOrganisationMember(member.id, {
      role: pendingInvitation.role,
      status: "active",
      joinedAt: member.joinedAt ?? now,
      removedAt: null,
      updatedAt: now
    })) ?? member;
  } else {
    member = await ctx.storage.createOrganisationMember({
      id: createId("mem"),
      organisationId,
      userId: user.id,
      role: pendingInvitation.role,
      status: "active",
      joinedAt: now,
      removedAt: null,
      createdAt: now,
      updatedAt: now
    });
  }

  const invitation = (await ctx.storage.updateInvitation(pendingInvitation.id, {
    status: "accepted",
    acceptedAt: now
  })) ?? pendingInvitation;

  await audit(ctx, {
    eventType: "invite.accepted",
    actorUserId: user.id,
    targetUserId: user.id,
    organisationId,
    context: input.request,
    metadata: { invitationId: invitation.id }
  });

  return { organisation, member };
}

export async function revokeInvitation(
  ctx: AuthEngineContext,
  input: RevokeInvitationInput
): Promise<Invitation> {
  const invitation = await ctx.storage.getInvitationById(input.invitationId);
  if (!invitation) {
    throw new AuthError("invitation_not_found", "Invitation not found", 404);
  }

  await requirePermission(ctx, invitation.organisationId, input.actorUserId, "invite_members");

  if (invitation.status !== "pending") {
    throw new AuthError("invitation_not_pending", "Invitation is not pending", 409);
  }

  const now = new Date();
  const updatedInvitation = await ctx.storage.updateInvitation(input.invitationId, {
    status: "revoked",
    revokedAt: now
  });
  if (invitation.tokenId) {
    await ctx.storage.updateToken(invitation.tokenId, { usedAt: now });
  }

  await audit(ctx, {
    eventType: "invite.revoked",
    actorUserId: input.actorUserId,
    organisationId: invitation.organisationId,
    context: input.request,
    metadata: { invitationId: invitation.id, email: invitation.email }
  });

  return updatedInvitation ?? invitation;
}

export async function listInvitations(
  ctx: AuthEngineContext,
  input: ListInvitationsInput
): Promise<Invitation[]> {
  await requirePermission(
    ctx,
    input.organisationId,
    input.actorUserId,
    "invite_members"
  );
  return ctx.storage.listInvitationsByOrganisationId(input.organisationId);
}
