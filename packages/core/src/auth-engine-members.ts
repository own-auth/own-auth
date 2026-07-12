import { AuthError } from "./errors.js";
import type {
  Organisation,
  OrganisationMember,
  OrganisationMemberDetails
} from "./types.js";
import type {
  ChangeMemberRoleInput,
  GetMemberInput,
  ListMembersInput,
  RemoveMemberInput
} from "./auth-engine-types.js";
import { audit, type AuthEngineContext } from "./auth-engine-internals.js";
import { requirePermission } from "./auth-engine-organisation-access.js";

export async function changeMemberRole(
  ctx: AuthEngineContext,
  input: ChangeMemberRoleInput
): Promise<OrganisationMember> {
  await requirePermission(
    ctx,
    input.organisationId,
    input.actorUserId,
    "change_member_roles"
  );
  const { organisation, member } = await requireTargetMember(
    ctx,
    input.organisationId,
    input.userId
  );
  const ownershipTransferredTo = member.role === "owner" && input.role !== "owner"
    ? await transferOwnership(ctx, organisation, member)
    : null;
  const updatedMember = await ctx.storage.updateOrganisationMember(member.id, {
    role: input.role,
    updatedAt: new Date()
  });

  await audit(ctx, {
    eventType: "member.role_changed",
    actorUserId: input.actorUserId,
    targetUserId: member.userId,
    organisationId: input.organisationId,
    context: input.request,
    metadata: {
      previousRole: member.role,
      role: input.role,
      ownershipTransferredTo
    }
  });

  return updatedMember ?? member;
}

export async function removeMember(
  ctx: AuthEngineContext,
  input: RemoveMemberInput
): Promise<OrganisationMember> {
  const actor = await requirePermission(
    ctx,
    input.organisationId,
    input.actorUserId,
    "remove_members"
  );
  const { organisation, member } = await requireTargetMember(
    ctx,
    input.organisationId,
    input.userId
  );

  if (member.role === "owner" && actor.role !== "owner") {
    throw new AuthError("permission_denied", "Only owners can remove owners", 403);
  }

  const ownershipTransferredTo = member.role === "owner"
    ? await transferOwnership(ctx, organisation, member)
    : null;
  const now = new Date();
  const updatedMember = await ctx.storage.updateOrganisationMember(member.id, {
    status: "removed",
    removedAt: now,
    updatedAt: now
  });

  await audit(ctx, {
    eventType: "member.removed",
    actorUserId: input.actorUserId,
    targetUserId: member.userId,
    organisationId: input.organisationId,
    context: input.request,
    metadata: {
      memberId: member.id,
      role: member.role,
      ownershipTransferredTo
    }
  });

  return updatedMember ?? member;
}

export async function listMembers(
  ctx: AuthEngineContext,
  input: ListMembersInput
): Promise<OrganisationMemberDetails[]> {
  await requirePermission(ctx, input.organisationId, input.actorUserId, "view_members");
  const members = await ctx.storage.listOrganisationMembers(input.organisationId);
  const details: OrganisationMemberDetails[] = [];
  for (const member of members) {
    if (member.status === "active") {
      details.push(await memberDetails(ctx, member));
    }
  }
  return details;
}

export async function getMember(
  ctx: AuthEngineContext,
  input: GetMemberInput
): Promise<OrganisationMemberDetails> {
  await requirePermission(ctx, input.organisationId, input.actorUserId, "view_members");
  const { member } = await requireTargetMember(ctx, input.organisationId, input.userId);
  return memberDetails(ctx, member);
}

async function requireTargetMember(
  ctx: AuthEngineContext,
  organisationId: string,
  userId: string
): Promise<{ organisation: Organisation; member: OrganisationMember }> {
  const organisation = await ctx.storage.getOrganisationById(organisationId);
  const member = await ctx.storage.getOrganisationMember(organisationId, userId);
  if (!organisation || !member || member.status !== "active") {
    throw new AuthError("member_not_found", "Member not found", 404);
  }

  return { organisation, member };
}

async function transferOwnership(
  ctx: AuthEngineContext,
  organisation: Organisation,
  member: OrganisationMember
): Promise<string | null> {
  const members = await ctx.storage.listOrganisationMembers(organisation.id);
  const replacement = members.find(
    (candidate) =>
      candidate.id !== member.id &&
      candidate.status === "active" &&
      candidate.role === "owner"
  );
  if (!replacement) {
    throw new AuthError("last_owner", "Promote another member to owner first", 409);
  }
  if (member.userId !== organisation.ownerUserId) {
    return null;
  }

  await ctx.storage.updateOrganisation(organisation.id, {
    ownerUserId: replacement.userId,
    updatedAt: new Date()
  });
  return replacement.userId;
}

async function memberDetails(
  ctx: AuthEngineContext,
  member: OrganisationMember
): Promise<OrganisationMemberDetails> {
  const user = await ctx.storage.getUserById(member.userId);
  return {
    ...member,
    name: user?.name ?? null,
    email: user?.email ?? null
  };
}
