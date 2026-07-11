import { AuthError } from "./errors.js";
import { createId } from "./crypto.js";
import { slugify } from "./normalise.js";
import { roleHasPermission, type Permission } from "./permissions.js";
import type {
  Organisation,
  OrganisationMember,
  OrganisationMemberDetails
} from "./types.js";
import type {
  ChangeMemberRoleInput,
  CreateOrganisationInput,
  DeleteOrganisationInput,
  GetMemberInput,
  GetOrganisationInput,
  ListMembersInput,
  RemoveMemberInput,
  UpdateOrganisationInput
} from "./auth-engine-types.js";
import {
  audit,
  cloneMetadata,
  requireActiveUser,
  uniqueOrganisationSlug,
  type AuthEngineContext
} from "./auth-engine-internals.js";

export async function createOrganisation(
  ctx: AuthEngineContext,
  input: CreateOrganisationInput
): Promise<{
  organisation: Organisation;
  ownerMembership: OrganisationMember;
}> {
  await requireActiveUser(ctx, input.ownerUserId);

  const now = new Date();
  const baseSlug = slugify(input.slug ?? input.name);
  const slug = await uniqueOrganisationSlug(ctx, baseSlug);
  const organisation = await ctx.storage.createOrganisation({
    id: createId("org"),
    name: input.name,
    slug,
    ownerUserId: input.ownerUserId,
    metadata: cloneMetadata(input.metadata),
    createdAt: now,
    updatedAt: now,
    disabledAt: null
  });
  const ownerMembership = await ctx.storage.createOrganisationMember({
    id: createId("mem"),
    organisationId: organisation.id,
    userId: input.ownerUserId,
    role: "owner",
    status: "active",
    joinedAt: now,
    removedAt: null,
    createdAt: now,
    updatedAt: now
  });

  await audit(ctx, {
    eventType: "organisation.created",
    actorUserId: input.ownerUserId,
    targetUserId: input.ownerUserId,
    organisationId: organisation.id,
    context: input.request,
    metadata: { name: input.name, slug }
  });

  return { organisation, ownerMembership };
}

export async function getOrganisation(
  ctx: AuthEngineContext,
  input: GetOrganisationInput
): Promise<Organisation> {
  const organisation = await requireActiveOrganisation(ctx, input.organisationId);
  const actor = await ctx.storage.getUserById(input.actorUserId);
  if (!actor || actor.disabledAt) {
    throw new AuthError("organisation_not_found", "Organisation not found", 404);
  }
  const member = await ctx.storage.getOrganisationMember(
    input.organisationId,
    input.actorUserId
  );

  if (!member || member.status !== "active") {
    throw new AuthError("organisation_not_found", "Organisation not found", 404);
  }

  return organisation;
}

export async function deleteOrganisation(
  ctx: AuthEngineContext,
  input: DeleteOrganisationInput
): Promise<Organisation> {
  const organisation = await ctx.storage.getOrganisationById(input.organisationId);
  if (!organisation) {
    throw new AuthError("organisation_not_found", "Organisation not found", 404);
  }

  await requireActiveUser(ctx, input.actorUserId);
  if (organisation.ownerUserId !== input.actorUserId) {
    throw new AuthError("permission_denied", "Only the organisation owner can delete it", 403);
  }

  const [members, apiKeys, invitations] = await Promise.all([
    ctx.storage.listOrganisationMembers(organisation.id),
    ctx.storage.listApiKeysByOrganisationId(organisation.id),
    ctx.storage.listInvitationsByOrganisationId(organisation.id)
  ]);
  const deleted = await ctx.storage.deleteOrganisation(organisation.id);
  if (!deleted) {
    throw new AuthError("organisation_not_found", "Organisation not found", 404);
  }

  await audit(ctx, {
    eventType: "organisation.deleted",
    actorUserId: input.actorUserId,
    context: input.request,
    metadata: {
      organisationId: organisation.id,
      name: organisation.name,
      slug: organisation.slug,
      membersRemoved: members.length,
      apiKeysRemoved: apiKeys.length,
      invitationsRemoved: invitations.length
    }
  });

  return organisation;
}

export async function updateOrganisation(
  ctx: AuthEngineContext,
  organisationId: string,
  input: UpdateOrganisationInput
): Promise<Organisation> {
  await requirePermission(ctx, organisationId, input.actorUserId, "manage_basic_settings");

  const patch: Partial<Organisation> = {
    updatedAt: new Date()
  };

  if (input.name !== undefined) patch.name = input.name;
  if (input.slug !== undefined) {
    patch.slug = await uniqueOrganisationSlug(ctx, slugify(input.slug));
  }
  if (input.metadata !== undefined) patch.metadata = cloneMetadata(input.metadata);

  const organisation = await ctx.storage.updateOrganisation(organisationId, patch);
  if (!organisation) {
    throw new AuthError("organisation_not_found", "Organisation not found", 404);
  }

  await audit(ctx, {
    eventType: "organisation.updated",
    actorUserId: input.actorUserId,
    organisationId,
    context: input.request,
    metadata: patch
  });

  return organisation;
}

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

  const organisation = await ctx.storage.getOrganisationById(input.organisationId);
  const member = await ctx.storage.getOrganisationMember(
    input.organisationId,
    input.userId
  );
  if (
    !organisation ||
    !member ||
    member.organisationId !== input.organisationId ||
    member.status !== "active"
  ) {
    throw new AuthError("member_not_found", "Member not found", 404);
  }

  let ownershipTransferredTo: string | null = null;
  if (member.role === "owner" && input.role !== "owner") {
    const replacement = await findReplacementOwner(ctx, input.organisationId, member.id);
    if (!replacement) {
      throw new AuthError("last_owner", "Promote another member to owner first", 409);
    }
    if (member.userId === organisation.ownerUserId) {
      ownershipTransferredTo = replacement.userId;
      await ctx.storage.updateOrganisation(organisation.id, {
        ownerUserId: replacement.userId,
        updatedAt: new Date()
      });
    }
  }

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

  const organisation = await ctx.storage.getOrganisationById(input.organisationId);
  const member = await ctx.storage.getOrganisationMember(
    input.organisationId,
    input.userId
  );
  if (
    !organisation ||
    !member ||
    member.organisationId !== input.organisationId ||
    member.status !== "active"
  ) {
    throw new AuthError("member_not_found", "Member not found", 404);
  }

  if (member.role === "owner" && actor.role !== "owner") {
    throw new AuthError("permission_denied", "Only owners can remove owners", 403);
  }

  let ownershipTransferredTo: string | null = null;
  if (member.role === "owner") {
    const replacement = await findReplacementOwner(ctx, input.organisationId, member.id);
    if (!replacement) {
      throw new AuthError("last_owner", "Promote another member to owner first", 409);
    }
    if (member.userId === organisation.ownerUserId) {
      ownershipTransferredTo = replacement.userId;
      await ctx.storage.updateOrganisation(organisation.id, {
        ownerUserId: replacement.userId,
        updatedAt: new Date()
      });
    }
  }

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

async function findReplacementOwner(
  ctx: AuthEngineContext,
  organisationId: string,
  excludedMemberId: string
): Promise<OrganisationMember | null> {
  const members = await ctx.storage.listOrganisationMembers(organisationId);
  return members.find(
    (member) =>
      member.id !== excludedMemberId &&
      member.status === "active" &&
      member.role === "owner"
  ) ?? null;
}

export async function listMembers(
  ctx: AuthEngineContext,
  input: ListMembersInput
): Promise<OrganisationMemberDetails[]> {
  await requirePermission(ctx, input.organisationId, input.actorUserId, "view_members");
  const members = await ctx.storage.listOrganisationMembers(input.organisationId);
  return Promise.all(
    members
      .filter((member) => member.status === "active")
      .map((member) => memberDetails(ctx, member))
  );
}

export async function getMember(
  ctx: AuthEngineContext,
  input: GetMemberInput
): Promise<OrganisationMemberDetails> {
  await requirePermission(ctx, input.organisationId, input.actorUserId, "view_members");
  const member = await ctx.storage.getOrganisationMember(
    input.organisationId,
    input.userId
  );
  if (
    !member ||
    member.organisationId !== input.organisationId ||
    member.status !== "active"
  ) {
    throw new AuthError("member_not_found", "Member not found", 404);
  }

  return memberDetails(ctx, member);
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

export async function checkPermission(
  ctx: AuthEngineContext,
  organisationId: string,
  userId: string,
  permission: Permission
): Promise<boolean> {
  const organisation = await ctx.storage.getOrganisationById(organisationId);
  if (!organisation || organisation.disabledAt) {
    return false;
  }

  const user = await ctx.storage.getUserById(userId);
  if (!user || user.disabledAt) {
    return false;
  }

  const member = await ctx.storage.getOrganisationMember(organisationId, userId);
  return Boolean(member && member.status === "active" && roleHasPermission(member.role, permission));
}

export async function requireActiveOrganisation(
  ctx: AuthEngineContext,
  organisationId: string
): Promise<Organisation> {
  const organisation = await ctx.storage.getOrganisationById(organisationId);
  if (!organisation || organisation.disabledAt) {
    throw new AuthError("organisation_not_found", "Organisation not found", 404);
  }

  return organisation;
}

export async function requirePermission(
  ctx: AuthEngineContext,
  organisationId: string,
  userId: string,
  permission: Permission
): Promise<OrganisationMember> {
  await requireActiveOrganisation(ctx, organisationId);
  const user = await ctx.storage.getUserById(userId);
  if (!user || user.disabledAt) {
    throw new AuthError("permission_denied", "Permission denied", 403);
  }

  const member = await ctx.storage.getOrganisationMember(organisationId, userId);

  if (!member || member.status !== "active" || !roleHasPermission(member.role, permission)) {
    throw new AuthError("permission_denied", "You do not have permission for this action", 403);
  }

  return member;
}

export async function listOrganisations(
  ctx: AuthEngineContext,
  actorUserId: string
): Promise<Organisation[]> {
  await requireActiveUser(ctx, actorUserId);
  const organisations = await ctx.storage.listOrganisationsByUserId(actorUserId);
  return organisations.filter((organisation) => !organisation.disabledAt);
}
