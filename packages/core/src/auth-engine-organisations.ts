import { createId } from "./crypto.js";
import { AuthError } from "./errors.js";
import { slugify } from "./normalise.js";
import type { Organisation, OrganisationMember } from "./types.js";
import type {
  CreateOrganisationInput,
  DeleteOrganisationInput,
  GetOrganisationInput,
  UpdateOrganisationInput
} from "./auth-engine-types.js";
import {
  audit,
  cloneMetadata,
  requireActiveUser,
  uniqueOrganisationSlug,
  type AuthEngineContext
} from "./auth-engine-internals.js";
import {
  requireOrganisationAccess,
  requirePermission
} from "./auth-engine-organisation-access.js";

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
  const { organisation } = await requireOrganisationAccess(
    ctx,
    input.organisationId,
    input.actorUserId
  );
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

  const members = await ctx.storage.listOrganisationMembers(organisation.id);
  const apiKeys = await ctx.storage.listApiKeysByOrganisationId(organisation.id);
  const invitations = await ctx.storage.listInvitationsByOrganisationId(organisation.id);
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

  const patch: Partial<Organisation> = { updatedAt: new Date() };
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

export async function listOrganisations(
  ctx: AuthEngineContext,
  actorUserId: string
): Promise<Organisation[]> {
  await requireActiveUser(ctx, actorUserId);
  const organisations = await ctx.storage.listOrganisationsByUserId(actorUserId);
  return organisations.filter((organisation) => !organisation.disabledAt);
}
