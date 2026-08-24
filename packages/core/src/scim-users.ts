import { createId } from "./crypto.js";
import { AuthError } from "./errors.js";
import {
  createAuditEvent,
  rateLimit,
  requireActiveUser,
  userFor
} from "./auth-engine-internals.js";
import type { AuthEngineContext } from "./auth-engine-context.js";
import { requireOrganisationOwner } from "./auth-engine-organisation-access.js";
import type { OrganisationMember, RequestContext, User } from "./types.js";
import type {
  LinkScimUserInput,
  RestoreScimUserInput,
  ScimConnection,
  ScimToken,
  ScimUser,
  ScimUserAttributes,
  ScimUserFilter,
  ScimUserPage
} from "./scim-types.js";
import { recordCommittedAuthEvents } from "./webhook-outbox.js";
import { ScimProtocolError } from "./scim-protocol-error.js";
import {
  normalizeScimAttributes,
  normalizeScimUserName,
  requireScim,
  requireScimConnection,
  requireScimRole
} from "./scim-helpers.js";
import { hashScimToken } from "./scim-connections.js";

export interface AuthenticatedScimRequest {
  connection: ScimConnection;
  token: ScimToken;
}

export async function authenticateRequest(
  ctx: AuthEngineContext,
  rawToken: string,
  request?: RequestContext
): Promise<AuthenticatedScimRequest> {
  const { config, storage } = requireScim(ctx);
  const token = rawToken.startsWith("oa_scim_") && rawToken.length <= 256
    ? await storage.getTokenByHash(hashScimToken(ctx, rawToken))
    : null;
  const now = new Date();
  if (!token || token.revokedAt || (token.expiresAt && token.expiresAt <= now)) {
    if (request?.ipAddress) {
      await rateLimit(
        ctx,
        "scim-auth-failed",
        request.ipAddress,
        config.failedAuthLimit,
        config.failedAuthWindowMs
      );
    }
    throw new AuthError("scim_token_invalid", "Invalid SCIM token", 401);
  }
  const connection = await requireScimConnection(ctx, token.connectionId);
  await rateLimit(
    ctx,
    "scim-request",
    connection.id,
    config.requestLimit,
    config.requestWindowMs
  );
  const updatedToken = await storage.updateToken(token.id, { lastUsedAt: now });
  if (
    !updatedToken ||
    updatedToken.revokedAt ||
    (updatedToken.expiresAt && updatedToken.expiresAt <= now)
  ) {
    throw new AuthError("scim_token_invalid", "Invalid SCIM token", 401);
  }
  return { connection, token: updatedToken };
}

export async function linkUser(
  ctx: AuthEngineContext,
  input: LinkScimUserInput
): Promise<ScimUser> {
  const { storage } = requireScim(ctx);
  const connection = await requireScimConnection(ctx, input.connectionId);
  await requireOrganisationOwner(ctx, connection.organisationId, input.actorUserId);
  const user = await requireActiveUser(ctx, input.userId);
  const existingMember = await ctx.storage.getOrganisationMember(connection.organisationId, user.id);
  const existingResources = await storage.listUsersByOrganisationAndUser(
    connection.organisationId, user.id
  );
  if (existingMember || existingResources.length > 0) throw linkConflict();
  const attributes = normalizeScimAttributes(input);
  await requireIdentifiersAvailable(ctx, connection.id, attributes);
  const now = new Date();
  const membership = membershipFor(connection, user.id, attributes.active, now);
  const resource = resourceFor(connection.id, user.id, membership.id, attributes, now);
  const auditEvents = [createAuditEvent({
    eventType: "scim.user_linked",
    actorUserId: input.actorUserId,
    targetUserId: user.id,
    organisationId: connection.organisationId,
    request: input.request,
    metadata: { connectionId: connection.id, scimUserId: resource.id },
    now
  })];
  await storage.commitProvision({
    membership,
    scimUser: resource,
    auditEvents
  });
  await recordCommittedAuthEvents(ctx, auditEvents);
  return resource;
}

export async function restoreUser(
  ctx: AuthEngineContext,
  input: RestoreScimUserInput
): Promise<ScimUser> {
  const { storage } = requireScim(ctx);
  const connection = await requireScimConnection(ctx, input.connectionId);
  await requireOrganisationOwner(ctx, connection.organisationId, input.actorUserId);
  const resource = await storage.getUserById(input.scimUserId);
  if (!resource || resource.connectionId !== connection.id || !resource.deletedAt) {
    throw new AuthError("scim_user_not_found", "SCIM user not found", 404);
  }
  await requireActiveUser(ctx, resource.userId);
  const membership = await ctx.storage.getOrganisationMemberById(resource.membershipId);
  const resources = await storage.listUsersByOrganisationAndUser(
    connection.organisationId, resource.userId
  );
  const userNameOwner = await storage.getUserByUserName(
    connection.id, resource.normalizedUserName
  );
  const externalOwner = resource.externalId
    ? await storage.getUserByExternalId(connection.id, resource.externalId)
    : null;
  const emailOwner = resource.normalizedEmail
    ? await storage.getActiveUserByEmail(connection.id, resource.normalizedEmail)
    : null;
  if (
    !membership || membership.organisationId !== connection.organisationId ||
    membership.userId !== resource.userId || membership.status !== "removed" ||
    membership.role === "owner" || !ctx.authorization.hasRole(membership.role) ||
    resources.some((candidate) => candidate.id !== resource.id) ||
    (userNameOwner && userNameOwner.id !== resource.id) ||
    (externalOwner && externalOwner.id !== resource.id) ||
    (emailOwner && emailOwner.id !== resource.id)
  ) throw restoreConflict();

  const now = new Date();
  const auditEvent = createAuditEvent({
    eventType: "scim.user_restored",
    actorUserId: input.actorUserId,
    targetUserId: resource.userId,
    organisationId: connection.organisationId,
    request: input.request,
    metadata: { connectionId: connection.id, scimUserId: resource.id },
    now
  });
  const restored = await storage.mutateUser({
    id: resource.id,
    expectedVersion: resource.version,
    patch: { active: true, deletedAt: null, updatedAt: now },
    membershipPatch: {
      status: "active",
      joinedAt: now,
      removedAt: null,
      updatedAt: now
    },
    auditEvent
  });
  if (!restored) throw restoreConflict();
  await recordCommittedAuthEvents(ctx, [auditEvent]);
  return restored;
}

export async function createUserResource(
  ctx: AuthEngineContext,
  connection: ScimConnection,
  input: ScimUserAttributes,
  request?: RequestContext
): Promise<ScimUser> {
  const { storage } = requireScim(ctx);
  const attributes = normalizeScimAttributes(input);
  requireScimRole(ctx, connection.defaultRole);
  await requireIdentifiersAvailable(ctx, connection.id, attributes);

  const existingUser = attributes.email
    ? await ctx.storage.getUserByEmail(attributes.email)
    : null;
  let user: User;
  let createUser: User | undefined;
  let linked = false;
  if (existingUser) {
    const membership = await ctx.storage.getOrganisationMember(
      connection.organisationId, existingUser.id
    );
    const resources = await storage.listUsersByOrganisationAndUser(
      connection.organisationId, existingUser.id
    );
    if (
      connection.accountLinking !== "email" || !existingUser.emailVerifiedAt ||
      existingUser.disabledAt || membership || resources.length > 0
    ) throw uniqueness();
    user = existingUser;
    linked = true;
  } else {
    const now = new Date();
    createUser = userFor({
      email: attributes.email,
      emailVerifiedAt: null,
      phone: null,
      phoneVerifiedAt: null,
      passwordHash: null,
      name: attributes.displayName ?? undefined
    }, now);
    user = createUser;
  }

  const now = new Date();
  const membership = membershipFor(connection, user.id, attributes.active, now);
  const resource = resourceFor(connection.id, user.id, membership.id, attributes, now);
  const auditEvents = [createAuditEvent({
    eventType: "scim.user_created",
    targetUserId: user.id,
    organisationId: connection.organisationId,
    request,
    metadata: { connectionId: connection.id, scimUserId: resource.id },
    now
  })];
  if (createUser) {
    auditEvents.unshift(createAuditEvent({
      eventType: "user.signed_up",
      actorUserId: user.id,
      targetUserId: user.id,
      organisationId: connection.organisationId,
      request,
      metadata: { provider: "scim" },
      now
    }));
  }
  if (linked) {
    auditEvents.push(createAuditEvent({
      eventType: "scim.user_linked",
      targetUserId: user.id,
      organisationId: connection.organisationId,
      request,
      metadata: { connectionId: connection.id, scimUserId: resource.id },
      now
    }));
  }
  try {
    await storage.commitProvision({ user: createUser, membership, scimUser: resource, auditEvents });
    await recordCommittedAuthEvents(ctx, auditEvents);
  } catch (error) {
    if (
      await storage.getUserByUserName(connection.id, resource.normalizedUserName) ||
      (resource.externalId && await storage.getUserByExternalId(connection.id, resource.externalId)) ||
      (resource.normalizedEmail && await storage.getActiveUserByEmail(
        connection.id, resource.normalizedEmail
      )) ||
      await ctx.storage.getOrganisationMember(connection.organisationId, user.id)
    ) throw uniqueness();
    throw error;
  }
  return resource;
}

export async function getUserResource(
  ctx: AuthEngineContext,
  connectionId: string,
  resourceId: string
): Promise<ScimUser> {
  const { storage } = requireScim(ctx);
  const resource = await storage.getUserById(resourceId);
  if (!resource || resource.connectionId !== connectionId || resource.deletedAt) throw noTarget();
  return resource;
}

export async function listUserResources(
  ctx: AuthEngineContext,
  connectionId: string,
  filter: ScimUserFilter | null,
  startIndex: number,
  count: number
): Promise<ScimUserPage> {
  const { storage } = requireScim(ctx);
  const normalized = filter?.attribute === "userName"
    ? { ...filter, value: normalizeScimUserName(filter.value) }
    : filter;
  return storage.listUsers(connectionId, normalized, startIndex, count);
}

export async function replaceUserResource(
  ctx: AuthEngineContext,
  connection: ScimConnection,
  resourceId: string,
  input: ScimUserAttributes,
  expectedVersion: number | null,
  request?: RequestContext
): Promise<ScimUser> {
  const { storage } = requireScim(ctx);
  const resource = await getUserResource(ctx, connection.id, resourceId);
  if (expectedVersion !== null && resource.version !== expectedVersion) throw versionConflict();
  const attributes = normalizeScimAttributes(input);
  await requireIdentifiersAvailable(ctx, connection.id, attributes, resource.id);
  const member = await ctx.storage.getOrganisationMemberById(resource.membershipId);
  if (!member || member.status === "removed" || member.role === "owner") throw uniqueness();

  const changed = changedFields(resource, attributes);
  if (changed.length === 0) return resource;
  const now = new Date();
  const eventType = resource.active !== attributes.active
    ? attributes.active ? "scim.user_reactivated" : "scim.user_suspended"
    : "scim.user_updated";
  const auditEvent = createAuditEvent({
    eventType,
    targetUserId: resource.userId,
    organisationId: connection.organisationId,
    request,
    metadata: { connectionId: connection.id, scimUserId: resource.id, fields: changed },
    now
  });
  const updated = await storage.mutateUser({
    id: resource.id,
    expectedVersion: resource.version,
    patch: {
      externalId: attributes.externalId,
      userName: attributes.userName,
      normalizedUserName: normalizeScimUserName(attributes.userName),
      email: attributes.email,
      normalizedEmail: attributes.email,
      displayName: attributes.displayName,
      givenName: attributes.givenName,
      familyName: attributes.familyName,
      active: attributes.active,
      updatedAt: now
    },
    membershipPatch: attributes.active === resource.active ? undefined : {
      status: attributes.active ? "active" : "suspended",
      joinedAt: attributes.active ? member.joinedAt ?? now : member.joinedAt,
      removedAt: null,
      updatedAt: now
    },
    auditEvent
  });
  if (!updated) throw versionConflict();
  await recordCommittedAuthEvents(ctx, [auditEvent]);
  return updated;
}

export async function deleteUserResource(
  ctx: AuthEngineContext,
  connection: ScimConnection,
  resourceId: string,
  expectedVersion: number | null,
  request?: RequestContext
): Promise<ScimUser> {
  const { storage } = requireScim(ctx);
  const resource = await getUserResource(ctx, connection.id, resourceId);
  if (expectedVersion !== null && resource.version !== expectedVersion) throw versionConflict();
  const member = await ctx.storage.getOrganisationMemberById(resource.membershipId);
  if (!member || member.role === "owner") throw uniqueness();
  const now = new Date();
  const auditEvent = createAuditEvent({
    eventType: "scim.user_deleted",
    targetUserId: resource.userId,
    organisationId: connection.organisationId,
    request,
    metadata: { connectionId: connection.id, scimUserId: resource.id },
    now
  });
  const deleted = await storage.mutateUser({
    id: resource.id,
    expectedVersion: resource.version,
    patch: { active: false, deletedAt: now, updatedAt: now },
    membershipPatch: {
      status: "removed",
      removedAt: now,
      updatedAt: now
    },
    auditEvent
  });
  if (!deleted) throw versionConflict();
  await recordCommittedAuthEvents(ctx, [auditEvent]);
  return deleted;
}

function membershipFor(
  connection: ScimConnection,
  userId: string,
  active: boolean,
  now: Date
): OrganisationMember<string> {
  return {
    id: createId("mem"),
    organisationId: connection.organisationId,
    userId,
    role: connection.defaultRole,
    status: active ? "active" : "suspended",
    joinedAt: active ? now : null,
    removedAt: null,
    createdAt: now,
    updatedAt: now
  };
}

function resourceFor(
  connectionId: string,
  userId: string,
  membershipId: string,
  input: Required<ScimUserAttributes>,
  now: Date
): ScimUser {
  return {
    id: createId("scimu"),
    connectionId,
    userId,
    membershipId,
    externalId: input.externalId,
    userName: input.userName,
    normalizedUserName: normalizeScimUserName(input.userName),
    email: input.email,
    normalizedEmail: input.email,
    displayName: input.displayName,
    givenName: input.givenName,
    familyName: input.familyName,
    active: input.active,
    version: 1,
    deletedAt: null,
    createdAt: now,
    updatedAt: now
  };
}

async function requireIdentifiersAvailable(
  ctx: AuthEngineContext,
  connectionId: string,
  input: Required<ScimUserAttributes>,
  exceptId?: string
): Promise<void> {
  const { storage } = requireScim(ctx);
  const userName = await storage.getUserByUserName(
    connectionId, normalizeScimUserName(input.userName)
  );
  const external = input.externalId
    ? await storage.getUserByExternalId(connectionId, input.externalId)
    : null;
  const email = input.email
    ? await storage.getActiveUserByEmail(connectionId, input.email)
    : null;
  if (
    (userName && userName.id !== exceptId) ||
    (external && external.id !== exceptId) ||
    (email && email.id !== exceptId)
  ) {
    throw uniqueness();
  }
}

function changedFields(resource: ScimUser, input: Required<ScimUserAttributes>): string[] {
  const fields: Array<[string, unknown, unknown]> = [
    ["externalId", resource.externalId, input.externalId],
    ["userName", resource.userName, input.userName],
    ["email", resource.email, input.email],
    ["displayName", resource.displayName, input.displayName],
    ["givenName", resource.givenName, input.givenName],
    ["familyName", resource.familyName, input.familyName],
    ["active", resource.active, input.active]
  ];
  return fields.filter(([, before, after]) => before !== after).map(([field]) => field);
}

function uniqueness(): ScimProtocolError {
  return new ScimProtocolError(409, "uniqueness", "SCIM user conflicts with an existing resource");
}

function noTarget(): ScimProtocolError {
  return new ScimProtocolError(404, "noTarget", "SCIM user not found");
}

function versionConflict(): ScimProtocolError {
  return new ScimProtocolError(412, null, "SCIM resource version does not match");
}

function linkConflict(): AuthError {
  return new AuthError("scim_restore_conflict", "User cannot be linked to this SCIM connection", 409);
}

function restoreConflict(): AuthError {
  return new AuthError("scim_restore_conflict", "SCIM user cannot be restored", 409);
}
