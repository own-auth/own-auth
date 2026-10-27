import { createId } from "./crypto.js";
import { AuthError } from "./errors.js";
import { normalizeEmail } from "./normalise.js";
import type { AuthEngineContext } from "./auth-engine-context.js";
import {
  accountFor,
  assertUserEnabled,
  createAuditEvent,
  userFor
} from "./auth-engine-internals.js";
import type { Account, OrganisationMember, RequestContext, User } from "./types.js";
import type {
  SamlConnection,
  SamlIntent,
  SamlVerifiedAssertion
} from "./saml-types.js";
import { hashSamlSubject, requireSaml } from "./saml-helpers.js";
import {
  findPairedSamlUser,
  verifyPairedSamlEmail
} from "./scim-saml.js";
import { recordCommittedAuthEvents } from "./webhook-outbox.js";
import { claimEmailOwnership } from "./auth-engine-email-ownership.js";

export interface ResolvedSamlIdentity {
  user: User;
  linked: boolean;
}

interface MappedSamlIdentity {
  provider: `saml.${string}`;
  providerAccountId: string;
  email: string | null;
  name: string | null;
}

export async function resolveSamlIdentity(
  ctx: AuthEngineContext,
  connection: SamlConnection,
  assertion: SamlVerifiedAssertion,
  transaction: { intent: SamlIntent; userId: string | null },
  request?: RequestContext
): Promise<ResolvedSamlIdentity> {
  const identity = mapIdentity(ctx, connection, assertion);
  const existingAccount = await ctx.storage.getAccountByProvider(
    identity.provider,
    identity.providerAccountId
  );
  if (existingAccount) {
    return resolveExistingAccount(
      ctx, connection, existingAccount, transaction, identity.email, request
    );
  }
  const pairedScimUser = identity.email
    ? await findPairedSamlUser(ctx, connection.id, identity.email)
    : null;
  if (transaction.intent === "link") {
    if (!transaction.userId) throw invalidTransaction();
    if (pairedScimUser && pairedScimUser.userId !== transaction.userId) {
      throw identityConflict();
    }
    const user = await requireIdentityUser(ctx, transaction.userId);
    const account = await linkIdentity(ctx, connection, identity, user, request);
    return {
      user: await verifyPairedSamlEmail(ctx, {
        samlConnectionId: connection.id, resource: pairedScimUser, user, normalizedEmail: identity.email,
        verifiedAccountId: account.id, request, originalActorUserId: transaction.userId
      }),
      linked: true
    };
  }
  if (!identity.email) throw verifiedEmailRequired();

  if (pairedScimUser) {
    const user = await requireIdentityUser(ctx, pairedScimUser.userId);
    const account = await linkIdentity(ctx, connection, identity, user, request);
    return {
      user: await verifyPairedSamlEmail(ctx, {
        samlConnectionId: connection.id, resource: pairedScimUser, user, normalizedEmail: identity.email,
        verifiedAccountId: account.id, request
      }),
      linked: true
    };
  }

  const existingUser = await ctx.storage.getUserByEmail(identity.email);
  if (existingUser) {
    return linkIdentityByEmail(ctx, connection, identity, existingUser, identity.email, request);
  }
  return provisionIdentity(ctx, connection, identity, request);
}

async function linkIdentityByEmail(
  ctx: AuthEngineContext,
  connection: SamlConnection,
  identity: MappedSamlIdentity,
  user: User,
  email: string,
  request?: RequestContext
): Promise<ResolvedSamlIdentity> {
  if (user.emailVerifiedAt) assertUserEnabled(user);
  if (connection.accountLinking !== "verified_email") {
    throw new AuthError(
      "account_linking_required",
      "Sign in to the existing account before linking this SAML identity",
      409
    );
  }
  await membershipFor(ctx, connection, user.id);
  const owner = await claimEmailOwnership(ctx, {
    user, email, proof: { kind: "provider", samlOrganisationId: connection.organisationId }, request
  });
  await linkIdentity(ctx, connection, identity, owner, request);
  return { user: owner, linked: true };
}

async function resolveExistingAccount(
  ctx: AuthEngineContext,
  connection: SamlConnection,
  account: Account,
  transaction: { intent: SamlIntent; userId: string | null },
  email: string | null,
  request?: RequestContext
): Promise<ResolvedSamlIdentity> {
  if (transaction.intent === "link" && account.userId !== transaction.userId) {
    throw identityConflict();
  }
  let user = await ctx.storage.getUserById(account.userId);
  if (!user) throw new AuthError("invalid_credentials", "Invalid SAML identity", 401);
  await membershipFor(ctx, connection, user.id);
  if (email && email === user.email) {
    user = await claimEmailOwnership(ctx, {
      user, email, verifiedAccountId: account.id, request,
      proof: {
        kind: "provider", samlOrganisationId: connection.organisationId,
        originalActorUserId: transaction.intent === "link" ? transaction.userId ?? undefined : undefined
      }
    });
  }
  assertUserEnabled(user);
  const paired = email ? await findPairedSamlUser(ctx, connection.id, email) : null;
  if (paired && paired.userId !== user.id) throw identityConflict();
  await ensureMembership(ctx, connection, user, request);
  return {
    user: await verifyPairedSamlEmail(ctx, {
      samlConnectionId: connection.id, resource: paired, user, normalizedEmail: email,
      verifiedAccountId: account.id, request
    }),
    linked: transaction.intent === "link"
  };
}

async function linkIdentity(
  ctx: AuthEngineContext,
  connection: SamlConnection,
  identity: MappedSamlIdentity,
  user: User,
  request?: RequestContext
): Promise<Account> {
  const existingMembership = await membershipFor(ctx, connection, user.id);
  const sameProvider = (await ctx.storage.listAccountsByUserId(user.id))
    .find((account) => account.provider === identity.provider);
  if (sameProvider) {
    if (sameProvider.providerAccountId === identity.providerAccountId) return sameProvider;
    throw new AuthError(
      "saml_identity_conflict",
      "A different SAML identity is already linked for this connection",
      409
    );
  }

  const now = new Date();
  const membership = existingMembership ? undefined : createMembership(connection, user.id, now);
  const account = accountFor(
    user.id,
    identity.provider,
    identity.providerAccountId,
    identity.email,
    null,
    now
  );
  const auditEvents = [createAuditEvent({
    eventType: "saml.identity_linked",
    actorUserId: user.id,
    targetUserId: user.id,
    organisationId: connection.organisationId,
    request,
    metadata: { connectionId: connection.id },
    now
  })];
  if (membership) {
    auditEvents.push(memberProvisionedEvent(connection, user.id, membership.role, request, now));
  }
  const { storage } = requireSaml(ctx);
  try {
    await storage.commitIdentity({
      account,
      membership,
      auditEvents
    });
    await recordCommittedAuthEvents(ctx, auditEvents);
    return account;
  } catch (error) {
    const winner = await ctx.storage.getAccountByProvider(
      identity.provider,
      identity.providerAccountId
    );
    if (winner?.userId === user.id) return winner;
    if (winner) throw identityConflict();
    const currentMembership = await ctx.storage.getOrganisationMember(
      connection.organisationId,
      user.id
    );
    if (membership && currentMembership?.status === "active") {
      const committedEvents = auditEvents.slice(0, 1);
      await storage.commitIdentity({ account, auditEvents: committedEvents });
      await recordCommittedAuthEvents(ctx, committedEvents);
      return account;
    }
    throw error;
  }
}

async function provisionIdentity(
  ctx: AuthEngineContext,
  connection: SamlConnection,
  identity: MappedSamlIdentity,
  request?: RequestContext
): Promise<ResolvedSamlIdentity> {
  if (!connection.jitProvisioningEnabled) throw membershipRequired();
  const email = identity.email;
  if (!email) throw verifiedEmailRequired();
  requireJitRole(ctx, connection.jitDefaultRole);

  const now = new Date();
  const user = userFor({
    email,
    emailVerifiedAt: now,
    phone: null,
    phoneVerifiedAt: null,
    passwordHash: null,
    name: identity.name ?? undefined
  }, now);
  const account = accountFor(
    user.id,
    identity.provider,
    identity.providerAccountId,
    email,
    null,
    now
  );
  const membership = createMembership(connection, user.id, now);
  const auditEvents = [
    createAuditEvent({
      eventType: "user.signed_up",
      actorUserId: user.id,
      targetUserId: user.id,
      organisationId: connection.organisationId,
      request,
      metadata: { provider: identity.provider },
      now
    }),
    createAuditEvent({
      eventType: "saml.identity_linked",
      actorUserId: user.id,
      targetUserId: user.id,
      organisationId: connection.organisationId,
      request,
      metadata: { connectionId: connection.id },
      now
    }),
    memberProvisionedEvent(connection, user.id, membership.role, request, now)
  ];
  const { storage } = requireSaml(ctx);
  try {
    await storage.commitIdentity({ user, account, membership, auditEvents });
    await recordCommittedAuthEvents(ctx, auditEvents);
    return { user, linked: true };
  } catch (error) {
    const winnerAccount = await ctx.storage.getAccountByProvider(
      identity.provider,
      identity.providerAccountId
    );
    if (winnerAccount) {
      return resolveExistingAccount(
        ctx,
        connection,
        winnerAccount,
        { intent: "sign_in", userId: null },
        email,
        request
      );
    }
    const winnerUser = await ctx.storage.getUserByEmail(email);
    if (winnerUser) {
      return linkIdentityByEmail(ctx, connection, identity, winnerUser, email, request);
    }
    throw error;
  }
}

async function ensureMembership(
  ctx: AuthEngineContext,
  connection: SamlConnection,
  user: User,
  request?: RequestContext
): Promise<void> {
  if (await membershipFor(ctx, connection, user.id)) return;
  const now = new Date();
  const membership = createMembership(connection, user.id, now);
  const { storage } = requireSaml(ctx);
  const auditEvents = [memberProvisionedEvent(
    connection,
    user.id,
    membership.role,
    request,
    now
  )];
  try {
    await storage.commitIdentity({
      membership,
      auditEvents
    });
    await recordCommittedAuthEvents(ctx, auditEvents);
  } catch (error) {
    const winner = await ctx.storage.getOrganisationMember(
      connection.organisationId,
      user.id
    );
    if (winner?.status === "active") return;
    throw error;
  }
}

async function membershipFor(
  ctx: AuthEngineContext,
  connection: SamlConnection,
  userId: string
): Promise<OrganisationMember<string> | null> {
  const existing = await ctx.storage.getOrganisationMember(connection.organisationId, userId);
  if (existing) {
    if (existing.status !== "active") throw membershipRequired();
    return existing;
  }
  if (!connection.jitProvisioningEnabled) throw membershipRequired();
  requireJitRole(ctx, connection.jitDefaultRole);
  return null;
}

function createMembership(
  connection: SamlConnection,
  userId: string,
  now: Date
): OrganisationMember<string> {
  return {
    id: createId("mem"),
    organisationId: connection.organisationId,
    userId,
    role: connection.jitDefaultRole,
    status: "active",
    joinedAt: now,
    removedAt: null,
    createdAt: now,
    updatedAt: now
  };
}

function mapIdentity(
  ctx: AuthEngineContext,
  connection: SamlConnection,
  assertion: SamlVerifiedAssertion
): MappedSamlIdentity {
  const subjectKey = connection.attributeMapping.subject ?? "nameId";
  const subject = subjectKey === "nameId"
    ? assertion.nameId.trim()
    : mappedScalar(assertion, subjectKey, true);
  if (!subject) throw new AuthError("saml_response_invalid", "SAML subject is missing", 401);
  const rawEmail = mappedScalar(assertion, connection.attributeMapping.email, false);
  const email = rawEmail ? normalizeEmail(rawEmail) : null;
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new AuthError("saml_response_invalid", "SAML email attribute is invalid", 401);
  }
  const name = connection.attributeMapping.name
    ? mappedScalar(assertion, connection.attributeMapping.name, false)
    : null;
  return {
    provider: `saml.${connection.key}`,
    providerAccountId: hashSamlSubject(ctx, connection.key, subject),
    email,
    name
  };
}

function mappedScalar(
  assertion: SamlVerifiedAssertion,
  name: string,
  required: boolean
): string | null {
  const value = assertion.attributes[name];
  if (typeof value === "string" && value.trim()) return value.trim();
  if (Array.isArray(value) && value.length === 1 && value[0]?.trim()) return value[0].trim();
  if (required || value !== undefined) {
    throw new AuthError("saml_response_invalid", `SAML attribute ${name} is invalid`, 401);
  }
  return null;
}

function memberProvisionedEvent(
  connection: SamlConnection,
  userId: string,
  role: string,
  request: RequestContext | undefined,
  now: Date
) {
  return createAuditEvent({
    eventType: "saml.member_provisioned",
    actorUserId: userId,
    targetUserId: userId,
    organisationId: connection.organisationId,
    request,
    metadata: { connectionId: connection.id, role },
    now
  });
}

async function requireIdentityUser(ctx: AuthEngineContext, userId: string): Promise<User> {
  const user = await ctx.storage.getUserById(userId);
  if (!user) throw new AuthError("invalid_credentials", "Invalid SAML identity", 401);
  assertUserEnabled(user);
  return user;
}

function requireJitRole(ctx: AuthEngineContext, role: string): void {
  if (role === "owner" || !ctx.authorization.hasRole(role)) {
    throw new AuthError("role_not_configured", "SAML JIT role is not configured", 409);
  }
}

function identityConflict(): AuthError {
  return new AuthError("saml_identity_conflict", "SAML identity is linked to another user", 409);
}

function membershipRequired(): AuthError {
  return new AuthError(
    "saml_membership_required",
    "An active organisation membership is required for this SAML connection",
    403
  );
}

function verifiedEmailRequired(): AuthError {
  return new AuthError(
    "saml_verified_email_required",
    "A trusted SAML email attribute is required",
    409
  );
}

function invalidTransaction(): AuthError {
  return new AuthError("saml_transaction_invalid", "SAML transaction is invalid", 401);
}
