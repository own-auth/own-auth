import type {
  Organisation,
  OrganisationMember,
  Session,
  User
} from "../types.js";
import type { PasskeyCredential } from "../identity-types.js";
import type {
  AdministrationSession,
  AdministrationUser
} from "../administration.js";
import type {
  AuthSessionPayload,
  DeliveryPayload,
  PublicAuthSession,
  PublicAuthUser,
  PublicAdministrationAuditEvent,
  PublicAdministrationSession,
  PublicAdministrationUser,
  PublicOrganisation,
  PublicOrganisationMember,
  PublicPasskey
} from "./contract.js";
import type { AuditEvent } from "../types.js";

type PublicUserSource = Omit<User, "disabledAt" | "passwordHash">;
type PublicSessionSource = Omit<Session, "revokeReason" | "revokedAt" | "tokenHash">;

export function serializeUser(user: PublicUserSource): PublicAuthUser {
  return {
    id: user.id,
    email: user.email,
    emailVerifiedAt: toIso(user.emailVerifiedAt),
    phone: user.phone,
    phoneVerifiedAt: toIso(user.phoneVerifiedAt),
    name: user.name,
    imageUrl: user.imageUrl,
    metadata: structuredClone(user.metadata),
    createdAt: user.createdAt.toISOString(),
    updatedAt: user.updatedAt.toISOString(),
    lastLoginAt: toIso(user.lastLoginAt)
  };
}

export function serializeSession(session: PublicSessionSource): PublicAuthSession {
  return {
    id: session.id,
    userId: session.userId,
    createdAt: session.createdAt.toISOString(),
    lastActiveAt: session.lastActiveAt.toISOString(),
    expiresAt: session.expiresAt.toISOString(),
    idleExpiresAt: session.idleExpiresAt.toISOString(),
    ipAddress: session.ipAddress,
    userAgent: session.userAgent,
    authenticationMethods: [...session.authenticationMethods],
    assuranceLevel: session.assuranceLevel,
    authenticatedAt: session.authenticatedAt.toISOString()
  };
}

export function serializeAuthSession(input: {
  user: User;
  session: Session;
}): AuthSessionPayload {
  return {
    status: "complete",
    user: serializeUser(input.user),
    session: serializeSession(input.session)
  };
}

export function serializePasskey(passkey: PasskeyCredential): PublicPasskey {
  return {
    id: passkey.id,
    name: passkey.name,
    discoverable: passkey.discoverable,
    deviceType: passkey.deviceType,
    backedUp: passkey.backedUp,
    createdAt: passkey.createdAt.toISOString(),
    lastUsedAt: toIso(passkey.lastUsedAt)
  };
}

export function serializeAdministrationUser(
  user: AdministrationUser
): PublicAdministrationUser {
  return {
    ...serializeUser(user),
    disabledAt: toIso(user.disabledAt)
  };
}

export function serializeAdministrationSession(
  session: AdministrationSession
): PublicAdministrationSession {
  return {
    ...serializeSession(session),
    revokedAt: toIso(session.revokedAt),
    revokeReason: session.revokeReason,
    effectiveStatus: session.effectiveStatus
  };
}

export function serializeAdministrationAuditEvent(
  event: AuditEvent
): PublicAdministrationAuditEvent {
  return {
    id: event.id,
    eventType: event.eventType,
    actorUserId: event.actorUserId,
    targetUserId: event.targetUserId,
    organisationId: event.organisationId,
    apiKeyId: event.apiKeyId,
    ipAddress: event.ipAddress,
    userAgent: event.userAgent,
    metadata: structuredClone(event.metadata),
    createdAt: event.createdAt.toISOString()
  };
}

export function serializeDelivery(input: {
  sent: boolean;
  expiresAt: Date | null;
  delivery: DeliveryPayload["delivery"];
}): DeliveryPayload {
  return {
    sent: input.sent,
    expiresAt: toIso(input.expiresAt),
    delivery: input.delivery
  };
}

export function serializeOrganisation(organisation: Organisation): PublicOrganisation {
  return {
    id: organisation.id,
    name: organisation.name,
    slug: organisation.slug
  };
}

export function serializeMember(
  member: OrganisationMember<string>
): PublicOrganisationMember {
  return {
    id: member.id,
    organisationId: member.organisationId,
    userId: member.userId,
    role: member.role,
    joinedAt: toIso(member.joinedAt)
  };
}

function toIso(value: Date | null): string | null {
  return value?.toISOString() ?? null;
}
