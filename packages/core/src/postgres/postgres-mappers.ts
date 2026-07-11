import type {
  Account,
  AccountProvider,
  ApiKey,
  ApiKeyStatus,
  AuditEvent,
  AuditEventType,
  AuthToken,
  Invitation,
  InvitationStatus,
  MemberStatus,
  Organisation,
  OrganisationMember,
  OrganisationRole,
  Session,
  SmsOtp,
  SmsOtpPurpose,
  TokenType,
  User
} from "../types.js";
import type { Row } from "./postgres-types.js";
import {
  dateValue,
  jsonRecord,
  nullableDate,
  nullableString,
  numberValue,
  stringArray,
  stringValue
} from "./postgres-row.js";

export function mapUser(row: Row): User {
  return {
    id: stringValue(row.id),
    email: nullableString(row.email),
    emailVerifiedAt: nullableDate(row.email_verified_at),
    phone: nullableString(row.phone),
    phoneVerifiedAt: nullableDate(row.phone_verified_at),
    passwordHash: nullableString(row.password_hash),
    name: nullableString(row.name),
    imageUrl: nullableString(row.image_url),
    disabledAt: nullableDate(row.disabled_at),
    metadata: jsonRecord(row.metadata),
    createdAt: dateValue(row.created_at),
    updatedAt: dateValue(row.updated_at),
    lastLoginAt: nullableDate(row.last_login_at)
  };
}

export function mapAccount(row: Row): Account {
  return {
    id: stringValue(row.id),
    userId: stringValue(row.user_id),
    provider: stringValue(row.provider) as AccountProvider,
    providerAccountId: stringValue(row.provider_account_id),
    providerEmail: nullableString(row.provider_email),
    providerPhone: nullableString(row.provider_phone),
    createdAt: dateValue(row.created_at),
    updatedAt: dateValue(row.updated_at)
  };
}

export function mapSession(row: Row): Session {
  return {
    id: stringValue(row.id),
    userId: stringValue(row.user_id),
    tokenHash: stringValue(row.token_hash),
    createdAt: dateValue(row.created_at),
    lastActiveAt: dateValue(row.last_active_at),
    expiresAt: dateValue(row.expires_at),
    idleExpiresAt: dateValue(row.idle_expires_at),
    ipAddress: nullableString(row.ip_address),
    userAgent: nullableString(row.user_agent),
    revokedAt: nullableDate(row.revoked_at),
    revokeReason: nullableString(row.revoke_reason)
  };
}

export function mapToken(row: Row): AuthToken {
  return {
    id: stringValue(row.id),
    tokenHash: stringValue(row.token_hash),
    type: stringValue(row.type) as TokenType,
    userId: nullableString(row.user_id),
    email: nullableString(row.email),
    phone: nullableString(row.phone),
    organisationId: nullableString(row.organisation_id),
    expiresAt: dateValue(row.expires_at),
    usedAt: nullableDate(row.used_at),
    createdAt: dateValue(row.created_at)
  };
}

export function mapSmsOtp(row: Row): SmsOtp {
  return {
    id: stringValue(row.id),
    phone: stringValue(row.phone),
    userId: nullableString(row.user_id),
    codeHash: stringValue(row.code_hash),
    purpose: stringValue(row.purpose) as SmsOtpPurpose,
    expiresAt: dateValue(row.expires_at),
    attempts: numberValue(row.attempts),
    maxAttempts: numberValue(row.max_attempts),
    consumedAt: nullableDate(row.consumed_at),
    createdAt: dateValue(row.created_at),
    lastSentAt: dateValue(row.last_sent_at)
  };
}

export function mapApiKey(row: Row): ApiKey {
  return {
    id: stringValue(row.id),
    keyPrefix: stringValue(row.key_prefix),
    keyHash: stringValue(row.key_hash),
    name: stringValue(row.name),
    userId: nullableString(row.user_id),
    organisationId: nullableString(row.organisation_id),
    scopes: stringArray(row.scopes),
    status: stringValue(row.status) as ApiKeyStatus,
    expiresAt: nullableDate(row.expires_at),
    lastUsedAt: nullableDate(row.last_used_at),
    createdAt: dateValue(row.created_at),
    revokedAt: nullableDate(row.revoked_at),
    revokedBy: nullableString(row.revoked_by),
    metadata: jsonRecord(row.metadata)
  };
}

export function mapOrganisation(row: Row): Organisation {
  return {
    id: stringValue(row.id),
    name: stringValue(row.name),
    slug: stringValue(row.slug),
    ownerUserId: stringValue(row.owner_user_id),
    metadata: jsonRecord(row.metadata),
    createdAt: dateValue(row.created_at),
    updatedAt: dateValue(row.updated_at),
    disabledAt: nullableDate(row.disabled_at)
  };
}

export function mapOrganisationMember(row: Row): OrganisationMember {
  return {
    id: stringValue(row.id),
    organisationId: stringValue(row.organisation_id),
    userId: stringValue(row.user_id),
    role: stringValue(row.role) as OrganisationRole,
    status: stringValue(row.status) as MemberStatus,
    joinedAt: nullableDate(row.joined_at),
    removedAt: nullableDate(row.removed_at),
    createdAt: dateValue(row.created_at),
    updatedAt: dateValue(row.updated_at)
  };
}

export function mapInvitation(row: Row): Invitation {
  return {
    id: stringValue(row.id),
    tokenId: nullableString(row.token_id),
    organisationId: stringValue(row.organisation_id),
    email: nullableString(row.email),
    phone: nullableString(row.phone),
    role: stringValue(row.role) as OrganisationRole,
    invitedByUserId: stringValue(row.invited_by_user_id),
    status: stringValue(row.status) as InvitationStatus,
    expiresAt: dateValue(row.expires_at),
    acceptedAt: nullableDate(row.accepted_at),
    revokedAt: nullableDate(row.revoked_at),
    createdAt: dateValue(row.created_at)
  };
}

export function mapAuditEvent(row: Row): AuditEvent {
  return {
    id: stringValue(row.id),
    eventType: stringValue(row.event_type) as AuditEventType,
    actorUserId: nullableString(row.actor_user_id),
    targetUserId: nullableString(row.target_user_id),
    organisationId: nullableString(row.organisation_id),
    apiKeyId: nullableString(row.api_key_id),
    ipAddress: nullableString(row.ip_address),
    userAgent: nullableString(row.user_agent),
    metadata: jsonRecord(row.metadata),
    createdAt: dateValue(row.created_at)
  };
}
