import type {
  Account,
  ApiKey,
  AuditEvent,
  AuthToken,
  Invitation,
  Organisation,
  OrganisationMember,
  Session,
  SmsOtp,
  User
} from "./types.js";
import {
  databaseColumnList,
  type EntityColumnMap as ColumnMap
} from "./database-types.js";

export const userColumns: ColumnMap<User> = {
  id: "id",
  email: "email",
  emailVerifiedAt: "email_verified_at",
  phone: "phone",
  phoneVerifiedAt: "phone_verified_at",
  passwordHash: "password_hash",
  name: "name",
  imageUrl: "image_url",
  disabledAt: "disabled_at",
  metadata: "metadata",
  createdAt: "created_at",
  updatedAt: "updated_at",
  lastLoginAt: "last_login_at"
};

export const accountColumns: ColumnMap<Account> = {
  id: "id",
  userId: "user_id",
  provider: "provider",
  providerAccountId: "provider_account_id",
  providerEmail: "provider_email",
  providerPhone: "provider_phone",
  createdAt: "created_at",
  updatedAt: "updated_at"
};

export const sessionColumns: ColumnMap<Session> = {
  id: "id",
  userId: "user_id",
  tokenHash: "token_hash",
  createdAt: "created_at",
  lastActiveAt: "last_active_at",
  expiresAt: "expires_at",
  idleExpiresAt: "idle_expires_at",
  ipAddress: "ip_address",
  userAgent: "user_agent",
  revokedAt: "revoked_at",
  revokeReason: "revoke_reason",
  authenticationMethods: "authentication_methods",
  assuranceLevel: "assurance_level",
  authenticatedAt: "authenticated_at"
};

export const tokenColumns: ColumnMap<AuthToken> = {
  passwordResetVersion: "password_reset_version",
  id: "id",
  tokenHash: "token_hash",
  type: "type",
  userId: "user_id",
  email: "email",
  phone: "phone",
  organisationId: "organisation_id",
  expiresAt: "expires_at",
  usedAt: "used_at",
  createdAt: "created_at"
};

export const smsOtpColumns: ColumnMap<SmsOtp> = {
  id: "id",
  phone: "phone",
  userId: "user_id",
  codeHash: "code_hash",
  purpose: "purpose",
  expiresAt: "expires_at",
  attempts: "attempts",
  maxAttempts: "max_attempts",
  consumedAt: "consumed_at",
  createdAt: "created_at",
  lastSentAt: "last_sent_at"
};

export const apiKeyColumns: ColumnMap<ApiKey> = {
  id: "id",
  keyPrefix: "key_prefix",
  keyHash: "key_hash",
  name: "name",
  userId: "user_id",
  organisationId: "organisation_id",
  scopes: "scopes",
  status: "status",
  expiresAt: "expires_at",
  lastUsedAt: "last_used_at",
  createdAt: "created_at",
  revokedAt: "revoked_at",
  revokedBy: "revoked_by",
  metadata: "metadata"
};

export const organisationColumns: ColumnMap<Organisation> = {
  id: "id",
  name: "name",
  slug: "slug",
  ownerUserId: "owner_user_id",
  metadata: "metadata",
  createdAt: "created_at",
  updatedAt: "updated_at",
  disabledAt: "disabled_at"
};

export const organisationMemberColumns: ColumnMap<OrganisationMember> = {
  id: "id",
  organisationId: "organisation_id",
  userId: "user_id",
  role: "role",
  status: "status",
  joinedAt: "joined_at",
  removedAt: "removed_at",
  createdAt: "created_at",
  updatedAt: "updated_at"
};

export const invitationColumns: ColumnMap<Invitation> = {
  id: "id",
  tokenId: "token_id",
  organisationId: "organisation_id",
  email: "email",
  phone: "phone",
  role: "role",
  invitedByUserId: "invited_by_user_id",
  status: "status",
  expiresAt: "expires_at",
  acceptedAt: "accepted_at",
  revokedAt: "revoked_at",
  createdAt: "created_at"
};

export const auditEventColumns: ColumnMap<AuditEvent> = {
  id: "id",
  eventType: "event_type",
  actorUserId: "actor_user_id",
  targetUserId: "target_user_id",
  organisationId: "organisation_id",
  apiKeyId: "api_key_id",
  ipAddress: "ip_address",
  userAgent: "user_agent",
  metadata: "metadata",
  createdAt: "created_at"
};

export const userReturning = databaseColumnList(userColumns);
export const accountReturning = databaseColumnList(accountColumns);
export const sessionReturning = databaseColumnList(sessionColumns);
export const tokenReturning = databaseColumnList(tokenColumns);
export const smsOtpReturning = databaseColumnList(smsOtpColumns);
export const apiKeyReturning = databaseColumnList(apiKeyColumns);
export const organisationReturning = databaseColumnList(organisationColumns);
export const organisationMemberReturning = databaseColumnList(organisationMemberColumns);
export const invitationReturning = databaseColumnList(invitationColumns);
export const auditEventReturning = databaseColumnList(auditEventColumns);
