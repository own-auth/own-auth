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
} from "../types.js";
import type { ColumnMap } from "./postgres-types.js";

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
  revokeReason: "revoke_reason"
};

export const tokenColumns: ColumnMap<AuthToken> = {
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

export const userReturning = [
  "id",
  "email",
  "email_verified_at",
  "phone",
  "phone_verified_at",
  "password_hash",
  "name",
  "image_url",
  "disabled_at",
  "metadata",
  "created_at",
  "updated_at",
  "last_login_at"
].join(", ");

export const accountReturning = [
  "id",
  "user_id",
  "provider",
  "provider_account_id",
  "provider_email",
  "provider_phone",
  "created_at",
  "updated_at"
].join(", ");

export const sessionReturning = [
  "id",
  "user_id",
  "token_hash",
  "created_at",
  "last_active_at",
  "expires_at",
  "idle_expires_at",
  "ip_address",
  "user_agent",
  "revoked_at",
  "revoke_reason"
].join(", ");

export const tokenReturning = [
  "id",
  "token_hash",
  "type",
  "user_id",
  "email",
  "phone",
  "organisation_id",
  "expires_at",
  "used_at",
  "created_at"
].join(", ");

export const smsOtpReturning = [
  "id",
  "phone",
  "user_id",
  "code_hash",
  "purpose",
  "expires_at",
  "attempts",
  "max_attempts",
  "consumed_at",
  "created_at",
  "last_sent_at"
].join(", ");

export const apiKeyReturning = [
  "id",
  "key_prefix",
  "key_hash",
  "name",
  "user_id",
  "organisation_id",
  "scopes",
  "status",
  "expires_at",
  "last_used_at",
  "created_at",
  "revoked_at",
  "revoked_by",
  "metadata"
].join(", ");

export const organisationReturning = [
  "id",
  "name",
  "slug",
  "owner_user_id",
  "metadata",
  "created_at",
  "updated_at",
  "disabled_at"
].join(", ");

export const organisationMemberReturning = [
  "id",
  "organisation_id",
  "user_id",
  "role",
  "status",
  "joined_at",
  "removed_at",
  "created_at",
  "updated_at"
].join(", ");

export const invitationReturning = [
  "id",
  "token_id",
  "organisation_id",
  "email",
  "phone",
  "role",
  "invited_by_user_id",
  "status",
  "expires_at",
  "accepted_at",
  "revoked_at",
  "created_at"
].join(", ");

export const auditEventReturning = [
  "id",
  "event_type",
  "actor_user_id",
  "target_user_id",
  "organisation_id",
  "api_key_id",
  "ip_address",
  "user_agent",
  "metadata",
  "created_at"
].join(", ");
