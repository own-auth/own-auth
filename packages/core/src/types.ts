export type JsonRecord = Record<string, unknown>;

export type ExternalAccountProvider = "apple" | "google";

export type AccountProvider = "password" | "magic_link" | "phone" | ExternalAccountProvider;

export type TokenType =
  | "email_verification"
  | "password_reset"
  | "magic_link"
  | "organisation_invite"
  | "phone_verification";

export type SmsOtpPurpose = "phone_login" | "phone_verification" | "account_recovery";

export type ApiKeyStatus = "active" | "revoked";

export type OrganisationRole = "owner" | "admin" | "member";

export type MemberStatus = "active" | "suspended" | "removed";

export type InvitationStatus = "pending" | "accepted" | "expired" | "revoked";

export type AuditEventType =
  | "user.signed_up"
  | "user.signed_in"
  | "user.signed_out"
  | "user.disabled"
  | "user.re_enabled"
  | "external_provider.linked"
  | "session.created"
  | "session.revoked"
  | "session.revoked_other"
  | "session.revoked_all"
  | "magic_link.requested"
  | "magic_link.used"
  | "email_verification.requested"
  | "email.verified"
  | "sms_otp.sent"
  | "sms_otp.verified"
  | "phone.verified"
  | "password_reset.requested"
  | "password.changed"
  | "api_key.created"
  | "api_key.revoked"
  | "api_key.used"
  | "organisation.created"
  | "organisation.deleted"
  | "organisation.updated"
  | "member.invited"
  | "invite.accepted"
  | "invite.revoked"
  | "member.removed"
  | "member.role_changed";

export interface RequestContext {
  ipAddress?: string;
  userAgent?: string;
}

export interface User {
  id: string;
  email: string | null;
  emailVerifiedAt: Date | null;
  phone: string | null;
  phoneVerifiedAt: Date | null;
  passwordHash: string | null;
  name: string | null;
  imageUrl: string | null;
  disabledAt: Date | null;
  metadata: JsonRecord;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt: Date | null;
}

export interface Account {
  id: string;
  userId: string;
  provider: AccountProvider;
  providerAccountId: string;
  providerEmail: string | null;
  providerPhone: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface Session {
  id: string;
  userId: string;
  tokenHash: string;
  createdAt: Date;
  lastActiveAt: Date;
  expiresAt: Date;
  idleExpiresAt: Date;
  ipAddress: string | null;
  userAgent: string | null;
  revokedAt: Date | null;
  revokeReason: string | null;
}

export interface AuthToken {
  id: string;
  tokenHash: string;
  type: TokenType;
  userId: string | null;
  email: string | null;
  phone: string | null;
  organisationId: string | null;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
}

export interface SmsOtp {
  id: string;
  phone: string;
  userId: string | null;
  codeHash: string;
  purpose: SmsOtpPurpose;
  expiresAt: Date;
  attempts: number;
  maxAttempts: number;
  consumedAt: Date | null;
  createdAt: Date;
  lastSentAt: Date;
}

export interface ApiKey {
  id: string;
  keyPrefix: string;
  keyHash: string;
  name: string;
  userId: string | null;
  organisationId: string | null;
  scopes: string[];
  status: ApiKeyStatus;
  expiresAt: Date | null;
  lastUsedAt: Date | null;
  createdAt: Date;
  revokedAt: Date | null;
  revokedBy: string | null;
  metadata: JsonRecord;
}

export interface ApiKeyDetails {
  id: string;
  keyPrefix: string;
  name: string;
  userId: string | null;
  organisationId: string | null;
  scopes: string[];
  status: ApiKeyStatus;
  expiresAt: Date | null;
  lastUsedAt: Date | null;
  createdAt: Date;
  revokedAt: Date | null;
  revokedBy: string | null;
  metadata: JsonRecord;
}

export interface Organisation {
  id: string;
  name: string;
  slug: string;
  ownerUserId: string;
  metadata: JsonRecord;
  createdAt: Date;
  updatedAt: Date;
  disabledAt: Date | null;
}

export interface OrganisationMember {
  id: string;
  organisationId: string;
  userId: string;
  role: OrganisationRole;
  status: MemberStatus;
  joinedAt: Date | null;
  removedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface OrganisationMemberDetails extends OrganisationMember {
  name: string | null;
  email: string | null;
}

export interface Invitation {
  id: string;
  tokenId: string | null;
  organisationId: string;
  email: string | null;
  phone: string | null;
  role: OrganisationRole;
  invitedByUserId: string;
  status: InvitationStatus;
  expiresAt: Date;
  acceptedAt: Date | null;
  revokedAt: Date | null;
  createdAt: Date;
}

export interface AuditEvent {
  id: string;
  eventType: AuditEventType;
  actorUserId: string | null;
  targetUserId: string | null;
  organisationId: string | null;
  apiKeyId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  metadata: JsonRecord;
  createdAt: Date;
}

export interface CurrentSession {
  session: Session;
  user: User;
}

export interface VerifiedApiKey {
  apiKey: ApiKeyDetails;
  user: User | null;
  organisation: Organisation | null;
}
