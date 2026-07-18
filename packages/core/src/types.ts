export type JsonRecord = Record<string, unknown>;

export type ExternalAccountProvider = "apple" | "github" | "google";

export type SamlAccountProvider = `saml.${string}`;

export type AccountProvider =
  | "password"
  | "magic_link"
  | "phone"
  | ExternalAccountProvider
  | SamlAccountProvider;

export type SessionAssuranceLevel = "aal1" | "aal2";

export type TokenType =
  | "email_verification"
  | "password_reset"
  | "magic_link"
  | "organisation_invite"
  | "phone_verification";

export type SmsOtpPurpose = "phone_login" | "phone_verification" | "account_recovery";

export type ApiKeyStatus = "active" | "revoked";

export const builtInOrganisationRoles = ["owner", "admin", "member"] as const;

export type BuiltInOrganisationRole = (typeof builtInOrganisationRoles)[number];

export type OrganisationRole<CustomRole extends string = never> =
  | BuiltInOrganisationRole
  | CustomRole;

export type MemberStatus = "active" | "suspended" | "removed";

export type InvitationStatus = "pending" | "accepted" | "expired" | "revoked";

export const coreAuditEventTypes = [
  "user.signed_up",
  "user.signed_in",
  "user.signed_out",
  "user.disabled",
  "user.re_enabled",
  "admin.users_listed",
  "admin.user_viewed",
  "admin.sessions_listed",
  "admin.sessions_revoked",
  "admin.audit_events_listed",
  "external_provider.linked",
  "external_provider.unlinked",
  "oauth.started",
  "oauth.signed_in",
  "oauth.failed",
  "oauth.credential_stored",
  "oauth.credential_refreshed",
  "oauth.credential_revoked",
  "authorization_server.client_created",
  "authorization_server.client_updated",
  "authorization_server.client_secret_rotated",
  "authorization_server.client_revoked",
  "authorization_server.protected_resource_created",
  "authorization_server.protected_resource_updated",
  "authorization_server.protected_resource_secret_rotated",
  "authorization_server.protected_resource_revoked",
  "authorization_server.authorization_started",
  "authorization_server.authorization_approved",
  "authorization_server.authorization_denied",
  "authorization_server.code_exchanged",
  "authorization_server.token_refreshed",
  "authorization_server.token_revoked",
  "authorization_server.refresh_reuse_detected",
  "authorization_server.grant_revoked",
  "authorization_server.device_authorization_started",
  "authorization_server.device_authorization_approved",
  "authorization_server.device_authorization_denied",
  "authorization_server.device_token_exchanged",
  "mfa.totp_enrollment_started",
  "mfa.totp_enabled",
  "mfa.totp_disabled",
  "mfa.challenge_succeeded",
  "mfa.challenge_failed",
  "mfa.recovery_code_used",
  "mfa.recovery_codes_regenerated",
  "session.elevated",
  "passkey.registered",
  "passkey.authenticated",
  "passkey.renamed",
  "passkey.revoked",
  "saml.connection_created",
  "saml.connection_updated",
  "saml.connection_disabled",
  "saml.connection_enabled",
  "saml.started",
  "saml.signed_in",
  "saml.failed",
  "saml.identity_linked",
  "saml.identity_unlinked",
  "saml.member_provisioned",
  "scim.connection_created",
  "scim.connection_updated",
  "scim.connection_disabled",
  "scim.connection_enabled",
  "scim.token_created",
  "scim.token_revoked",
  "scim.user_created",
  "scim.user_linked",
  "scim.user_updated",
  "scim.user_suspended",
  "scim.user_reactivated",
  "scim.user_deleted",
  "scim.user_restored",
  "session.created",
  "session.revoked",
  "session.revoked_other",
  "session.revoked_all",
  "magic_link.requested",
  "magic_link.used",
  "email_verification.requested",
  "email.verified",
  "sms_otp.sent",
  "sms_otp.verified",
  "phone.verified",
  "password_reset.requested",
  "password.changed",
  "api_key.created",
  "api_key.revoked",
  "api_key.used",
  "organisation.created",
  "organisation.deleted",
  "organisation.updated",
  "member.invited",
  "invite.accepted",
  "invite.revoked",
  "member.removed",
  "member.role_changed"
] as const;

export type CoreAuditEventType = (typeof coreAuditEventTypes)[number];
export type AuditEventType = CoreAuditEventType | `plugin.${string}`;

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
  authenticationMethods: string[];
  assuranceLevel: SessionAssuranceLevel;
  authenticatedAt: Date;
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

export interface OrganisationMember<CustomRole extends string = never> {
  id: string;
  organisationId: string;
  userId: string;
  role: OrganisationRole<CustomRole>;
  status: MemberStatus;
  joinedAt: Date | null;
  removedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface OrganisationMemberDetails<CustomRole extends string = never>
  extends OrganisationMember<CustomRole> {
  name: string | null;
  email: string | null;
}

export interface Invitation<CustomRole extends string = never> {
  id: string;
  tokenId: string | null;
  organisationId: string;
  email: string | null;
  phone: string | null;
  role: OrganisationRole<CustomRole>;
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
