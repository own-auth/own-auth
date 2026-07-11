import type {
  ApiKeyDetails,
  Invitation,
  JsonRecord,
  Organisation,
  OrganisationMember,
  OrganisationRole,
  ExternalAccountProvider,
  RequestContext,
  Session,
  SmsOtpPurpose,
  User
} from "./types.js";
export { day, defaultTokenTtls, hour, minute } from "./auth-engine-options.js";
export type { OwnAuthOptions, TokenTtlConfig } from "./auth-engine-options.js";

export interface SessionResult {
  user: User;
  session: Session;
  sessionToken: string;
}

export interface DeliveryResult {
  sent: boolean;
  expiresAt: Date | null;
  token?: string;
  code?: string;
  url?: string;
}

export interface CreateUserInput {
  email?: string;
  phone?: string;
  password?: string;
  name?: string;
  imageUrl?: string;
  metadata?: JsonRecord;
}

export interface SignUpEmailPasswordInput {
  email: string;
  password: string;
  name?: string;
  metadata?: JsonRecord;
  request?: RequestContext;
}

export interface SignInEmailPasswordInput {
  email: string;
  password: string;
  request?: RequestContext;
}

export interface ChangePasswordInput {
  sessionToken: string;
  currentPassword: string;
  newPassword: string;
  request?: RequestContext;
}

export interface RevokeSessionInput {
  sessionToken: string;
  sessionId: string;
  request?: RequestContext;
}

export interface SignInWithExternalProviderInput {
  provider: ExternalAccountProvider;
  providerAccountId: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  imageUrl?: string;
  metadata?: JsonRecord;
  request?: RequestContext;
}

export interface RequestTokenInput {
  email: string;
  redirectUrl?: string;
  request?: RequestContext;
}

export interface RequestEmailVerificationInput {
  email: string;
  request?: RequestContext;
}

export interface VerifyTokenInput {
  token: string;
  request?: RequestContext;
}

export interface ResetPasswordInput {
  token: string;
  newPassword: string;
  request?: RequestContext;
}

export interface RequestSmsOtpInput {
  phone: string;
  purpose?: SmsOtpPurpose;
  userId?: string;
  request?: RequestContext;
}

export interface VerifySmsOtpInput {
  phone: string;
  code: string;
  purpose?: SmsOtpPurpose;
  request?: RequestContext;
}

export interface SmsOtpVerificationResult {
  user: User;
  session: Session | null;
  sessionToken: string | null;
}

export interface CreateApiKeyInput {
  name: string;
  organisationId?: string;
  scopes?: string[];
  expiresAt?: Date;
  metadata?: JsonRecord;
  actorUserId: string;
  request?: RequestContext;
}

export interface CreatedApiKey {
  apiKey: ApiKeyDetails;
  rawKey: string;
}

export interface CreateOrganisationInput {
  name: string;
  slug?: string;
  ownerUserId: string;
  metadata?: JsonRecord;
  request?: RequestContext;
}

export interface GetOrganisationInput {
  organisationId: string;
  actorUserId: string;
}

export interface DeleteOrganisationInput {
  organisationId: string;
  actorUserId: string;
  request?: RequestContext;
}

export interface InviteMemberInput {
  organisationId: string;
  email: string;
  role?: OrganisationRole;
  invitedByUserId: string;
  request?: RequestContext;
}

export interface ListMembersInput {
  organisationId: string;
  actorUserId: string;
}

export interface GetMemberInput {
  organisationId: string;
  userId: string;
  actorUserId: string;
}

export interface InvitationResult {
  invitation: Invitation;
  token?: string;
  url?: string;
}

export interface UpdateOrganisationInput {
  actorUserId: string;
  name?: string;
  slug?: string;
  metadata?: JsonRecord;
  request?: RequestContext;
}

export interface AcceptInviteInput {
  token: string;
  userId: string;
  request?: RequestContext;
}

export interface AcceptInviteResult {
  organisation: Organisation;
  member: OrganisationMember;
}

export interface ChangeMemberRoleInput {
  organisationId: string;
  userId: string;
  role: OrganisationRole;
  actorUserId: string;
  request?: RequestContext;
}

export interface RemoveMemberInput {
  organisationId: string;
  userId: string;
  actorUserId: string;
  request?: RequestContext;
}

export interface UserStatusInput {
  userId: string;
  actorUserId: string;
  request?: RequestContext;
}

export interface RevokeInvitationInput {
  invitationId: string;
  actorUserId: string;
  request?: RequestContext;
}

export interface ListInvitationsInput {
  organisationId: string;
  actorUserId: string;
}

export interface ListApiKeysInput {
  actorUserId: string;
  organisationId?: string;
}

export interface RevokeApiKeyInput {
  keyPrefix: string;
  actorUserId: string;
  request?: RequestContext;
}

export interface ListAuditEventsInput {
  actorUserId: string;
  userId?: string;
  organisationId?: string;
  apiKeyId?: string;
}

export interface CleanupAuditLogsInput {
  olderThan: Date;
}

export interface ListSessionsInput {
  actorUserId: string;
}

export interface RevokeAllSessionsInput {
  actorUserId: string;
  request?: RequestContext;
}

export interface ListOrganisationsInput {
  actorUserId: string;
}
