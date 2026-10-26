import type {
  Account,
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
import type { MfaMethod, OAuthInteractionMode, OAuthIntent } from "./identity-types.js";
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON
} from "@simplewebauthn/server";
export { day, defaultTokenTtls, hour, minute } from "./auth-engine-options.js";
export type { OwnAuthOptions, PasskeyOptions, TokenTtlConfig } from "./auth-engine-options.js";

export interface SessionResult {
  status: "complete";
  user: User;
  session: Session;
  sessionToken: string;
}

export interface MfaRequiredResult {
  status: "mfa_required";
  challengeToken: string;
  methods: MfaMethod[];
  expiresAt: Date;
}

export type SignInResult = SessionResult | MfaRequiredResult;

export interface DeliveryResult {
  sent: boolean;
  expiresAt: Date | null;
  delivery: {
    status: "sent" | "failed";
    reason?: "quota_exhausted" | "provider_rejected" | "transient_error" | "invalid_request";
  };
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

/** A provider identity whose token or authorization response was already verified. */
export interface VerifiedExternalIdentityInput {
  provider: ExternalAccountProvider;
  providerAccountId: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  imageUrl?: string;
  metadata?: JsonRecord;
  request?: RequestContext;
}

export interface LinkOAuthProviderInput extends VerifiedExternalIdentityInput {
  actorUserId: string;
}

export interface UnlinkOAuthProviderInput {
  actorUserId: string;
  provider: ExternalAccountProvider;
  providerAccountId: string;
  request?: RequestContext;
}

export interface CreateOAuthAuthorizationUrlInput {
  provider: ExternalAccountProvider;
  intent?: OAuthIntent;
  destination?: string;
  mode?: OAuthInteractionMode;
  openerOrigin?: string;
  actorUserId?: string;
  request?: RequestContext;
}

export interface OAuthAuthorizationResult {
  url: string;
  expiresAt: Date;
  state: string;
  /** Store only in the initiating browser's protected cookie or server session. */
  browserBindingToken: string;
}

export interface CompleteOAuthSignInInput {
  provider: ExternalAccountProvider;
  callbackParameters: URLSearchParams;
  /** Read from the initiating browser, never from provider callback parameters. */
  browserBindingToken: string;
  request?: RequestContext;
}

interface OAuthCompletionMetadata {
  destination: string | null;
  interactionMode: OAuthInteractionMode;
  openerOrigin: string | null;
}

export type OAuthCompletionResult =
  | (OAuthCompletionMetadata & SessionResult)
  | (OAuthCompletionMetadata & MfaRequiredResult)
  | (OAuthCompletionMetadata & { status: "linked"; account: Account });

export interface BeginTotpEnrollmentInput {
  sessionToken: string;
  request?: RequestContext;
}

export interface BeginTotpEnrollmentResult {
  factorId: string;
  secret: string;
  uri: string;
}

export interface ConfirmTotpEnrollmentInput {
  sessionToken: string;
  factorId: string;
  code: string;
  request?: RequestContext;
}

export interface ConfirmTotpEnrollmentResult {
  recoveryCodes: string[];
}

export interface DisableTotpInput {
  sessionToken: string;
  code: string;
  request?: RequestContext;
}

export interface CompleteMfaInput {
  challengeToken: string;
  code: string;
  request?: RequestContext;
}

export interface RegenerateRecoveryCodesInput {
  sessionToken: string;
  code: string;
  request?: RequestContext;
}

export interface BeginPasskeyRegistrationInput {
  sessionToken: string;
  request?: RequestContext;
}

export interface BeginPasskeyRegistrationResult {
  options: PublicKeyCredentialCreationOptionsJSON;
}

export interface CompletePasskeyRegistrationInput {
  sessionToken: string;
  response: RegistrationResponseJSON;
  name?: string;
  request?: RequestContext;
}

export interface BeginPasskeyAuthenticationInput {
  userId?: string;
  mfaChallengeToken?: string;
  request?: RequestContext;
}

export interface BeginPasskeyAuthenticationResult {
  options: PublicKeyCredentialRequestOptionsJSON;
}

export interface CompletePasskeyAuthenticationInput {
  response: AuthenticationResponseJSON;
  request?: RequestContext;
}

export interface ListPasskeysInput {
  sessionToken: string;
}

export interface RenamePasskeyInput {
  sessionToken: string;
  passkeyId: string;
  name: string;
  request?: RequestContext;
}

export interface RevokePasskeyInput {
  sessionToken: string;
  passkeyId: string;
  request?: RequestContext;
}

export interface PrepareGoogleOneTapInput {
  request?: RequestContext;
}

export interface PreparedGoogleOneTap {
  nonce: string;
  expiresAt: Date;
}

export interface GoogleOneTapInput {
  credential: string;
  nonce: string;
  request?: RequestContext;
}

export interface GetExternalAccessTokenInput {
  actorUserId: string;
  provider: ExternalAccountProvider;
  providerAccountId?: string;
  request?: RequestContext;
}

export interface ExternalAccessTokenResult {
  accessToken: string;
  scopes: string[];
}

export type RevokeExternalProviderAccessInput = GetExternalAccessTokenInput;

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

export type SmsOtpVerificationResult =
  | SignInResult
  | { status: "verified"; user: User; session: null; sessionToken: null };

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

export interface InviteMemberInput<CustomRole extends string = never> {
  organisationId: string;
  email: string;
  role?: OrganisationRole<CustomRole>;
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

export interface InvitationResult<CustomRole extends string = never> {
  invitation: Invitation<CustomRole>;
  delivery: DeliveryResult["delivery"];
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

export interface AcceptInviteResult<CustomRole extends string = never> {
  organisation: Organisation;
  member: OrganisationMember<CustomRole>;
}

export interface ChangeMemberRoleInput<CustomRole extends string = never> {
  organisationId: string;
  userId: string;
  role: OrganisationRole<CustomRole>;
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
  reason?: "manual" | "security";
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
