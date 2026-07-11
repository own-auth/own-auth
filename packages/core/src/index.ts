export { OwnAuth, createOwnAuth } from "./auth-engine.js";
export type {
  AcceptInviteInput,
  AcceptInviteResult,
  ChangeMemberRoleInput,
  CleanupAuditLogsInput,
  CreateApiKeyInput,
  ChangePasswordInput,
  CreatedApiKey,
  CreateOrganisationInput,
  CreateUserInput,
  DeleteOrganisationInput,
  DeliveryResult,
  GetOrganisationInput,
  GetMemberInput,
  InvitationResult,
  InviteMemberInput,
  ListApiKeysInput,
  ListAuditEventsInput,
  ListInvitationsInput,
  ListMembersInput,
  ListOrganisationsInput,
  ListSessionsInput,
  OwnAuthOptions,
  RequestEmailVerificationInput,
  RequestSmsOtpInput,
  RequestTokenInput,
  ResetPasswordInput,
  RevokeAllSessionsInput,
  RevokeApiKeyInput,
  RevokeInvitationInput,
  RevokeSessionInput,
  RemoveMemberInput,
  SessionResult,
  SignInEmailPasswordInput,
  SignInWithExternalProviderInput,
  SignUpEmailPasswordInput,
  SmsOtpVerificationResult,
  UpdateOrganisationInput,
  UserStatusInput,
  VerifySmsOtpInput,
  VerifyTokenInput
} from "./auth-engine-types.js";
export { AuthError, toAuthError } from "./errors.js";
export type { AuthErrorCode } from "./errors.js";
export { InMemoryAuthStorage } from "./memory-storage.js";
export type { AuthStorage } from "./storage.js";
export {
  InMemoryRateLimitStore,
  enforceRateLimit
} from "./rate-limit.js";
export type { RateLimitResult, RateLimitStore } from "./rate-limit.js";
export {
  ConsoleEmailProvider,
  ConsoleSmsProvider,
  MemoryEmailProvider,
  MemorySmsProvider,
  OwnAuthManagedEmailProvider
} from "./providers.js";
export type {
  EmailMessage,
  EmailProvider,
  OwnAuthManagedEmailProviderOptions,
  SmsMessage,
  SmsProvider
} from "./providers.js";
export {
  permissionsForRole,
  roleHasPermission
} from "./permissions.js";
export type { Permission } from "./permissions.js";
export type {
  Account,
  AccountProvider,
  ApiKey,
  ApiKeyDetails,
  ApiKeyStatus,
  AuditEvent,
  AuditEventType,
  AuthToken,
  CurrentSession,
  ExternalAccountProvider,
  Invitation,
  InvitationStatus,
  JsonRecord,
  MemberStatus,
  Organisation,
  OrganisationMember,
  OrganisationMemberDetails,
  OrganisationRole,
  RequestContext,
  Session,
  SmsOtp,
  SmsOtpPurpose,
  TokenType,
  User,
  VerifiedApiKey
} from "./types.js";
