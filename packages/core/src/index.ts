export { OwnAuth } from "./auth-engine.js";
export { createOwnAuth } from "./create-own-auth.js";
export {
  corePermissions,
  defineOwnAuthAuthorization,
  permissionsForRole,
  roleHasPermission
} from "./authorization.js";
export type {
  CorePermission,
  OwnAuthAuthorizationDefinition,
  Permission
} from "./authorization.js";
export { coreAuditEventTypes } from "./types.js";
export type {
  AcceptInviteInput,
  AcceptInviteResult,
  BeginTotpEnrollmentInput,
  BeginTotpEnrollmentResult,
  BeginPasskeyAuthenticationInput,
  BeginPasskeyAuthenticationResult,
  BeginPasskeyRegistrationInput,
  BeginPasskeyRegistrationResult,
  ChangeMemberRoleInput,
  CleanupAuditLogsInput,
  CreateApiKeyInput,
  ChangePasswordInput,
  CompleteOAuthSignInInput,
  CompleteMfaInput,
  CompletePasskeyAuthenticationInput,
  CompletePasskeyRegistrationInput,
  ConfirmTotpEnrollmentInput,
  ConfirmTotpEnrollmentResult,
  CreatedApiKey,
  CreateOrganisationInput,
  CreateUserInput,
  CreateOAuthAuthorizationUrlInput,
  DeleteOrganisationInput,
  DisableTotpInput,
  DeliveryResult,
  ExternalAccessTokenResult,
  GetOrganisationInput,
  GetExternalAccessTokenInput,
  GetMemberInput,
  GoogleOneTapInput,
  InvitationResult,
  InviteMemberInput,
  ListApiKeysInput,
  ListPasskeysInput,
  ListAuditEventsInput,
  ListInvitationsInput,
  ListMembersInput,
  ListOrganisationsInput,
  ListSessionsInput,
  OwnAuthOptions,
  OAuthAuthorizationResult,
  OAuthCompletionResult,
  PrepareGoogleOneTapInput,
  PreparedGoogleOneTap,
  RegenerateRecoveryCodesInput,
  RenamePasskeyInput,
  RequestEmailVerificationInput,
  RequestSmsOtpInput,
  RequestTokenInput,
  ResetPasswordInput,
  RevokeAllSessionsInput,
  RevokeExternalProviderAccessInput,
  RevokePasskeyInput,
  RevokeApiKeyInput,
  RevokeInvitationInput,
  RevokeSessionInput,
  RemoveMemberInput,
  SessionResult,
  SignInResult,
  MfaRequiredResult,
  SignInEmailPasswordInput,
  VerifiedExternalIdentityInput,
  LinkOAuthProviderInput,
  UnlinkOAuthProviderInput,
  SignUpEmailPasswordInput,
  SmsOtpVerificationResult,
  UpdateOrganisationInput,
  UserStatusInput,
  VerifySmsOtpInput,
  VerifyTokenInput
} from "./auth-engine-types.js";
export { AuthError, toAuthError } from "./errors.js";
export type { AuthErrorCode } from "./errors.js";
export { EncryptionKeyRing, createEncryptionKeyRing } from "./encryption.js";
export type {
  DecryptedValue,
  EncryptedValue,
  EncryptionKeyInput,
  EncryptionKeyRingOptions,
  EncryptionPurpose
} from "./encryption.js";
export type {
  MfaChallenge,
  MfaFactorStatus,
  MfaMethod,
  OAuthCredential,
  OAuthFlowKind,
  OAuthIntent,
  OAuthInteractionMode,
  OAuthTransaction,
  PasskeyCredential,
  RecoveryCode,
  TotpFactor,
  WebAuthnChallenge,
  WebAuthnChallengePurpose
} from "./identity-types.js";
export type {
  AppleOAuthOptions,
  GitHubOAuthOptions,
  GoogleOAuthOptions,
  OAuthAccountLinking,
  OAuthAuthorizationRequest,
  OAuthExchangeResult,
  OAuthOptions,
  OAuthProviderAdapter,
  OAuthRefreshResult,
  VerifiedProviderIdentity
} from "./oauth-types.js";
export {
  createOwnAuthPluginClientManifest,
  defineOwnAuthConfig,
  defineOwnAuthPlugin,
  OwnAuthPluginError
} from "./plugin-definition.js";
export {
  createOwnAuthPluginClientConfiguration,
  createOwnAuthPluginContractFingerprint
} from "./plugin-contract.js";
export type {
  OwnAuthPluginClientConfiguration
} from "./plugin-contract.js";
export {
  createConfiguredOwnAuthOpenApiDocument
} from "./plugin-openapi.js";
export type {
  OwnAuthConfiguredOpenApiDocument,
  OwnAuthConfiguredOpenApiOptions
} from "./plugin-openapi.js";
export type {
  CallOwnAuthPluginMethodOptions,
  OwnAuthConfig,
  OwnAuthPluginAfterHook,
  OwnAuthPluginAfterHookContext,
  OwnAuthPluginBeforeHook,
  OwnAuthPluginClientManifest,
  OwnAuthPluginClientMethod,
  OwnAuthPluginContext,
  OwnAuthPluginDefinition,
  OwnAuthPluginEndpoint,
  OwnAuthPluginHookContext,
  OwnAuthPluginMigration,
  OwnAuthPluginRateLimit,
  OwnAuthPluginRuntimeOptions,
  OwnAuthPluginServerMethod,
  PluginSessionRequirement
} from "./plugin-types.js";
export { OWN_AUTH_VERSION } from "./version.js";
export { InMemoryAuthStorage } from "./memory-storage.js";
export type { AuditEventFilter, AuthStorage } from "./storage.js";
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
export type {
  Account,
  AccountProvider,
  ApiKey,
  ApiKeyDetails,
  ApiKeyStatus,
  BuiltInOrganisationRole,
  AuditEvent,
  AuditEventType,
  CoreAuditEventType,
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
  SessionAssuranceLevel,
  SmsOtp,
  SmsOtpPurpose,
  TokenType,
  User,
  VerifiedApiKey
} from "./types.js";
export type {
  CleanupWebhookDeliveriesInput,
  ListWebhookDeliveriesInput,
  ProcessWebhookDeliveriesInput,
  ProcessWebhookDeliveriesResult,
  RetryWebhookDeliveryInput,
  StoredWebhookEvent,
  WebhookAttempt,
  WebhookAttemptErrorCode,
  WebhookAttemptOutcome,
  WebhookDelivery,
  WebhookDeliveryDetails,
  WebhookDeliveryStatus,
  WebhookEndpointOptions,
  WebhookEvent,
  WebhookEventData,
  WebhookEventType,
  WebhookOptions
} from "./webhook-types.js";
export type {
  ClaimWebhookDeliveriesInput,
  ClaimedWebhookDelivery,
  ListedWebhookDelivery,
  SettleWebhookDeliveryInput,
  WebhookCapableStorage,
  WebhookDeliverySeed,
  WebhookStorage
} from "./webhook-storage.js";
export {
  clearMfaChallengeCookie,
  clearSessionCookie,
  createMfaChallengeCookie,
  createOwnAuthHandler,
  createOwnAuthOpenApiDocument,
  createSessionCookie,
  defaultMfaCookieName,
  defaultSessionCookieName,
  getOwnAuthEndpoint,
  ownAuthEndpointContract,
  readMfaChallengeToken,
  readSessionToken
} from "./http/index.js";
export type {
  AuthSessionPayload,
  DeliveryPayload,
  MfaRequiredPayload,
  OwnAuthEndpointDefinition,
  OwnAuthEndpointId,
  OwnAuthEndpointInputMap,
  OwnAuthEndpointOutputMap,
  OwnAuthErrorPayload,
  OwnAuthHandler,
  OwnAuthHandlerOptions,
  OwnAuthHttpErrorCode,
  OwnAuthOpenApiDocument,
  OwnAuthOpenApiOptions,
  OwnAuthMfaCookieOptions,
  OwnAuthSessionCookieOptions,
  PublicAuthSession,
  PublicAuthUser,
  PublicOrganisation,
  PublicOrganisationMember,
  PublicPasskey,
  SignInPayload,
  SameSitePolicy
} from "./http/index.js";
