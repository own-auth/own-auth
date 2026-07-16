import type { OwnAuthAuthorizationDefinition, Permission } from "./authorization.js";
import type { AuthStorage } from "./storage.js";
import type {
  ApiKeyDetails,
  AuditEvent,
  CurrentSession,
  Invitation,
  Organisation,
  OrganisationMember,
  OrganisationMemberDetails,
  RequestContext,
  Session,
  User,
  VerifiedApiKey
} from "./types.js";
import type { RateLimitStore } from "./rate-limit.js";
import { createAuthEngineContext, requestContextFrom, type AuthEngineContext } from "./auth-engine-internals.js";
import * as apiKeys from "./auth-engine-api-keys.js";
import * as auditEvents from "./auth-engine-audit.js";
import * as email from "./auth-engine-email.js";
import * as external from "./auth-engine-external.js";
import * as invitations from "./auth-engine-invitations.js";
import * as members from "./auth-engine-members.js";
import * as mfa from "./auth-engine-mfa.js";
import * as organisationAccess from "./auth-engine-organisation-access.js";
import * as organisations from "./auth-engine-organisations.js";
import * as oauth from "./auth-engine-oauth.js";
import * as oauthCredentials from "./auth-engine-oauth-credentials.js";
import * as passkeys from "./auth-engine-passkeys.js";
import * as sessions from "./auth-engine-sessions.js";
import * as sms from "./auth-engine-sms.js";
import * as users from "./auth-engine-users.js";
import * as webhookOperations from "./auth-engine-webhooks.js";
import { OwnAuthAdministration } from "./auth-engine-administration.js";
import { OwnAuthAuthorizationServer } from "./auth-engine-authorization-server.js";
import { OwnAuthPluginRuntime, type RegisteredPluginEndpoint } from "./plugin-runtime.js";
import type { CallOwnAuthPluginMethodOptions, OwnAuthPluginDefinition } from "./plugin-types.js";
import type {
  AcceptInviteInput,
  AcceptInviteResult,
  BeginTotpEnrollmentInput,
  BeginTotpEnrollmentResult,
  BeginPasskeyAuthenticationInput,
  BeginPasskeyAuthenticationResult,
  BeginPasskeyRegistrationInput,
  BeginPasskeyRegistrationResult,
  ChangeMemberRoleInput,
  CompleteOAuthSignInInput,
  CompleteMfaInput,
  CompletePasskeyAuthenticationInput,
  CompletePasskeyRegistrationInput,
  ConfirmTotpEnrollmentInput,
  ConfirmTotpEnrollmentResult,
  ChangePasswordInput,
  CleanupAuditLogsInput,
  CreateApiKeyInput,
  CreatedApiKey,
  CreateOrganisationInput,
  CreateOAuthAuthorizationUrlInput,
  CreateUserInput,
  DeleteOrganisationInput,
  DisableTotpInput,
  DeliveryResult,
  ExternalAccessTokenResult,
  GetOrganisationInput,
  GetExternalAccessTokenInput,
  GetMemberInput,
  InvitationResult,
  GoogleOneTapInput,
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
  RemoveMemberInput,
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
  SessionResult,
  SignInResult,
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
import { createAuthClosedError } from "./errors.js";
import { traceAuthOperation, tracePluginOperation } from "./telemetry.js";
import type {
  CleanupWebhookDeliveriesInput,
  ListWebhookDeliveriesInput,
  ProcessWebhookDeliveriesInput,
  ProcessWebhookDeliveriesResult,
  RetryWebhookDeliveryInput,
  WebhookDeliveryDetails
} from "./webhook-types.js";
export type { OwnAuthOptions } from "./auth-engine-types.js";
export class OwnAuth<CustomRole extends string = never, CustomPermission extends string = never> {
  readonly storage: AuthStorage;
  readonly rateLimitStore: RateLimitStore;
  readonly admin: OwnAuthAdministration;
  readonly authorizationServer: OwnAuthAuthorizationServer;
  private readonly ctx: AuthEngineContext;
  private readonly pluginRuntime: OwnAuthPluginRuntime;
  private closed = false;
  private closePromise: Promise<void> | null = null;
  constructor(options: OwnAuthOptions<OwnAuthAuthorizationDefinition<CustomPermission, CustomRole>> = {}) {
    this.ctx = createAuthEngineContext(options);
    this.storage = this.ctx.storage;
    this.rateLimitStore = this.ctx.rateLimitStore;
    this.pluginRuntime = new OwnAuthPluginRuntime(
      options.plugins ?? [],
      this.storage,
      this.rateLimitStore,
      () => this as unknown as OwnAuth<string, string>,
      options.pluginRuntime
    );
    this.admin = new OwnAuthAdministration(this.ctx, (operation, input, work) =>
      this.executeCore(operation, input, work));
    this.authorizationServer = new OwnAuthAuthorizationServer(this.ctx, (operation, input, work) =>
      this.executeCore(operation, input, work));
  }

  get plugins(): readonly OwnAuthPluginDefinition[] { return this.pluginRuntime.definitions; }
  get pluginContractFingerprint(): string { return this.pluginRuntime.fingerprint; }
  /** @internal Used by createOwnAuthHandler. */
  isAdministrationConfigured(): boolean { return this.ctx.administration !== null; }
  /** @internal Used by createOwnAuthHandler. */
  findPluginEndpoint(path: string, method: string): RegisteredPluginEndpoint | null {
    return this.pluginRuntime.findEndpoint(path, method);
  }
  /** @internal Used by createOwnAuthHandler. */
  getPluginEndpointMethods(path: string): string[] {
    return this.pluginRuntime.methodsForPath(path);
  }
  /** @internal Used by createOwnAuthHandler. */
  executePluginEndpoint(
    endpoint: RegisteredPluginEndpoint,
    input: unknown,
    sessionToken: string | null,
    request: RequestContext
  ): Promise<unknown> {
    return this.executePlugin(
      endpoint.plugin.id,
      endpoint.endpoint.id,
      "endpoint",
      () => this.pluginRuntime.executeEndpoint(endpoint, input, sessionToken, request)
    );
  }
  callPluginMethod(
    pluginId: string,
    method: string,
    input: unknown,
    options?: CallOwnAuthPluginMethodOptions
  ): Promise<unknown> {
    return this.executePlugin(
      pluginId,
      method,
      "method",
      () => this.pluginRuntime.callServerMethod(pluginId, method, input, options)
    );
  }
  private executePlugin<Result>(
    pluginId: string,
    operation: string,
    kind: "endpoint" | "method",
    work: () => Promise<Result>
  ): Promise<Result> {
    return this.runWhileOpen(() =>
      tracePluginOperation({ pluginId, operation, kind }, work)
    );
  }
  private executeCore<Result>(
    operation: string,
    input: unknown,
    work: () => Promise<Result>
  ): Promise<Result> {
    return this.runWhileOpen(() =>
      traceAuthOperation(
        operation,
        () => this.pluginRuntime.runCoreOperation(
          operation,
          input,
          requestContextFrom(input),
          work
        )
      )
    );
  }
  private runWhileOpen<Result>(work: () => Promise<Result>): Promise<Result> {
    if (this.closed) {
      return Promise.reject(createAuthClosedError());
    }
    return work();
  }

  createUser(input: CreateUserInput): Promise<User> {
    return this.executeCore("createUser", input, () => users.createUser(this.ctx, input));
  }
  signUpEmailPassword(input: SignUpEmailPasswordInput): Promise<SessionResult> {
    return this.executeCore("signUpEmailPassword", input, () =>
      users.signUpEmailPassword(this.ctx, input));
  }
  signInEmailPassword(input: SignInEmailPasswordInput): Promise<SignInResult> {
    return this.executeCore("signInEmailPassword", input, () =>
      users.signInEmailPassword(this.ctx, input));
  }
  signInWithVerifiedExternalIdentity(input: VerifiedExternalIdentityInput): Promise<SignInResult> {
    return this.executeCore("signInWithVerifiedExternalIdentity", input, () =>
      external.signInWithVerifiedExternalIdentity(this.ctx, input));
  }
  linkOAuthProvider(input: LinkOAuthProviderInput) {
    return this.executeCore("linkOAuthProvider", input, () =>
      external.linkOAuthProvider(this.ctx, input));
  }
  unlinkOAuthProvider(input: UnlinkOAuthProviderInput): Promise<void> {
    return this.executeCore("unlinkOAuthProvider", input, () =>
      external.unlinkOAuthProvider(this.ctx, input));
  }
  createOAuthAuthorizationUrl(input: CreateOAuthAuthorizationUrlInput): Promise<OAuthAuthorizationResult> {
    return this.executeCore("createOAuthAuthorizationUrl", input, () =>
      oauth.createOAuthAuthorizationUrl(this.ctx, input));
  }
  completeOAuthSignIn(input: CompleteOAuthSignInInput): Promise<OAuthCompletionResult> {
    return this.executeCore("completeOAuthSignIn", input, () =>
      oauth.completeOAuthSignIn(this.ctx, input));
  }
  prepareGoogleOneTap(input?: PrepareGoogleOneTapInput): Promise<PreparedGoogleOneTap> {
    return this.executeCore("prepareGoogleOneTap", input, () =>
      oauth.prepareGoogleOneTap(this.ctx, input));
  }
  signInWithGoogleOneTap(input: GoogleOneTapInput): Promise<OAuthCompletionResult> {
    return this.executeCore("signInWithGoogleOneTap", input, () =>
      oauth.signInWithGoogleOneTap(this.ctx, input));
  }
  beginTotpEnrollment(input: BeginTotpEnrollmentInput): Promise<BeginTotpEnrollmentResult> {
    return this.executeCore("beginTotpEnrollment", input, () =>
      mfa.beginTotpEnrollment(this.ctx, input));
  }
  confirmTotpEnrollment(input: ConfirmTotpEnrollmentInput): Promise<ConfirmTotpEnrollmentResult> {
    return this.executeCore("confirmTotpEnrollment", input, () =>
      mfa.confirmTotpEnrollment(this.ctx, input));
  }
  disableTotp(input: DisableTotpInput): Promise<void> {
    return this.executeCore("disableTotp", input, () => mfa.disableTotp(this.ctx, input));
  }
  completeMfaWithTotp(input: CompleteMfaInput): Promise<SessionResult> {
    return this.executeCore("completeMfaWithTotp", input, () =>
      mfa.completeMfaWithTotp(this.ctx, input));
  }
  completeMfaWithRecoveryCode(input: CompleteMfaInput): Promise<SessionResult> {
    return this.executeCore("completeMfaWithRecoveryCode", input, () =>
      mfa.completeMfaWithRecoveryCode(this.ctx, input));
  }
  regenerateRecoveryCodes(input: RegenerateRecoveryCodesInput): Promise<string[]> {
    return this.executeCore("regenerateRecoveryCodes", input, () =>
      mfa.regenerateRecoveryCodes(this.ctx, input));
  }
  getExternalAccessToken(input: GetExternalAccessTokenInput): Promise<ExternalAccessTokenResult> {
    return this.executeCore("getExternalAccessToken", input, () =>
      oauthCredentials.getExternalAccessToken(this.ctx, input));
  }
  revokeExternalProviderAccess(input: RevokeExternalProviderAccessInput): Promise<void> {
    return this.executeCore("revokeExternalProviderAccess", input, () =>
      oauthCredentials.revokeExternalProviderAccess(this.ctx, input));
  }
  beginPasskeyRegistration(input: BeginPasskeyRegistrationInput): Promise<BeginPasskeyRegistrationResult> {
    return this.executeCore("beginPasskeyRegistration", input, () =>
      passkeys.beginPasskeyRegistration(this.ctx, input));
  }
  completePasskeyRegistration(input: CompletePasskeyRegistrationInput) {
    return this.executeCore("completePasskeyRegistration", input, () =>
      passkeys.completePasskeyRegistration(this.ctx, input));
  }
  beginPasskeyAuthentication(input?: BeginPasskeyAuthenticationInput): Promise<BeginPasskeyAuthenticationResult> {
    return this.executeCore("beginPasskeyAuthentication", input, () =>
      passkeys.beginPasskeyAuthentication(this.ctx, input));
  }
  completePasskeyAuthentication(input: CompletePasskeyAuthenticationInput): Promise<SessionResult> {
    return this.executeCore("completePasskeyAuthentication", input, () =>
      passkeys.completePasskeyAuthentication(this.ctx, input));
  }
  listPasskeys(input: ListPasskeysInput) {
    return this.executeCore("listPasskeys", input, () => passkeys.listPasskeys(this.ctx, input));
  }
  renamePasskey(input: RenamePasskeyInput) {
    return this.executeCore("renamePasskey", input, () => passkeys.renamePasskey(this.ctx, input));
  }
  revokePasskey(input: RevokePasskeyInput): Promise<void> {
    return this.executeCore("revokePasskey", input, () => passkeys.revokePasskey(this.ctx, input));
  }
  changePassword(input: ChangePasswordInput): Promise<User> {
    return this.executeCore("changePassword", input, () => users.changePassword(this.ctx, input));
  }
  getCurrentSession(sessionToken: string): Promise<CurrentSession | null> {
    const input = { sessionToken };
    return this.executeCore("getCurrentSession", input, () =>
      sessions.getCurrentSession(this.ctx, sessionToken));
  }
  requireCurrentSession(sessionToken: string): Promise<CurrentSession> {
    const input = { sessionToken };
    return this.executeCore("requireCurrentSession", input, () =>
      sessions.requireCurrentSession(this.ctx, sessionToken));
  }
  signOut(sessionToken: string, context?: RequestContext): Promise<void> {
    const input = { sessionToken, request: context };
    return this.executeCore("signOut", input, () => sessions.signOut(this.ctx, sessionToken, context));
  }
  revokeSession(input: RevokeSessionInput): Promise<Session> {
    return this.executeCore("revokeSession", input, () => sessions.revokeSession(this.ctx, input));
  }
  revokeAllSessions(input: RevokeAllSessionsInput): Promise<number> {
    return this.executeCore("revokeAllSessions", input, () =>
      sessions.revokeAllSessions(this.ctx, input));
  }
  requestMagicLink(input: RequestTokenInput): Promise<DeliveryResult> {
    return this.executeCore("requestMagicLink", input, () => email.requestMagicLink(this.ctx, input));
  }
  verifyMagicLink(input: VerifyTokenInput): Promise<SignInResult> {
    return this.executeCore("verifyMagicLink", input, () => email.verifyMagicLink(this.ctx, input));
  }
  requestEmailVerification(input: RequestEmailVerificationInput): Promise<DeliveryResult> {
    return this.executeCore("requestEmailVerification", input, () =>
      email.requestEmailVerification(this.ctx, input));
  }
  verifyEmail(input: VerifyTokenInput): Promise<User> {
    return this.executeCore("verifyEmail", input, () => email.verifyEmail(this.ctx, input));
  }
  requestPasswordReset(input: RequestEmailVerificationInput): Promise<DeliveryResult> {
    return this.executeCore("requestPasswordReset", input, () =>
      email.requestPasswordReset(this.ctx, input));
  }
  resetPassword(input: ResetPasswordInput): Promise<User> {
    return this.executeCore("resetPassword", input, () => email.resetPassword(this.ctx, input));
  }
  requestSmsOtp(input: RequestSmsOtpInput): Promise<DeliveryResult> {
    return this.executeCore("requestSmsOtp", input, () => sms.requestSmsOtp(this.ctx, input));
  }
  verifySmsOtp(input: VerifySmsOtpInput): Promise<SmsOtpVerificationResult> {
    return this.executeCore("verifySmsOtp", input, () => sms.verifySmsOtp(this.ctx, input));
  }
  createApiKey(input: CreateApiKeyInput): Promise<CreatedApiKey> {
    return this.executeCore("createApiKey", input, () => apiKeys.createApiKey(this.ctx, input));
  }
  verifyApiKey(rawKey: string, requiredScopes: string[] = []): Promise<VerifiedApiKey> {
    const input = { rawKey, requiredScopes };
    return this.executeCore("verifyApiKey", input, () =>
      apiKeys.verifyApiKey(this.ctx, rawKey, requiredScopes));
  }
  revokeApiKey(input: RevokeApiKeyInput): Promise<ApiKeyDetails> {
    return this.executeCore("revokeApiKey", input, () => apiKeys.revokeApiKey(this.ctx, input));
  }
  createOrganisation(input: CreateOrganisationInput): Promise<{
    organisation: Organisation;
    ownerMembership: OrganisationMember<CustomRole>;
  }> {
    return this.executeCore("createOrganisation", input, () =>
      organisations.createOrganisation(this.ctx, input)) as Promise<{
        organisation: Organisation;
        ownerMembership: OrganisationMember<CustomRole>;
      }>;
  }
  getOrganisation(input: GetOrganisationInput): Promise<Organisation> {
    return this.executeCore("getOrganisation", input, () =>
      organisations.getOrganisation(this.ctx, input));
  }
  deleteOrganisation(input: DeleteOrganisationInput): Promise<Organisation> {
    return this.executeCore("deleteOrganisation", input, () =>
      organisations.deleteOrganisation(this.ctx, input));
  }
  updateOrganisation(organisationId: string, input: UpdateOrganisationInput): Promise<Organisation> {
    const operationInput = { organisationId, ...input };
    return this.executeCore("updateOrganisation", operationInput, () =>
      organisations.updateOrganisation(this.ctx, organisationId, input));
  }
  inviteMember(input: InviteMemberInput<CustomRole>): Promise<InvitationResult<CustomRole>> {
    return this.executeCore("inviteMember", input, () =>
      invitations.inviteMember(this.ctx, input)) as Promise<InvitationResult<CustomRole>>;
  }
  acceptInvite(input: AcceptInviteInput): Promise<AcceptInviteResult<CustomRole>> {
    return this.executeCore("acceptInvite", input, () =>
      invitations.acceptInvite(this.ctx, input)) as Promise<AcceptInviteResult<CustomRole>>;
  }
  changeMemberRole(input: ChangeMemberRoleInput<CustomRole>): Promise<OrganisationMember<CustomRole>> {
    return this.executeCore("changeMemberRole", input, () =>
      members.changeMemberRole(this.ctx, input)) as Promise<OrganisationMember<CustomRole>>;
  }
  removeMember(input: RemoveMemberInput): Promise<OrganisationMember<CustomRole>> {
    return this.executeCore("removeMember", input, () =>
      members.removeMember(this.ctx, input)) as Promise<OrganisationMember<CustomRole>>;
  }
  getMember(input: GetMemberInput): Promise<OrganisationMemberDetails<CustomRole>> {
    return this.executeCore("getMember", input, () =>
      members.getMember(this.ctx, input)) as Promise<OrganisationMemberDetails<CustomRole>>;
  }
  listMembers(input: ListMembersInput): Promise<OrganisationMemberDetails<CustomRole>[]> {
    return this.executeCore("listMembers", input, () =>
      members.listMembers(this.ctx, input)) as Promise<OrganisationMemberDetails<CustomRole>[]>;
  }
  checkPermission(
    organisationId: string,
    userId: string,
    permission: Permission<CustomPermission>
  ): Promise<boolean> {
    const input = { organisationId, userId, permission };
    return this.executeCore("checkPermission", input, () =>
      organisationAccess.checkPermission(this.ctx, organisationId, userId, permission));
  }
  requirePermission(
    organisationId: string,
    userId: string,
    permission: Permission<CustomPermission>
  ): Promise<OrganisationMember<CustomRole>> {
    const input = { organisationId, userId, permission };
    return this.executeCore("requirePermission", input, () =>
      organisationAccess.requirePermission(this.ctx, organisationId, userId, permission)
    ) as Promise<OrganisationMember<CustomRole>>;
  }
  disableUser(input: UserStatusInput): Promise<User> {
    return this.executeCore("disableUser", input, () => users.disableUser(this.ctx, input));
  }
  enableUser(input: UserStatusInput): Promise<User> {
    return this.executeCore("enableUser", input, () => users.enableUser(this.ctx, input));
  }
  revokeInvitation(input: RevokeInvitationInput): Promise<Invitation<CustomRole>> {
    return this.executeCore("revokeInvitation", input, () =>
      invitations.revokeInvitation(this.ctx, input)) as Promise<Invitation<CustomRole>>;
  }
  listSessions(input: ListSessionsInput): Promise<Session[]> {
    return this.executeCore("listSessions", input, () => sessions.listSessions(this.ctx, input));
  }
  listApiKeys(input: ListApiKeysInput): Promise<ApiKeyDetails[]> {
    return this.executeCore("listApiKeys", input, () => apiKeys.listApiKeys(this.ctx, input));
  }
  listOrganisations(input: ListOrganisationsInput): Promise<Organisation[]> {
    return this.executeCore("listOrganisations", input, () =>
      organisations.listOrganisations(this.ctx, input.actorUserId));
  }
  listInvitations(input: ListInvitationsInput): Promise<Invitation<CustomRole>[]> {
    return this.executeCore("listInvitations", input, () =>
      invitations.listInvitations(this.ctx, input)) as Promise<Invitation<CustomRole>[]>;
  }
  listAuditEvents(input: ListAuditEventsInput): Promise<AuditEvent[]> {
    return this.executeCore("listAuditEvents", input, () =>
      auditEvents.listAuditEvents(this.ctx, input));
  }
  cleanupAuditLogs(input: CleanupAuditLogsInput): Promise<number> {
    return this.executeCore("cleanupAuditLogs", input, () =>
      auditEvents.cleanupAuditLogs(this.ctx, input));
  }
  processWebhookDeliveries(input?: ProcessWebhookDeliveriesInput): Promise<ProcessWebhookDeliveriesResult> {
    return this.executeCore("processWebhookDeliveries", input, () =>
      webhookOperations.processWebhookDeliveries(this.ctx, input));
  }
  listWebhookDeliveries(input?: ListWebhookDeliveriesInput): Promise<WebhookDeliveryDetails[]> {
    return this.executeCore("listWebhookDeliveries", input, () =>
      webhookOperations.listWebhookDeliveries(this.ctx, input));
  }
  retryWebhookDelivery(input: RetryWebhookDeliveryInput): Promise<void> {
    return this.executeCore("retryWebhookDelivery", input, () =>
      webhookOperations.retryWebhookDelivery(this.ctx, input));
  }
  cleanupWebhookDeliveries(input: CleanupWebhookDeliveriesInput): Promise<number> {
    return this.executeCore("cleanupWebhookDeliveries", input, () =>
      webhookOperations.cleanupWebhookDeliveries(this.ctx, input));
  }

  close(): Promise<void> {
    if (this.closePromise) {
      return this.closePromise;
    }

    this.closed = true;
    this.closePromise = this.ctx.closePersistence();
    return this.closePromise;
  }
}
