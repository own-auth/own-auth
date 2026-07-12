import type { Permission } from "./permissions.js";
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
import {
  createAuthEngineContext,
  type AuthEngineContext
} from "./auth-engine-internals.js";
import * as apiKeys from "./auth-engine-api-keys.js";
import * as auditEvents from "./auth-engine-audit.js";
import * as email from "./auth-engine-email.js";
import * as external from "./auth-engine-external.js";
import * as invitations from "./auth-engine-invitations.js";
import * as members from "./auth-engine-members.js";
import * as organisationAccess from "./auth-engine-organisation-access.js";
import * as organisations from "./auth-engine-organisations.js";
import * as sessions from "./auth-engine-sessions.js";
import * as sms from "./auth-engine-sms.js";
import * as users from "./auth-engine-users.js";
import type {
  AcceptInviteInput,
  AcceptInviteResult,
  ChangeMemberRoleInput,
  ChangePasswordInput,
  CleanupAuditLogsInput,
  CreateApiKeyInput,
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
  RemoveMemberInput,
  RequestEmailVerificationInput,
  RequestSmsOtpInput,
  RequestTokenInput,
  ResetPasswordInput,
  RevokeAllSessionsInput,
  RevokeApiKeyInput,
  RevokeInvitationInput,
  RevokeSessionInput,
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

export type { OwnAuthOptions } from "./auth-engine-types.js";

export class OwnAuth {
  readonly storage: AuthStorage;
  readonly rateLimitStore: RateLimitStore;
  private readonly ctx: AuthEngineContext;

  constructor(options: OwnAuthOptions = {}) {
    this.ctx = createAuthEngineContext(options);
    this.storage = this.ctx.storage;
    this.rateLimitStore = this.ctx.rateLimitStore;
  }

  createUser(input: CreateUserInput): Promise<User> { return users.createUser(this.ctx, input); }
  signUpEmailPassword(input: SignUpEmailPasswordInput): Promise<SessionResult> { return users.signUpEmailPassword(this.ctx, input); }
  signInEmailPassword(input: SignInEmailPasswordInput): Promise<SessionResult> { return users.signInEmailPassword(this.ctx, input); }
  signInWithExternalProvider(input: SignInWithExternalProviderInput): Promise<SessionResult> {
    return external.signInWithExternalProvider(this.ctx, input);
  }
  changePassword(input: ChangePasswordInput): Promise<User> { return users.changePassword(this.ctx, input); }
  getCurrentSession(sessionToken: string): Promise<CurrentSession | null> { return sessions.getCurrentSession(this.ctx, sessionToken); }
  requireCurrentSession(sessionToken: string): Promise<CurrentSession> { return sessions.requireCurrentSession(this.ctx, sessionToken); }
  signOut(sessionToken: string, context?: RequestContext): Promise<void> { return sessions.signOut(this.ctx, sessionToken, context); }
  revokeSession(input: RevokeSessionInput): Promise<Session> { return sessions.revokeSession(this.ctx, input); }
  revokeAllSessions(input: RevokeAllSessionsInput): Promise<number> {
    return sessions.revokeAllSessions(this.ctx, input);
  }
  requestMagicLink(input: RequestTokenInput): Promise<DeliveryResult> { return email.requestMagicLink(this.ctx, input); }
  verifyMagicLink(input: VerifyTokenInput): Promise<SessionResult> { return email.verifyMagicLink(this.ctx, input); }
  requestEmailVerification(input: RequestEmailVerificationInput): Promise<DeliveryResult> {
    return email.requestEmailVerification(this.ctx, input);
  }
  verifyEmail(input: VerifyTokenInput): Promise<User> { return email.verifyEmail(this.ctx, input); }
  requestPasswordReset(input: RequestEmailVerificationInput): Promise<DeliveryResult> {
    return email.requestPasswordReset(this.ctx, input);
  }
  resetPassword(input: ResetPasswordInput): Promise<User> { return email.resetPassword(this.ctx, input); }
  requestSmsOtp(input: RequestSmsOtpInput): Promise<DeliveryResult> { return sms.requestSmsOtp(this.ctx, input); }
  verifySmsOtp(input: VerifySmsOtpInput): Promise<SmsOtpVerificationResult> { return sms.verifySmsOtp(this.ctx, input); }
  createApiKey(input: CreateApiKeyInput): Promise<CreatedApiKey> { return apiKeys.createApiKey(this.ctx, input); }
  verifyApiKey(rawKey: string, requiredScopes: string[] = []): Promise<VerifiedApiKey> { return apiKeys.verifyApiKey(this.ctx, rawKey, requiredScopes); }
  revokeApiKey(input: RevokeApiKeyInput): Promise<ApiKeyDetails> {
    return apiKeys.revokeApiKey(this.ctx, input);
  }
  createOrganisation(input: CreateOrganisationInput): Promise<{
    organisation: Organisation;
    ownerMembership: OrganisationMember;
  }> {
    return organisations.createOrganisation(this.ctx, input);
  }
  getOrganisation(input: GetOrganisationInput): Promise<Organisation> {
    return organisations.getOrganisation(this.ctx, input);
  }
  deleteOrganisation(input: DeleteOrganisationInput): Promise<Organisation> {
    return organisations.deleteOrganisation(this.ctx, input);
  }
  updateOrganisation(organisationId: string, input: UpdateOrganisationInput): Promise<Organisation> {
    return organisations.updateOrganisation(this.ctx, organisationId, input);
  }
  inviteMember(input: InviteMemberInput): Promise<InvitationResult> { return invitations.inviteMember(this.ctx, input); }
  acceptInvite(input: AcceptInviteInput): Promise<AcceptInviteResult> {
    return invitations.acceptInvite(this.ctx, input);
  }
  changeMemberRole(input: ChangeMemberRoleInput): Promise<OrganisationMember> { return members.changeMemberRole(this.ctx, input); }
  removeMember(input: RemoveMemberInput): Promise<OrganisationMember> { return members.removeMember(this.ctx, input); }
  getMember(input: GetMemberInput): Promise<OrganisationMemberDetails> {
    return members.getMember(this.ctx, input);
  }
  listMembers(input: ListMembersInput): Promise<OrganisationMemberDetails[]> {
    return members.listMembers(this.ctx, input);
  }
  checkPermission(
    organisationId: string,
    userId: string,
    permission: Permission
  ): Promise<boolean> {
    return organisationAccess.checkPermission(this.ctx, organisationId, userId, permission);
  }
  requirePermission(
    organisationId: string,
    userId: string,
    permission: Permission
  ): Promise<OrganisationMember> {
    return organisationAccess.requirePermission(this.ctx, organisationId, userId, permission);
  }
  disableUser(input: UserStatusInput): Promise<User> { return users.disableUser(this.ctx, input); }
  enableUser(input: UserStatusInput): Promise<User> { return users.enableUser(this.ctx, input); }
  revokeInvitation(input: RevokeInvitationInput): Promise<Invitation> { return invitations.revokeInvitation(this.ctx, input); }
  listSessions(input: ListSessionsInput): Promise<Session[]> {
    return sessions.listSessions(this.ctx, input);
  }
  listApiKeys(input: ListApiKeysInput): Promise<ApiKeyDetails[]> {
    return apiKeys.listApiKeys(this.ctx, input);
  }
  listOrganisations(input: ListOrganisationsInput): Promise<Organisation[]> {
    return organisations.listOrganisations(this.ctx, input.actorUserId);
  }
  listInvitations(input: ListInvitationsInput): Promise<Invitation[]> {
    return invitations.listInvitations(this.ctx, input);
  }
  listAuditEvents(input: ListAuditEventsInput): Promise<AuditEvent[]> {
    return auditEvents.listAuditEvents(this.ctx, input);
  }
  cleanupAuditLogs(input: CleanupAuditLogsInput): Promise<number> {
    return auditEvents.cleanupAuditLogs(this.ctx, input);
  }
}

export function createOwnAuth(options?: OwnAuthOptions): OwnAuth {
  return new OwnAuth(options);
}
