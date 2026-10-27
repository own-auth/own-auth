import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON
} from "@simplewebauthn/server";
import type { AuthError, AuthErrorCode } from "../errors.js";
import type { MfaMethod } from "../identity-types.js";
import type { ExternalAccountProvider, SessionAssuranceLevel } from "../types.js";
import type {
  AdministrationEraseUserInput, EraseUserInput, UserErasureOperationInput, UserErasureResult
} from "../user-erasure.js";

export type OwnAuthHttpMethod = "GET" | "POST";
export type JsonSchema = Readonly<Record<string, unknown>>;

export interface PublicAuthUser {
  id: string;
  email: string | null;
  emailVerifiedAt: string | null;
  phone: string | null;
  phoneVerifiedAt: string | null;
  name: string | null;
  imageUrl: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
  lastLoginAt: string | null;
}

export interface PublicAuthSession {
  id: string;
  userId: string;
  createdAt: string;
  lastActiveAt: string;
  expiresAt: string;
  idleExpiresAt: string;
  ipAddress: string | null;
  userAgent: string | null;
  authenticationMethods: string[];
  assuranceLevel: SessionAssuranceLevel;
  authenticatedAt: string;
}

export interface PublicOrganisation {
  id: string;
  name: string;
  slug: string;
}

export interface PublicOrganisationMember {
  id: string;
  organisationId: string;
  userId: string;
  role: string;
  joinedAt: string | null;
}

export interface PublicPasskey {
  id: string;
  name: string;
  discoverable: boolean;
  deviceType: "singleDevice" | "multiDevice";
  backedUp: boolean;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface PublicAdministrationUser extends PublicAuthUser {
  disabledAt: string | null;
}

export interface PublicAdministrationSession extends PublicAuthSession {
  revokedAt: string | null;
  revokeReason: string | null;
  effectiveStatus: "active" | "disabled_user" | "expired" | "revoked";
}

export interface PublicAdministrationAuditEvent {
  id: string;
  eventType: string;
  actorUserId: string | null;
  targetUserId: string | null;
  organisationId: string | null;
  apiKeyId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
}

export interface AuthSessionPayload {
  status: "complete";
  user: PublicAuthUser;
  session: PublicAuthSession;
}

export interface MfaRequiredPayload {
  status: "mfa_required";
  methods: MfaMethod[];
  expiresAt: string;
}

export type SignInPayload = AuthSessionPayload | MfaRequiredPayload;

export interface DeliveryPayload {
  sent: boolean;
  expiresAt: string | null;
  delivery: {
    status: "sent" | "failed";
    reason?: "quota_exhausted" | "provider_rejected" | "transient_error" | "invalid_request";
  };
}

export interface OwnAuthEndpointInputMap {
  eraseUser: Omit<EraseUserInput, "sessionToken" | "request">;
  adminEraseUser: Omit<AdministrationEraseUserInput, "actorUserId" | "request">;
  adminGetUserErasure: UserErasureOperationInput;
  adminResumeUserErasure: UserErasureOperationInput;
  signUpEmailPassword: { email: string; password: string; name?: string };
  signInEmailPassword: { email: string; password: string };
  getSession: undefined;
  signOut: undefined;
  changePassword: { currentPassword: string; newPassword: string };
  requestMagicLink: { email: string; redirectUrl?: string };
  verifyMagicLink: { token: string };
  requestEmailVerification: { email: string };
  verifyEmail: { token: string };
  requestPasswordReset: { email: string };
  resetPassword: { token: string; newPassword: string };
  requestSmsOtp: {
    phone: string;
    purpose?: "phone_login" | "phone_verification" | "account_recovery";
  };
  verifySmsOtp: {
    phone: string;
    code: string;
    purpose?: "phone_login" | "phone_verification" | "account_recovery";
  };
  acceptInvite: { token: string };
  oauthStart: {
    provider: ExternalAccountProvider;
    intent?: "sign_in" | "link";
    destination?: string;
    mode?: "redirect" | "popup";
    openerOrigin?: string;
  };
  oauthGoogleCallback: Record<string, string>;
  oauthGitHubCallback: Record<string, string>;
  oauthAppleCallback: Record<string, string>;
  oauthAppleCallbackPost: Record<string, string>;
  prepareGoogleOneTap: undefined;
  signInGoogleOneTap: { credential: string; nonce: string };
  unlinkOAuthProvider: { provider: ExternalAccountProvider; providerAccountId: string };
  samlStart: {
    connectionId: string;
    intent?: "sign_in" | "link";
    destination?: string;
  };
  samlAcs: { SAMLResponse: string; RelayState: string };
  samlMetadata: { connectionId: string };
  completeMfaTotp: { code: string };
  completeMfaRecovery: { code: string };
  beginTotpEnrollment: undefined;
  confirmTotpEnrollment: { factorId: string; code: string };
  disableTotp: { code: string };
  regenerateRecoveryCodes: { code: string };
  beginPasskeyRegistration: undefined;
  completePasskeyRegistration: { response: RegistrationResponseJSON; name?: string };
  beginPasskeyAuthentication: { userId?: string; mfa?: boolean };
  completePasskeyAuthentication: { response: AuthenticationResponseJSON };
  listPasskeys: undefined;
  renamePasskey: { passkeyId: string; name: string };
  revokePasskey: { passkeyId: string };
  adminListUsers: {
    query?: string;
    status?: "active" | "disabled" | "all";
    cursor?: string;
    limit?: string;
  };
  adminGetUser: { userId: string };
  adminListUserSessions: { userId: string };
  adminListUserAuditEvents: { userId: string; cursor?: string; limit?: string };
  adminDisableUser: { userId: string; reason: string };
  adminEnableUser: { userId: string; reason: string };
  adminRevokeUserSessions: { userId: string; reason: string };
}

export interface OwnAuthEndpointOutputMap {
  eraseUser: UserErasureResult;
  adminEraseUser: UserErasureResult;
  adminGetUserErasure: UserErasureResult;
  adminResumeUserErasure: UserErasureResult;
  signUpEmailPassword: AuthSessionPayload;
  signInEmailPassword: SignInPayload;
  getSession: { session: AuthSessionPayload | null };
  signOut: { success: true };
  changePassword: { user: PublicAuthUser };
  requestMagicLink: DeliveryPayload;
  verifyMagicLink: SignInPayload;
  requestEmailVerification: DeliveryPayload;
  verifyEmail: { user: PublicAuthUser };
  requestPasswordReset: DeliveryPayload;
  resetPassword: { user: PublicAuthUser };
  requestSmsOtp: DeliveryPayload;
  verifySmsOtp: SignInPayload | { status: "verified"; user: PublicAuthUser };
  acceptInvite: { organisation: PublicOrganisation; member: PublicOrganisationMember };
  oauthStart: { url: string; expiresAt: string };
  oauthGoogleCallback: { status: "complete" | "mfa_required" | "linked" };
  oauthGitHubCallback: { status: "complete" | "mfa_required" | "linked" };
  oauthAppleCallback: { status: "complete" | "mfa_required" | "linked" };
  oauthAppleCallbackPost: { status: "complete" | "mfa_required" | "linked" };
  prepareGoogleOneTap: { nonce: string; expiresAt: string };
  signInGoogleOneTap: SignInPayload;
  unlinkOAuthProvider: { success: true };
  samlStart: { url: string; expiresAt: string };
  samlAcs: { status: "complete" | "mfa_required" | "linked" };
  samlMetadata: string;
  completeMfaTotp: AuthSessionPayload;
  completeMfaRecovery: AuthSessionPayload;
  beginTotpEnrollment: { factorId: string; secret: string; uri: string };
  confirmTotpEnrollment: { recoveryCodes: string[] };
  disableTotp: { success: true };
  regenerateRecoveryCodes: { recoveryCodes: string[] };
  beginPasskeyRegistration: { options: PublicKeyCredentialCreationOptionsJSON };
  completePasskeyRegistration: { passkey: PublicPasskey };
  beginPasskeyAuthentication: { options: PublicKeyCredentialRequestOptionsJSON };
  completePasskeyAuthentication: AuthSessionPayload;
  listPasskeys: { passkeys: PublicPasskey[] };
  renamePasskey: { passkey: PublicPasskey };
  revokePasskey: { success: true };
  adminListUsers: { users: PublicAdministrationUser[]; nextCursor: string | null };
  adminGetUser: { user: PublicAdministrationUser };
  adminListUserSessions: { sessions: PublicAdministrationSession[] };
  adminListUserAuditEvents: {
    events: PublicAdministrationAuditEvent[];
    nextCursor: string | null;
  };
  adminDisableUser: { user: PublicAdministrationUser };
  adminEnableUser: { user: PublicAdministrationUser };
  adminRevokeUserSessions: { revoked: number };
}

export type OwnAuthEndpointId = keyof OwnAuthEndpointInputMap;
export type OwnAuthHttpErrorCode =
  | AuthErrorCode
  | "csrf_failed"
  | "invalid_request"
  | "method_not_allowed"
  | "not_found"
  | "internal_error"
  | `plugin.${string}`;

export interface OwnAuthErrorPayload {
  error: { code: OwnAuthHttpErrorCode; message: string; details?: AuthError["details"] };
}

export interface OwnAuthEndpointDefinition {
  readonly pendingResponse?: boolean;
  readonly id: OwnAuthEndpointId;
  readonly method: OwnAuthHttpMethod;
  readonly path: string;
  readonly summary: string;
  readonly request?: JsonSchema;
  readonly requestTransport?: "json" | "query" | "form";
  readonly response: JsonSchema;
  readonly responseKind?: "json" | "oauth_callback" | "saml_callback" | "xml";
  readonly errors: readonly OwnAuthHttpErrorCode[];
  readonly session: "none" | "optional" | "required" | "create" | "clear";
  readonly csrf?: "default" | "oauth_state" | "saml_state";
  readonly feature?: "administration" | "saml";
}
