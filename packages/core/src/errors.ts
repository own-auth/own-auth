export type AuthErrorCode =
  | "email_already_exists"
  | "phone_already_exists"
  | "invalid_credentials"
  | "invalid_token"
  | "expired_token"
  | "token_already_used"
  | "invalid_session"
  | "disabled_user"
  | "rate_limited"
  | "weak_password"
  | "redirect_not_allowed"
  | "invalid_otp"
  | "otp_attempts_exceeded"
  | "api_key_invalid"
  | "api_key_revoked"
  | "api_key_expired"
  | "insufficient_scope"
  | "organisation_not_found"
  | "member_not_found"
  | "permission_denied"
  | "administration_not_configured"
  | "role_not_configured"
  | "last_owner"
  | "already_member"
  | "invite_exists"
  | "invitation_not_found"
  | "invitation_not_pending"
  | "user_not_found"
  | "account_linking_required"
  | "oauth_account_conflict"
  | "oauth_verified_email_required"
  | "oauth_transaction_invalid"
  | "oauth_provider_error"
  | "authorization_server_not_configured"
  | "authorization_client_not_found"
  | "authorization_client_revoked"
  | "authorization_interaction_invalid"
  | "device_authorization_invalid"
  | "device_authorization_already_decided"
  | "protected_resource_not_found"
  | "protected_resource_revoked"
  | "protected_resource_identifier_unavailable"
  | "external_credential_missing"
  | "encryption_not_configured"
  | "encryption_key_unavailable"
  | "encrypted_data_invalid"
  | "mfa_required"
  | "mfa_challenge_invalid"
  | "mfa_code_invalid"
  | "mfa_timestep_reused"
  | "authentication_method_required"
  | "passkey_invalid"
  | "passkey_not_found"
  | "saml_not_configured"
  | "saml_connection_not_found"
  | "saml_connection_disabled"
  | "saml_transaction_invalid"
  | "saml_response_invalid"
  | "saml_signature_algorithm_unsupported"
  | "saml_identity_conflict"
  | "saml_verified_email_required"
  | "saml_membership_required"
  | "scim_not_configured"
  | "scim_connection_not_found"
  | "scim_connection_disabled"
  | "scim_token_invalid"
  | "scim_user_not_found"
  | "scim_restore_conflict"
  | "plugin_denied"
  | "plugin_hook_timeout"
  | "webhook_signature_invalid"
  | "webhook_timestamp_invalid"
  | "webhook_replayed"
  | "webhook_delivery_not_retryable"
  | "auth_closed"
  | "validation_error";

export class AuthError extends Error {
  readonly code: AuthErrorCode;
  readonly statusCode: number;
  readonly safeMessage: string;

  constructor(code: AuthErrorCode, safeMessage: string, statusCode = 400) {
    super(safeMessage);
    this.name = "AuthError";
    this.code = code;
    this.statusCode = statusCode;
    this.safeMessage = safeMessage;
  }
}

export function toAuthError(error: unknown): AuthError {
  if (error instanceof AuthError) {
    return error;
  }

  return new AuthError("invalid_credentials", "Authentication failed", 500);
}

export function createAuthClosedError(): AuthError {
  return new AuthError("auth_closed", "Own Auth has been closed", 503);
}

const identityConflicts = {
  email: ["email_already_exists", "Email already exists"],
  phone: ["phone_already_exists", "Phone already exists"],
  providerAccount: ["oauth_account_conflict", "Provider account is already linked"]
} as const satisfies Record<string, readonly [AuthErrorCode, string]>;

export function createIdentityConflictError(
  conflict: keyof typeof identityConflicts
): AuthError {
  const [code, message] = identityConflicts[conflict];
  return new AuthError(code, message, 409);
}
