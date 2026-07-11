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
  | "last_owner"
  | "already_member"
  | "invite_exists"
  | "invitation_not_found"
  | "invitation_not_pending"
  | "user_not_found"
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
