export type AuthorizationProtocolErrorCode =
  | "access_denied"
  | "consent_required"
  | "authorization_pending"
  | "invalid_client"
  | "invalid_dpop_proof"
  | "invalid_grant"
  | "invalid_request"
  | "invalid_scope"
  | "invalid_target"
  | "invalid_token"
  | "interaction_required"
  | "expired_token"
  | "login_required"
  | "server_error"
  | "slow_down"
  | "temporarily_unavailable"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "unsupported_response_mode"
  | "unsupported_response_type";

export class AuthorizationProtocolError extends Error {
  readonly code: AuthorizationProtocolErrorCode;
  readonly safeDescription: string;
  readonly statusCode: number;
  readonly redirectUri: string | null;
  readonly state: string | null;

  constructor(
    code: AuthorizationProtocolErrorCode,
    safeDescription: string,
    options: {
      statusCode?: number;
      redirectUri?: string | null;
      state?: string | null;
    } = {}
  ) {
    super(safeDescription);
    this.name = "AuthorizationProtocolError";
    this.code = code;
    this.safeDescription = safeDescription;
    this.statusCode = options.statusCode ?? 400;
    this.redirectUri = options.redirectUri ?? null;
    this.state = options.state ?? null;
  }
}

export function invalidAuthorizationClient(): AuthorizationProtocolError {
  return new AuthorizationProtocolError(
    "invalid_client",
    "Authorization client authentication failed",
    { statusCode: 401 }
  );
}
