import {
  AuthorizationProtocolError,
  invalidAuthorizationClient
} from "./authorization-server-protocol-error.js";
import type {
  AuthorizationRequestInput,
  TokenEndpointAuthMethod
} from "./authorization-server-types.js";
import { readLimitedBody } from "./http/request-input.js";

export function parseAuthorizationRequest(
  params: URLSearchParams
): AuthorizationRequestInput {
  return {
    responseType: singleAuthorizationParameter(params, "response_type"),
    responseMode: singleAuthorizationParameter(params, "response_mode"),
    clientId: singleAuthorizationParameter(params, "client_id"),
    redirectUri: singleAuthorizationParameter(params, "redirect_uri"),
    scope: singleAuthorizationParameter(params, "scope"),
    state: singleAuthorizationParameter(params, "state"),
    codeChallenge: singleAuthorizationParameter(params, "code_challenge"),
    codeChallengeMethod: singleAuthorizationParameter(
      params,
      "code_challenge_method"
    ),
    nonce: singleAuthorizationParameter(params, "nonce"),
    prompt: singleAuthorizationParameter(params, "prompt"),
    maxAge: singleAuthorizationParameter(params, "max_age"),
    acrValues: singleAuthorizationParameter(params, "acr_values"),
    display: singleAuthorizationParameter(params, "display"),
    uiLocales: singleAuthorizationParameter(params, "ui_locales"),
    claimsLocales: singleAuthorizationParameter(params, "claims_locales"),
    loginHint: singleAuthorizationParameter(params, "login_hint"),
    requestObject: singleAuthorizationParameter(params, "request"),
    requestUri: singleAuthorizationParameter(params, "request_uri")
  };
}

export function readAuthorizationClientCredentials(
  request: Request,
  form: URLSearchParams
): {
  clientId?: string;
  clientSecret?: string;
  clientAuthenticationMethod: TokenEndpointAuthMethod;
} {
  const basic = basicCredentials(request.headers.get("authorization"));
  const bodyClientId = singleAuthorizationParameter(form, "client_id");
  const bodySecret = singleAuthorizationParameter(form, "client_secret");
  if (basic && (bodyClientId !== undefined || bodySecret !== undefined)) {
    throw new AuthorizationProtocolError(
      "invalid_request",
      "Use exactly one client authentication method"
    );
  }
  if (basic) {
    return {
      clientId: basic.clientId,
      clientSecret: basic.clientSecret,
      clientAuthenticationMethod: "client_secret_basic"
    };
  }
  if (bodySecret !== undefined) {
    return {
      clientId: bodyClientId,
      clientSecret: bodySecret,
      clientAuthenticationMethod: "client_secret_post"
    };
  }
  return {
    clientId: bodyClientId,
    clientAuthenticationMethod: "none"
  };
}

export function readAuthorizationBearerToken(request: Request): string {
  const [scheme, token, extra] =
    request.headers.get("authorization")?.trim().split(/\s+/) ?? [];
  if (scheme?.toLowerCase() !== "bearer" || !token || extra) {
    throw new AuthorizationProtocolError(
      "invalid_token",
      "A Bearer access token is required",
      { statusCode: 401 }
    );
  }
  return token;
}

export async function readAuthorizationForm(
  request: Request,
  maximumBodyBytes: number
): Promise<URLSearchParams> {
  const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim();
  if (contentType !== "application/x-www-form-urlencoded") {
    throw new AuthorizationProtocolError(
      "invalid_request",
      "Content-Type must be application/x-www-form-urlencoded"
    );
  }
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > maximumBodyBytes) {
    throw new AuthorizationProtocolError("invalid_request", "Request body is too large");
  }
  return new URLSearchParams(await readLimitedBody(request, maximumBodyBytes));
}

export function singleAuthorizationParameter(
  params: URLSearchParams,
  name: string
): string | undefined {
  const values = params.getAll(name);
  if (values.length > 1) {
    throw new AuthorizationProtocolError(
      "invalid_request",
      `${name} must appear at most once`
    );
  }
  return values[0];
}

function basicCredentials(value: string | null): {
  clientId: string;
  clientSecret: string;
} | null {
  if (!value) return null;
  const [scheme, encoded, extra] = value.trim().split(/\s+/);
  if (scheme?.toLowerCase() !== "basic" || !encoded || extra) {
    throw invalidAuthorizationClient();
  }
  try {
    const decoded = atob(encoded);
    const separator = decoded.indexOf(":");
    if (separator < 1) throw invalidAuthorizationClient();
    return {
      clientId: decodeURIComponent(decoded.slice(0, separator)),
      clientSecret: decodeURIComponent(decoded.slice(separator + 1))
    };
  } catch (error) {
    if (error instanceof AuthorizationProtocolError) throw error;
    throw invalidAuthorizationClient();
  }
}
