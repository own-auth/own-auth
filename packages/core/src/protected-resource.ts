import { encodeOAuthBasicCredentials } from "./encoding.js";
import { normalizeProtectedResourceUrl } from "./protected-resource-url.js";
import {
  canonicalizeDpopUrl,
  isDpopJwkThumbprint,
  maximumDpopProofBytes
} from "./dpop-crypto.js";

const scopePattern = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

export type ProtectedResourceVerificationError =
  | "invalid_dpop_proof"
  | "invalid_token"
  | "insufficient_scope";

export interface ActiveProtectedResourceToken {
  active: true;
  subject: string;
  clientId: string;
  resource: string;
  scopes: string[];
  tokenType: "Bearer" | "DPoP";
  dpopJkt?: string;
  issuedAt: Date;
  expiresAt: Date;
}

export interface InactiveProtectedResourceToken {
  active: false;
  error: ProtectedResourceVerificationError;
  requiredScopes?: string[];
}

export type ProtectedResourceTokenVerification =
  | ActiveProtectedResourceToken
  | InactiveProtectedResourceToken;

export interface VerifyProtectedResourceTokenInput {
  accessToken: string;
  requiredScopes?: readonly string[];
}

export interface VerifyProtectedResourceRequestInput {
  authorization: string | null | undefined;
  dpopProof?: string | null;
  method: string;
  url: string;
  requiredScopes?: readonly string[];
}

export interface OwnAuthProtectedResourceOptions {
  introspectionUrl: string;
  resource: string;
  resourceSecret: string;
  fetch?: typeof globalThis.fetch;
}

export interface BearerChallengeOptions {
  error?: ProtectedResourceVerificationError;
  realm?: string;
  requiredScopes?: readonly string[];
}

export type DpopChallengeOptions = BearerChallengeOptions;

export type OwnAuthProtectedResourceErrorCode =
  | "configuration_error"
  | "resource_authentication_failed"
  | "introspection_rate_limited"
  | "introspection_unavailable"
  | "invalid_introspection_response";

export class OwnAuthProtectedResourceError extends Error {
  constructor(
    readonly code: OwnAuthProtectedResourceErrorCode,
    message: string,
    readonly statusCode?: number
  ) {
    super(message);
    this.name = "OwnAuthProtectedResourceError";
  }
}

export interface OwnAuthProtectedResource {
  readonly resource: string;
  verifyAccessToken(
    input: VerifyProtectedResourceTokenInput
  ): Promise<ProtectedResourceTokenVerification>;
  verifyRequest(
    input: VerifyProtectedResourceRequestInput
  ): Promise<ProtectedResourceTokenVerification>;
  createBearerChallenge(options?: BearerChallengeOptions): string;
  createDpopChallenge(options?: DpopChallengeOptions): string;
}

export function createOwnAuthProtectedResource(
  options: OwnAuthProtectedResourceOptions
): OwnAuthProtectedResource {
  const introspectionUrl = requiredUrl(options.introspectionUrl, "introspectionUrl");
  const resource = requiredUrl(options.resource, "resource");
  const resourceSecret = requiredSecret(options.resourceSecret);
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw configurationError("A Fetch API implementation is required");
  }

  return {
    resource,
    createBearerChallenge,
    createDpopChallenge,
    async verifyAccessToken(input) {
      const accessToken = validAccessToken(input.accessToken);
      if (!accessToken) return invalidToken();
      return introspect({
        accessToken,
        tokenType: "Bearer",
        requiredScopes: input.requiredScopes
      });
    },
    async verifyRequest(input) {
      const authorization = parseAuthorization(input.authorization);
      if (!authorization) return invalidToken();
      const dpopProof = input.dpopProof ?? undefined;
      if (authorization.tokenType === "DPoP" && !validDpopProof(dpopProof)) {
        return invalidDpopProof();
      }
      if (authorization.tokenType === "Bearer" && dpopProof !== undefined) {
        return invalidDpopProof();
      }
      let requestUrl: string;
      try {
        requestUrl = canonicalizeDpopUrl(input.url);
      } catch {
        throw configurationError("url must be an absolute HTTP or HTTPS URL");
      }
      return introspect({
        ...authorization,
        dpopProof,
        requestMethod: input.method,
        requestUrl,
        requiredScopes: input.requiredScopes
      });
    }
  };

  async function introspect(input: {
    accessToken: string;
    tokenType: "Bearer" | "DPoP";
    dpopProof?: string;
    requestMethod?: string;
    requestUrl?: string;
    requiredScopes?: readonly string[];
  }): Promise<ProtectedResourceTokenVerification> {
    const requiredScopes = normalizeScopes(input.requiredScopes ?? []);
    const form = new URLSearchParams({ token: input.accessToken });
    if (input.dpopProof) form.set("dpop_proof", input.dpopProof);
    if (input.requestMethod) form.set("request_method", input.requestMethod);
    if (input.requestUrl) form.set("request_url", input.requestUrl);
    let response: Response;
    try {
      response = await fetchImpl(introspectionUrl, {
        method: "POST",
        headers: {
          accept: "application/json",
          authorization: encodeOAuthBasicCredentials(resource, resourceSecret),
          "content-type": "application/x-www-form-urlencoded"
        },
        body: form.toString()
      });
    } catch {
      throw new OwnAuthProtectedResourceError(
        "introspection_unavailable",
        "Own Auth token introspection is unavailable"
      );
    }
    if (response.status === 401 && isDpopChallenge(response)) {
      return invalidDpopProof();
    }
    if (response.status === 401 || response.status === 403) {
      throw new OwnAuthProtectedResourceError(
        "resource_authentication_failed",
        "Protected resource authentication failed",
        response.status
      );
    }
    if (response.status === 429) {
      throw new OwnAuthProtectedResourceError(
        "introspection_rate_limited",
        "Protected resource introspection is rate limited",
        429
      );
    }
    if (!response.ok) {
      throw new OwnAuthProtectedResourceError(
        "introspection_unavailable",
        "Own Auth token introspection failed",
        response.status
      );
    }
    const payload = await readIntrospectionResponse(response);
    if (payload.active === false) return invalidToken();
    if (payload.active !== true) throw invalidIntrospectionResponse();
    const active = parseActiveToken(payload, resource, input.tokenType);
    if (!active) return invalidToken();
    if (requiredScopes.some((scope) => !active.scopes.includes(scope))) {
      return {
        active: false,
        error: "insufficient_scope",
        requiredScopes
      };
    }
    return active;
  }
}

export function createBearerChallenge(
  options: BearerChallengeOptions = {}
): string {
  return createChallenge("Bearer", options);
}

export function createDpopChallenge(
  options: DpopChallengeOptions = {}
): string {
  return createChallenge("DPoP", options);
}

function createChallenge(
  scheme: "Bearer" | "DPoP",
  options: BearerChallengeOptions
): string {
  const parts = options.realm ? [`realm="${quote(options.realm)}"`] : [];
  if (options.error) {
    parts.push(`error="${options.error}"`);
    parts.push(
      `error_description="${options.error === "insufficient_scope"
        ? "The access token does not include the required scope"
        : options.error === "invalid_dpop_proof"
          ? "The DPoP proof is invalid"
          : "The access token is invalid, expired, or revoked"}"`
    );
  }
  const scopes = normalizeScopes(options.requiredScopes ?? []);
  if (scopes.length > 0) parts.push(`scope="${quote(scopes.join(" "))}"`);
  return parts.length > 0 ? `${scheme} ${parts.join(", ")}` : scheme;
}

function parseActiveToken(
  payload: Record<string, unknown>,
  resource: string,
  expectedTokenType: "Bearer" | "DPoP"
): ActiveProtectedResourceToken | null {
  if (
    typeof payload.sub !== "string" ||
    !payload.sub ||
    typeof payload.client_id !== "string" ||
    !payload.client_id ||
    typeof payload.aud !== "string" ||
    typeof payload.scope !== "string" ||
    typeof payload.exp !== "number" ||
    !Number.isSafeInteger(payload.exp) ||
    typeof payload.iat !== "number" ||
    !Number.isSafeInteger(payload.iat) ||
    (payload.token_type !== "Bearer" && payload.token_type !== "DPoP")
  ) {
    throw invalidIntrospectionResponse();
  }
  if (payload.token_type !== expectedTokenType) return null;
  const dpopJkt = parseDpopConfirmation(payload, payload.token_type);
  const expiresAt = new Date(payload.exp * 1_000);
  const issuedAt = new Date(payload.iat * 1_000);
  if (
    payload.aud !== resource ||
    Number.isNaN(expiresAt.getTime()) ||
    Number.isNaN(issuedAt.getTime()) ||
    expiresAt.getTime() <= Date.now() ||
    issuedAt.getTime() > expiresAt.getTime()
  ) {
    return null;
  }
  let scopes: string[];
  try {
    scopes = normalizeScopes(payload.scope ? payload.scope.split(" ") : []);
  } catch {
    return null;
  }
  return {
    active: true,
    subject: payload.sub,
    clientId: payload.client_id,
    resource,
    scopes,
    tokenType: payload.token_type,
    ...(dpopJkt ? { dpopJkt } : {}),
    issuedAt,
    expiresAt
  };
}

function parseDpopConfirmation(
  payload: Record<string, unknown>,
  tokenType: "Bearer" | "DPoP"
): string | null {
  if (tokenType === "Bearer") {
    if (payload.cnf !== undefined) throw invalidIntrospectionResponse();
    return null;
  }
  const confirmation = payload.cnf;
  if (!confirmation || typeof confirmation !== "object" || Array.isArray(confirmation)) {
    throw invalidIntrospectionResponse();
  }
  const thumbprint = (confirmation as Record<string, unknown>).jkt;
  if (!isDpopJwkThumbprint(thumbprint)) {
    throw invalidIntrospectionResponse();
  }
  return thumbprint;
}

async function readIntrospectionResponse(
  response: Response
): Promise<Record<string, unknown>> {
  try {
    const payload: unknown = await response.json();
    if (payload && typeof payload === "object" && !Array.isArray(payload)) {
      return payload as Record<string, unknown>;
    }
  } catch {
    // The response is handled as an invalid contract below.
  }
  throw invalidIntrospectionResponse();
}

function invalidIntrospectionResponse(): OwnAuthProtectedResourceError {
  return new OwnAuthProtectedResourceError(
    "invalid_introspection_response",
    "Own Auth returned an invalid introspection response"
  );
}

function requiredUrl(value: string, field: string): string {
  const normalized = normalizeProtectedResourceUrl(value, true);
  if (!normalized) {
    throw configurationError(
      `${field} must be an HTTPS or local development URL without a query or fragment`
    );
  }
  return normalized;
}

function requiredSecret(value: string): string {
  if (typeof value !== "string" || !value || value.length > 1_024) {
    throw configurationError("resourceSecret is required");
  }
  return value;
}

function validAccessToken(value: string): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= 4_096
    ? value
    : null;
}

function validDpopProof(value: string | undefined): value is string {
  return Boolean(
    value &&
    !value.includes(",") &&
    new TextEncoder().encode(value).byteLength <= maximumDpopProofBytes
  );
}

function parseAuthorization(value: string | null | undefined): {
  accessToken: string;
  tokenType: "Bearer" | "DPoP";
} | null {
  const [scheme, token, extra] = value?.trim().split(/\s+/) ?? [];
  const normalizedScheme = scheme?.toLowerCase();
  const accessToken = token ? validAccessToken(token) : null;
  if (
    !accessToken ||
    extra ||
    (normalizedScheme !== "bearer" && normalizedScheme !== "dpop")
  ) {
    return null;
  }
  return {
    accessToken,
    tokenType: normalizedScheme === "dpop" ? "DPoP" : "Bearer"
  };
}

function normalizeScopes(values: readonly string[]): string[] {
  if (!Array.isArray(values) || values.length > 100) {
    throw configurationError("requiredScopes must contain at most 100 scopes");
  }
  const scopes = [...values];
  if (
    new Set(scopes).size !== scopes.length ||
    scopes.some(
      (scope) => typeof scope !== "string" || !scopePattern.test(scope)
    )
  ) {
    throw configurationError("requiredScopes contains an invalid or duplicate scope");
  }
  return scopes;
}

function quote(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]/g, "").replace(/[\\"]/g, "\\$&");
}

function invalidToken(): InactiveProtectedResourceToken {
  return { active: false, error: "invalid_token" };
}

function invalidDpopProof(): InactiveProtectedResourceToken {
  return { active: false, error: "invalid_dpop_proof" };
}

function isDpopChallenge(response: Response): boolean {
  const challenge = response.headers.get("www-authenticate")?.toLowerCase();
  return challenge === "dpop" || challenge?.startsWith("dpop ") === true;
}

function configurationError(message: string): OwnAuthProtectedResourceError {
  return new OwnAuthProtectedResourceError("configuration_error", message);
}
