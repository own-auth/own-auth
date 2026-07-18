import type { AuthEngineContext } from "./auth-engine-context.js";
import type { AuthorizationServerRuntimeConfig } from "./authorization-server-config.js";
import type { AuthorizationServerStorage } from "./authorization-server-storage.js";
import { deviceAuthorizationGrantType } from "./authorization-server-device-types.js";
import type {
  AuthorizationApplicationType,
  AuthorizationClient,
  AuthorizationClientGrantType,
  AuthorizationPrompt,
  StoredAuthorizationRequest
} from "./authorization-server-types.js";
import {
  authorizationPrompts,
  authorizationServerTokenPrefixes
} from "./authorization-server-constants.js";
import { hashSecret, randomBase64Url } from "./crypto.js";
import { encodeBase64Url } from "./encoding.js";
import { requireEncryptionKeyRing } from "./encryption.js";
import { AuthError } from "./errors.js";
import { AuthorizationProtocolError } from "./authorization-server-protocol-error.js";
import { normalizeProtectedResourceUrl } from "./protected-resource-url.js";
import type { SessionAssuranceLevel } from "./types.js";
import {
  isLocalHostname,
  isSafeAuthRedirect,
  parseAbsoluteUrl
} from "./url-security.js";

const defaultClientScopes = ["openid", "profile", "email"];
const scopeNamePattern = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
const codeChallengePattern = /^[A-Za-z0-9_-]{43}$/;
const codeVerifierPattern = /^[A-Za-z0-9._~-]{43,128}$/;
const clientSecretPattern = new RegExp(
  `^(${authorizationServerTokenPrefixes.clientSecret}[A-Za-z0-9_-]{8})_` +
  "[A-Za-z0-9_-]{43}$"
);
const protectedResourceSecretPattern = new RegExp(
  `^(${authorizationServerTokenPrefixes.protectedResourceSecret}[A-Za-z0-9_-]{8})_` +
  "[A-Za-z0-9_-]{43}$"
);

export function requireAuthorizationServer(
  ctx: AuthEngineContext
): {
  config: AuthorizationServerRuntimeConfig;
  storage: AuthorizationServerStorage;
} {
  if (!ctx.authorizationServer || !ctx.authorizationServerStorage) {
    throw new AuthError(
      "authorization_server_not_configured",
      "OAuth/OIDC authorization-server support is not configured",
      404
    );
  }
  return {
    config: ctx.authorizationServer,
    storage: ctx.authorizationServerStorage
  };
}

export function createClientId(): string {
  return createPrefixedToken(authorizationServerTokenPrefixes.clientId, 16);
}

export function createClientSecret(): {
  raw: string;
  prefix: string;
} {
  const prefix =
    `${authorizationServerTokenPrefixes.clientSecret}${randomBase64Url(6)}`;
  return {
    raw: `${prefix}_${randomBase64Url(32)}`,
    prefix
  };
}

export function extractClientSecretPrefix(rawSecret: string): string | null {
  return clientSecretPattern.exec(rawSecret)?.[1] ?? null;
}

export function createProtectedResourceSecret(): {
  raw: string;
  prefix: string;
} {
  const prefix =
    `${authorizationServerTokenPrefixes.protectedResourceSecret}${randomBase64Url(6)}`;
  return {
    raw: `${prefix}_${randomBase64Url(32)}`,
    prefix
  };
}

export function extractProtectedResourceSecretPrefix(rawSecret: string): string | null {
  return protectedResourceSecretPattern.exec(rawSecret)?.[1] ?? null;
}

export function requireAuthorizationProtocolToken(value: string | undefined): string {
  if (typeof value !== "string" || !value || value.length > 512) {
    throw new AuthorizationProtocolError("invalid_request", "token is required");
  }
  return value;
}

export function normalizeProtectedResourceIdentifier(value: string): string {
  const normalized = normalizeProtectedResourceUrl(
    value,
    process.env.NODE_ENV !== "production"
  );
  if (!normalized) {
    throw validationError(
      "Protected resource identifiers require HTTPS or a local development URL without a query or fragment"
    );
  }
  return normalized;
}

export function createInteractionToken(): string {
  return createPrefixedToken(authorizationServerTokenPrefixes.interaction, 32);
}

export function createAuthorizationCodeToken(): string {
  return createPrefixedToken(
    authorizationServerTokenPrefixes.authorizationCode,
    32
  );
}

export function createAccessToken(): string {
  return createPrefixedToken(authorizationServerTokenPrefixes.accessToken, 32);
}

export function createRefreshToken(): string {
  return createPrefixedToken(authorizationServerTokenPrefixes.refreshToken, 48);
}

export function authorizationTokenPrefix(token: string): string {
  return token.slice(0, Math.min(token.length, 18));
}

export function hashAuthorizationSecret(ctx: AuthEngineContext, value: string): string {
  return hashSecret(value, ctx.tokenPepper);
}

export function normalizeClientRedirectUris(
  applicationType: AuthorizationApplicationType,
  values: readonly string[],
  grantTypes: readonly AuthorizationClientGrantType[]
): string[] {
  const minimum = grantTypes.includes("authorization_code") ? 1 : 0;
  if (!Array.isArray(values) || values.length < minimum || values.length > 20) {
    throw validationError(
      minimum === 1
        ? "redirectUris must contain between 1 and 20 URLs"
        : "redirectUris must contain at most 20 URLs"
    );
  }
  const redirectUris = values.map((value) => {
    if (typeof value !== "string" || value.length > 2_048) {
      throw validationError("Each redirect URI must be a string of at most 2048 characters");
    }
    const parsed = parseAbsoluteUrl(value);
    if (!parsed || parsed.hash || !isSafeAuthRedirect(parsed)) {
      throw validationError("Each redirect URI must be a safe absolute URL without a fragment");
    }
    if (
      applicationType === "web" &&
      parsed.protocol !== "https:" &&
      !(parsed.protocol === "http:" && isLocalHostname(parsed.hostname))
    ) {
      throw validationError("Web clients require HTTPS or local development redirect URIs");
    }
    return value;
  });
  if (new Set(redirectUris).size !== redirectUris.length) {
    throw validationError("redirectUris must not contain duplicates");
  }
  return redirectUris;
}

export function normalizeClientGrantTypes(
  values: readonly AuthorizationClientGrantType[] | undefined
): AuthorizationClientGrantType[] {
  const grantTypes = values
    ? [...values]
    : ["authorization_code", "refresh_token"] satisfies AuthorizationClientGrantType[];
  const supported = new Set<AuthorizationClientGrantType>([
    "authorization_code",
    "refresh_token",
    deviceAuthorizationGrantType
  ]);
  if (
    grantTypes.length < 1 ||
    grantTypes.length > supported.size ||
    new Set(grantTypes).size !== grantTypes.length ||
    grantTypes.some((grantType) => !supported.has(grantType))
  ) {
    throw validationError("grantTypes contains an unsupported or duplicate grant type");
  }
  return grantTypes;
}

export function normalizeAllowedScopes(
  config: AuthorizationServerRuntimeConfig,
  values: readonly string[] | undefined
): string[] {
  if (values !== undefined && !Array.isArray(values)) {
    throw validationError("allowedScopes must be an array");
  }
  const scopes = values ? [...values] : [...defaultClientScopes];
  if (scopes.length < 1 || scopes.length > 100) {
    throw validationError("allowedScopes must contain between 1 and 100 scopes");
  }
  if (new Set(scopes).size !== scopes.length) {
    throw validationError("allowedScopes must not contain duplicates");
  }
  validateScopeSet(config, scopes, "allowedScopes");
  return scopes;
}

export function parseRequestedScopes(
  config: AuthorizationServerRuntimeConfig,
  client: AuthorizationClient,
  value: string | undefined
): string[] {
  const scopes = splitSpaceSeparated(value, "scope", 100);
  if (scopes.length === 0) {
    throw validationError("scope is required");
  }
  validateScopeSet(config, scopes, "scope");
  if (scopes.some((scope) => !client.allowedScopes.includes(scope))) {
    throw new AuthError("validation_error", "Requested scope is not allowed", 400);
  }
  return scopes;
}

export function parsePrompts(value: string | undefined): AuthorizationPrompt[] {
  const prompts = splitSpaceSeparated(value, "prompt", 4);
  if (
    prompts.some(
      (prompt) => !authorizationPrompts.includes(prompt as AuthorizationPrompt)
    )
  ) {
    throw validationError("prompt contains an unsupported value");
  }
  if (prompts.includes("none") && prompts.length > 1) {
    throw validationError("prompt none cannot be combined with other values");
  }
  return prompts as AuthorizationPrompt[];
}

export function parseOptionalList(
  value: string | undefined,
  field: string
): string[] {
  return splitSpaceSeparated(value, field, 20);
}

export function parseMaxAge(value: string | undefined): number | null {
  if (value === undefined) return null;
  if (!/^\d+$/.test(value)) {
    throw validationError("max_age must be a non-negative integer");
  }
  const seconds = Number(value);
  if (!Number.isSafeInteger(seconds)) {
    throw validationError("max_age is too large");
  }
  return seconds;
}

export function requiredAssuranceLevel(
  acrValues: readonly string[]
): SessionAssuranceLevel | null {
  return acrValues.includes("urn:own-auth:aal2") || acrValues.includes("aal2")
    ? "aal2"
    : acrValues.includes("urn:own-auth:aal1") || acrValues.includes("aal1")
      ? "aal1"
      : null;
}

export function assuranceLevelAcr(level: SessionAssuranceLevel): string {
  return `urn:own-auth:${level}`;
}

export function epochSeconds(value: Date): number {
  return Math.floor(value.getTime() / 1000);
}

export function assertCodeChallenge(
  challenge: string | undefined,
  method: string | undefined
): string {
  if (!challenge || !codeChallengePattern.test(challenge) || method !== "S256") {
    throw validationError("PKCE with code_challenge_method S256 is required");
  }
  return challenge;
}

export async function calculateCodeChallenge(verifier: string): Promise<string> {
  if (!codeVerifierPattern.test(verifier)) {
    throw validationError("code_verifier is invalid");
  }
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier)
  );
  return encodeBase64Url(new Uint8Array(digest));
}

export async function encryptAuthorizationRequest(
  ctx: AuthEngineContext,
  interactionId: string,
  authorizationClientId: string,
  request: StoredAuthorizationRequest
) {
  return requireEncryptionKeyRing(ctx.encryption, "OAuth/OIDC authorization server").encrypt(
    JSON.stringify(request),
    "authorization-request",
    {
      authorizationClientId,
      interactionId,
      recordType: "authorization_request"
    }
  );
}

export async function decryptAuthorizationRequest(
  ctx: AuthEngineContext,
  input: {
    id: string;
    authorizationClientId: string;
    requestCiphertext: string;
    requestNonce: string;
    encryptionKeyId: string;
  }
): Promise<StoredAuthorizationRequest> {
  const decrypted = await requireEncryptionKeyRing(
    ctx.encryption,
    "OAuth/OIDC authorization server"
  ).decrypt(
    {
      ciphertext: input.requestCiphertext,
      nonce: input.requestNonce,
      encryptionKeyId: input.encryptionKeyId
    },
    "authorization-request",
    {
      authorizationClientId: input.authorizationClientId,
      interactionId: input.id,
      recordType: "authorization_request"
    }
  );
  return JSON.parse(decrypted.plaintext) as StoredAuthorizationRequest;
}

export async function encryptAuthorizationNonce(
  ctx: AuthEngineContext,
  codeId: string,
  authorizationClientId: string,
  nonce: string
) {
  return requireEncryptionKeyRing(ctx.encryption, "OAuth/OIDC authorization server").encrypt(
    nonce,
    "authorization-request",
    {
      authorizationClientId,
      authorizationCodeId: codeId,
      recordType: "oidc_nonce"
    }
  );
}

export async function decryptAuthorizationNonce(
  ctx: AuthEngineContext,
  input: {
    id: string;
    authorizationClientId: string;
    nonceCiphertext: string;
    nonceNonce: string;
    encryptionKeyId: string;
  }
): Promise<string> {
  const result = await requireEncryptionKeyRing(
    ctx.encryption,
    "OAuth/OIDC authorization server"
  ).decrypt(
    {
      ciphertext: input.nonceCiphertext,
      nonce: input.nonceNonce,
      encryptionKeyId: input.encryptionKeyId
    },
    "authorization-request",
    {
      authorizationClientId: input.authorizationClientId,
      authorizationCodeId: input.id,
      recordType: "oidc_nonce"
    }
  );
  return result.plaintext;
}

export function authorizationServerUrl(
  config: AuthorizationServerRuntimeConfig,
  path: string
): string {
  return new URL(path, config.issuer).toString();
}

export function authorizationRedirectUrl(
  redirectUri: string,
  values: Record<string, string | null>
): string {
  const url = new URL(redirectUri);
  for (const [name, value] of Object.entries(values)) {
    if (value !== null) url.searchParams.set(name, value);
  }
  return url.toString();
}

function splitSpaceSeparated(
  value: string | undefined,
  field: string,
  maximumItems: number
): string[] {
  if (value === undefined || !value.trim()) return [];
  if (value.length > 4_096) {
    throw validationError(`${field} is too long`);
  }
  const parts = value.trim().split(/\s+/);
  if (parts.length > maximumItems || new Set(parts).size !== parts.length) {
    throw validationError(`${field} contains too many or duplicate values`);
  }
  return parts;
}

function validateScopeSet(
  config: AuthorizationServerRuntimeConfig,
  scopes: readonly string[],
  field: string
): void {
  if (
    scopes.some(
      (scope) =>
        typeof scope !== "string" ||
        !scopeNamePattern.test(scope) ||
        /\s/.test(scope) ||
        !config.scopes.has(scope)
    )
  ) {
    throw validationError(`${field} contains an unknown or invalid scope`);
  }
}

function validationError(message: string): AuthError {
  return new AuthError("validation_error", message, 400);
}

function createPrefixedToken(prefix: string, randomByteLength: number): string {
  return `${prefix}${randomBase64Url(randomByteLength)}`;
}
