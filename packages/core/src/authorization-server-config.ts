import {
  AuthorizationServerSigner
} from "./authorization-server-signing.js";
import type {
  AuthorizationScopeDefinition,
  AuthorizationServerOptions
} from "./authorization-server-types.js";
import { isLocalHostname, parseAbsoluteUrl } from "./url-security.js";

const minute = 60 * 1000;
const hour = 60 * minute;
const day = 24 * hour;
const scopePattern = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

const builtInScopes = {
  openid: {
    label: "Sign you in",
    description: "Identify your account to this application."
  },
  profile: {
    label: "View your profile",
    description: "Read your name and profile image."
  },
  email: {
    label: "View your email address",
    description: "Read your email address and verification status."
  },
  phone: {
    label: "View your phone number",
    description: "Read your phone number and verification status."
  },
  offline_access: {
    label: "Stay connected",
    description: "Keep access after you close the application."
  }
} as const satisfies Record<string, AuthorizationScopeDefinition>;

export interface AuthorizationServerRuntimeConfig {
  issuer: string;
  interactionUrl: string;
  scopes: ReadonlyMap<string, Readonly<AuthorizationScopeDefinition>>;
  interactionTtlMs: number;
  authorizationCodeTtlMs: number;
  accessTokenTtlMs: number;
  refreshTokenTtlMs: number;
  resourceIntrospectionRequestsPerMinute: number;
  failedIntrospectionAttemptsPerMinute: number;
  dpop: Readonly<{
    proofTtlMs: number;
    clockSkewMs: number;
  }> | null;
  deviceAuthorization: Readonly<{
    verificationUrl: string;
    ttlMs: number;
    pollingIntervalSeconds: number;
  }> | null;
  signer: AuthorizationServerSigner;
}

export function normalizeAuthorizationServerOptions(
  options: AuthorizationServerOptions | undefined
): AuthorizationServerRuntimeConfig | null {
  if (!options) return null;

  const issuer = normalizeIssuer(options.issuer);
  const interactionUrl = normalizeAuthorizationPageUrl(
    options.interactionUrl,
    issuer,
    "authorizationServer.interactionUrl"
  );
  const scopes = normalizeScopes(options.scopes);
  return Object.freeze({
    issuer,
    interactionUrl,
    scopes,
    interactionTtlMs: positiveInteger(
      options.interactionTtlMs ?? 10 * minute,
      "authorizationServer.interactionTtlMs"
    ),
    authorizationCodeTtlMs: positiveInteger(
      options.authorizationCodeTtlMs ?? 5 * minute,
      "authorizationServer.authorizationCodeTtlMs"
    ),
    accessTokenTtlMs: positiveInteger(
      options.accessTokenTtlMs ?? hour,
      "authorizationServer.accessTokenTtlMs"
    ),
    refreshTokenTtlMs: positiveInteger(
      options.refreshTokenTtlMs ?? 30 * day,
      "authorizationServer.refreshTokenTtlMs"
    ),
    resourceIntrospectionRequestsPerMinute: positiveInteger(
      options.resourceIntrospectionRequestsPerMinute ?? 6_000,
      "authorizationServer.resourceIntrospectionRequestsPerMinute"
    ),
    failedIntrospectionAttemptsPerMinute: positiveInteger(
      options.failedIntrospectionAttemptsPerMinute ?? 30,
      "authorizationServer.failedIntrospectionAttemptsPerMinute"
    ),
    dpop: options.dpop
      ? Object.freeze({
          proofTtlMs: positiveInteger(
            options.dpop.proofTtlMs ?? 5 * minute,
            "authorizationServer.dpop.proofTtlMs"
          ),
          clockSkewMs: nonNegativeInteger(
            options.dpop.clockSkewMs ?? minute,
            "authorizationServer.dpop.clockSkewMs"
          )
        })
      : null,
    deviceAuthorization: options.deviceAuthorization
      ? Object.freeze({
          verificationUrl: normalizeAuthorizationPageUrl(
            options.deviceAuthorization.verificationUrl,
            issuer,
            "authorizationServer.deviceAuthorization.verificationUrl"
          ),
          ttlMs: positiveInteger(
            options.deviceAuthorization.ttlMs ?? 10 * minute,
            "authorizationServer.deviceAuthorization.ttlMs"
          ),
          pollingIntervalSeconds: positiveInteger(
            options.deviceAuthorization.pollingIntervalSeconds ?? 5,
            "authorizationServer.deviceAuthorization.pollingIntervalSeconds"
          )
        })
      : null,
    signer: new AuthorizationServerSigner({
      current: options.signingKeys.current,
      previous: [...(options.signingKeys.previous ?? [])]
    })
  });
}

export function scopeDetails(
  config: AuthorizationServerRuntimeConfig,
  scopes: readonly string[]
): Array<{ name: string; label: string; description: string | null }> {
  return scopes.map((name) => {
    const definition = config.scopes.get(name);
    if (!definition) {
      throw new Error(`Unknown configured authorization scope: ${name}`);
    }
    return {
      name,
      label: definition.label,
      description: definition.description ?? null
    };
  });
}

function normalizeIssuer(value: string): string {
  const parsed = parseAbsoluteUrl(value.trim());
  if (
    !parsed ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash ||
    (parsed.protocol !== "https:" &&
      !(
        process.env.NODE_ENV !== "production" &&
        parsed.protocol === "http:" &&
        isLocalHostname(parsed.hostname)
      ))
  ) {
    throw new Error(
      "authorizationServer.issuer must be an HTTPS origin without a path, query, or fragment"
    );
  }
  return parsed.origin;
}

function normalizeAuthorizationPageUrl(
  value: string,
  issuer: string,
  field: string
): string {
  let parsed: URL;
  try {
    parsed = new URL(value, issuer);
  } catch {
    throw new Error(`${field} must be a valid URL`);
  }
  if (
    parsed.username ||
    parsed.password ||
    parsed.hash ||
    (parsed.protocol !== "https:" &&
      !(
        process.env.NODE_ENV !== "production" &&
        parsed.protocol === "http:" &&
        isLocalHostname(parsed.hostname)
      ))
  ) {
    throw new Error(`${field} must use HTTPS or a local development URL`);
  }
  return parsed.toString();
}

function normalizeScopes(
  customScopes: AuthorizationServerOptions["scopes"]
): ReadonlyMap<string, Readonly<AuthorizationScopeDefinition>> {
  const scopes = new Map<string, Readonly<AuthorizationScopeDefinition>>();
  for (const [name, definition] of Object.entries(builtInScopes)) {
    scopes.set(name, Object.freeze({ ...definition }));
  }
  for (const [name, definition] of Object.entries(customScopes ?? {})) {
    if (!scopePattern.test(name) || /\s/.test(name)) {
      throw new Error(`Invalid authorization scope name: ${name}`);
    }
    if (scopes.has(name)) {
      throw new Error(`Authorization scope is already defined: ${name}`);
    }
    const label = definition.label.trim();
    const description = definition.description?.trim();
    if (!label || label.length > 120) {
      throw new Error(
        `Authorization scope ${name} requires a label of at most 120 characters`
      );
    }
    if (description && description.length > 500) {
      throw new Error(
        `Authorization scope ${name} description must be at most 500 characters`
      );
    }
    scopes.set(name, Object.freeze({
      label,
      description: description || undefined
    }));
  }
  return scopes;
}

function positiveInteger(value: number, option: string): number {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${option} must be a positive integer`);
  }
  return value;
}

function nonNegativeInteger(value: number, option: string): number {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`${option} must be a non-negative integer`);
  }
  return value;
}
