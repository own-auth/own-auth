import { OwnAuthHttpError } from "./errors.js";
import { isLocalHostname } from "../url-security.js";

export type SameSitePolicy = "lax" | "strict" | "none";

export interface OwnAuthSessionCookieOptions {
  name?: string;
  path?: string;
  domain?: string;
  sameSite?: SameSitePolicy;
  secure?: boolean;
}

export interface OwnAuthMfaCookieOptions extends OwnAuthSessionCookieOptions {}

export const defaultSessionCookieName = "own_auth_session";
export const defaultMfaCookieName = "own_auth_mfa";
const oauthStatePattern = /^[a-f0-9]{64}$/;

export function createOAuthBrowserCookie(
  state: string,
  browserBindingToken: string,
  expiresAt: Date,
  requestUrl: URL
): string {
  return serializeCookie(browserBindingToken, expiresAt, requestUrl, oauthCookieOptions(state, requestUrl));
}

export function clearOAuthBrowserCookie(state: string, requestUrl: URL): string {
  return serializeCookie("", new Date(0), requestUrl, oauthCookieOptions(state, requestUrl), 0);
}

export function readOAuthBrowserToken(request: Request, state: string): string | null {
  if (!oauthStatePattern.test(state)) return null;
  return readCookie(request, oauthCookieOptions(state, new URL(request.url)).name);
}

function oauthCookieOptions(state: string, requestUrl: URL): OwnAuthSessionCookieOptions & { name: string } {
  if (!oauthStatePattern.test(state)) {
    throw invalidCookieConfiguration("Invalid OAuth state");
  }
  const secure = resolveSecureCookie(requestUrl);
  return {
    name: `${secure ? "__Host-" : ""}own_auth_oauth_${state}`,
    path: "/",
    secure,
    // Apple returns through a POST from the provider's origin.
    sameSite: secure ? "none" : "lax"
  };
}

export function readSessionToken(
  request: Request,
  options: OwnAuthSessionCookieOptions = {}
): { token: string | null; source: "bearer" | "cookie" | null } {
  const authorization = request.headers.get("authorization");
  const [scheme, tokenValue, extra] = authorization?.trim().split(/\s+/) ?? [];
  if (scheme?.toLowerCase() === "bearer" && !extra) {
    const token = tokenValue?.trim() ?? "";
    if (token) {
      return { token, source: "bearer" };
    }
  }

  const cookies = parseCookieHeader(request.headers.get("cookie"));
  const token = cookies.get(options.name ?? defaultSessionCookieName) ?? null;
  return { token, source: token ? "cookie" : null };
}

export function createSessionCookie(
  token: string,
  expiresAt: Date,
  requestUrl: URL,
  options: OwnAuthSessionCookieOptions = {}
): string {
  return serializeCookie(token, expiresAt, requestUrl, options);
}

export function clearSessionCookie(
  requestUrl: URL,
  options: OwnAuthSessionCookieOptions = {}
): string {
  return serializeCookie("", new Date(0), requestUrl, options, 0);
}

export function readMfaChallengeToken(
  request: Request,
  options: OwnAuthMfaCookieOptions = {}
): string | null {
  return readCookie(request, options.name ?? defaultMfaCookieName);
}

export function createMfaChallengeCookie(
  token: string,
  expiresAt: Date,
  requestUrl: URL,
  options: OwnAuthMfaCookieOptions = {}
): string {
  return serializeCookie(
    token,
    expiresAt,
    requestUrl,
    { ...options, name: options.name ?? defaultMfaCookieName }
  );
}

export function clearMfaChallengeCookie(
  requestUrl: URL,
  options: OwnAuthMfaCookieOptions = {}
): string {
  return serializeCookie(
    "",
    new Date(0),
    requestUrl,
    { ...options, name: options.name ?? defaultMfaCookieName },
    0
  );
}

function serializeCookie(
  value: string,
  expiresAt: Date,
  requestUrl: URL,
  options: OwnAuthSessionCookieOptions,
  maxAge = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000))
): string {
  const secure = resolveSecureCookie(requestUrl, options.secure);
  const sameSite = options.sameSite ?? "lax";
  const name = options.name ?? defaultSessionCookieName;
  const path = options.path ?? "/";
  assertCookieConfiguration(name, path, options.domain);
  if (sameSite === "none" && !secure) {
    throw new OwnAuthHttpError(
      "internal_error",
      "SameSite=None session cookies require HTTPS",
      500
    );
  }

  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    `Path=${path}`,
    `Expires=${expiresAt.toUTCString()}`,
    `Max-Age=${maxAge}`,
    "HttpOnly",
    `SameSite=${capitalize(sameSite)}`
  ];

  if (secure) {
    parts.push("Secure");
  }
  if (options.domain) {
    parts.push(`Domain=${options.domain}`);
  }

  return parts.join("; ");
}

function assertCookieConfiguration(
  name: string,
  path: string,
  domain: string | undefined
): void {
  if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name)) {
    throw invalidCookieConfiguration("Invalid session cookie name");
  }
  if (!path.startsWith("/") || /[;\r\n]/.test(path)) {
    throw invalidCookieConfiguration("Invalid session cookie path");
  }
  if (domain && !/^\.?[A-Za-z0-9.-]+$/.test(domain)) {
    throw invalidCookieConfiguration("Invalid session cookie domain");
  }
}

function invalidCookieConfiguration(message: string): OwnAuthHttpError {
  return new OwnAuthHttpError("internal_error", message, 500);
}

function resolveSecureCookie(requestUrl: URL, configured?: boolean): boolean {
  const local = isLocalHostname(requestUrl.hostname);
  if (configured === false && !local) {
    throw new OwnAuthHttpError(
      "internal_error",
      "Session cookies may only disable Secure on localhost",
      500
    );
  }

  if (configured !== undefined) {
    return configured;
  }
  if (requestUrl.protocol === "https:") {
    return true;
  }
  if (requestUrl.protocol === "http:" && local) {
    return false;
  }

  throw new OwnAuthHttpError(
    "internal_error",
    "Session cookies require HTTPS outside localhost",
    500
  );
}

function readCookie(request: Request, name: string): string | null {
  return parseCookieHeader(request.headers.get("cookie")).get(name) ?? null;
}

function parseCookieHeader(value: string | null): Map<string, string | null> {
  const cookies = new Map<string, string | null>();
  if (!value) {
    return cookies;
  }

  for (const part of value.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 1) {
      continue;
    }

    const name = part.slice(0, separator).trim();
    const encodedValue = part.slice(separator + 1).trim();
    if (cookies.has(name)) {
      cookies.set(name, null);
      continue;
    }
    try {
      cookies.set(name, decodeURIComponent(encodedValue));
    } catch {
      cookies.set(name, encodedValue);
    }
  }

  return cookies;
}

function capitalize(value: string): string {
  return `${value[0]?.toUpperCase() ?? ""}${value.slice(1)}`;
}
