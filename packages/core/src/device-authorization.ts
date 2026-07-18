import {
  createDpopProof,
  type DpopKeyPair
} from "./dpop.js";
import { deviceAuthorizationGrantType } from "./authorization-server-device-types.js";
import { encodeOAuthBasicCredentials } from "./encoding.js";
import { normalizeProtectedResourceUrl } from "./protected-resource-url.js";

export type DeviceFlowClientAuthenticationMethod =
  | "none"
  | "client_secret_basic"
  | "client_secret_post";

export interface DeviceFlowClientOptions {
  deviceAuthorizationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret?: string;
  clientAuthenticationMethod?: DeviceFlowClientAuthenticationMethod;
  dpopKeyPair?: DpopKeyPair;
  fetch?: typeof globalThis.fetch;
}

export interface StartDeviceFlowInput {
  scope: string | readonly string[];
  resource?: string;
  signal?: AbortSignal;
}

export interface DeviceFlowAuthorization {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete?: string;
  scopes: string[];
  resource?: string;
  expiresAt: Date;
  intervalSeconds: number;
}

export interface PollDeviceFlowInput {
  authorization: DeviceFlowAuthorization;
  signal?: AbortSignal;
}

export interface DeviceFlowTokenResponse {
  tokenType: "Bearer" | "DPoP";
  accessToken: string;
  expiresIn: number;
  refreshToken?: string;
  idToken?: string;
  scopes: string[];
}

export type DeviceFlowClientErrorCode =
  | "access_denied"
  | "expired_token"
  | "invalid_response"
  | "network_error"
  | "protocol_error";

export class DeviceFlowClientError extends Error {
  constructor(
    readonly code: DeviceFlowClientErrorCode,
    message: string,
    readonly protocolError?: string
  ) {
    super(message);
    this.name = "DeviceFlowClientError";
  }
}

export interface DeviceFlowClient {
  start(input: StartDeviceFlowInput): Promise<DeviceFlowAuthorization>;
  poll(input: PollDeviceFlowInput): Promise<DeviceFlowTokenResponse>;
}

export function createDeviceFlowClient(
  options: DeviceFlowClientOptions
): DeviceFlowClient {
  const deviceEndpoint = requiredHttpUrl(
    options.deviceAuthorizationEndpoint,
    "deviceAuthorizationEndpoint"
  );
  const tokenEndpoint = requiredHttpUrl(options.tokenEndpoint, "tokenEndpoint");
  const clientId = requiredText(options.clientId, "clientId");
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("A Fetch API implementation is required");
  }
  const authenticationMethod = options.clientAuthenticationMethod ??
    (options.clientSecret ? "client_secret_basic" : "none");
  validateClientAuthentication(authenticationMethod, options.clientSecret);

  return {
    async start(input) {
      const form = clientForm(clientId, options.clientSecret, authenticationMethod);
      const scopes = normalizeScopes(input.scope);
      const resource = input.resource
        ? requiredHttpUrl(input.resource, "resource")
        : undefined;
      form.set("scope", scopes.join(" "));
      if (resource) form.set("resource", resource);
      if (options.dpopKeyPair) {
        form.set("dpop_jkt", options.dpopKeyPair.jwkThumbprint);
      }
      const payload = await postForm(
        deviceEndpoint,
        form,
        authenticationHeaders(clientId, options.clientSecret, authenticationMethod),
        input.signal
      );
      return parseDeviceAuthorization(payload, scopes, resource);
    },

    async poll(input) {
      let intervalSeconds = positiveInteger(
        input.authorization.intervalSeconds,
        "authorization.intervalSeconds"
      );
      let networkFailures = 0;
      while (Date.now() < input.authorization.expiresAt.getTime()) {
        await delay(intervalSeconds * 1000, input.signal);
        if (Date.now() >= input.authorization.expiresAt.getTime()) break;
        const form = clientForm(clientId, options.clientSecret, authenticationMethod);
        form.set("grant_type", deviceAuthorizationGrantType);
        form.set("device_code", input.authorization.deviceCode);
        if (input.authorization.resource) {
          form.set("resource", input.authorization.resource);
        }
        const headers = authenticationHeaders(
          clientId,
          options.clientSecret,
          authenticationMethod
        );
        if (options.dpopKeyPair) {
          headers.set("dpop", await createDpopProof({
            keyPair: options.dpopKeyPair,
            method: "POST",
            url: tokenEndpoint
          }));
        }
        let response: Response;
        try {
          response = await fetchImpl(tokenEndpoint, {
            method: "POST",
            headers,
            body: form.toString(),
            signal: input.signal
          });
          networkFailures = 0;
        } catch (error) {
          if (input.signal?.aborted) throw input.signal.reason ?? error;
          networkFailures += 1;
          intervalSeconds = Math.min(
            60,
            Math.max(intervalSeconds, 2 ** Math.min(networkFailures, 5))
          );
          continue;
        }
        const payload = await readJson(response);
        if (response.ok) {
          return parseTokenResponse(payload, input.authorization.scopes);
        }
        const protocolError = stringField(payload, "error");
        if (protocolError === "authorization_pending") continue;
        if (protocolError === "slow_down") {
          intervalSeconds += 5;
          continue;
        }
        if (protocolError === "access_denied") {
          throw new DeviceFlowClientError("access_denied", "Device authorization was denied");
        }
        if (protocolError === "expired_token") {
          throw new DeviceFlowClientError("expired_token", "The device code has expired");
        }
        throw new DeviceFlowClientError(
          "protocol_error",
          stringField(payload, "error_description") ?? "Device token exchange failed",
          protocolError ?? undefined
        );
      }
      throw new DeviceFlowClientError("expired_token", "The device code has expired");
    }
  };

  async function postForm(
    url: string,
    form: URLSearchParams,
    headers: Headers,
    signal?: AbortSignal
  ): Promise<Record<string, unknown>> {
    let response: Response;
    try {
      response = await fetchImpl(url, {
        method: "POST",
        headers,
        body: form.toString(),
        signal
      });
    } catch (error) {
      if (signal?.aborted) throw signal.reason ?? error;
      throw new DeviceFlowClientError("network_error", "Device authorization is unavailable");
    }
    const payload = await readJson(response);
    if (!response.ok) {
      throw new DeviceFlowClientError(
        "protocol_error",
        stringField(payload, "error_description") ?? "Device authorization failed",
        stringField(payload, "error") ?? undefined
      );
    }
    return payload;
  }
}

function parseDeviceAuthorization(
  payload: Record<string, unknown>,
  scopes: string[],
  resource: string | undefined
): DeviceFlowAuthorization {
  const deviceCode = stringField(payload, "device_code");
  const userCode = stringField(payload, "user_code");
  const verificationUri = stringField(payload, "verification_uri");
  const verificationUriComplete = stringField(payload, "verification_uri_complete");
  const expiresIn = integerField(payload, "expires_in");
  const intervalSeconds = integerField(payload, "interval") ?? 5;
  if (
    !deviceCode ||
    !userCode ||
    !verificationUri ||
    expiresIn === null ||
    expiresIn < 1 ||
    intervalSeconds < 1
  ) {
    throw invalidResponse();
  }
  return {
    deviceCode,
    userCode,
    verificationUri: requiredHttpUrl(verificationUri, "verification_uri"),
    ...(verificationUriComplete
      ? {
          verificationUriComplete: requiredHttpUrl(
            verificationUriComplete,
            "verification_uri_complete"
          )
        }
      : {}),
    scopes: [...scopes],
    ...(resource ? { resource } : {}),
    expiresAt: new Date(Date.now() + expiresIn * 1000),
    intervalSeconds
  };
}

function parseTokenResponse(
  payload: Record<string, unknown>,
  requestedScopes: readonly string[]
): DeviceFlowTokenResponse {
  const tokenTypeValue = stringField(payload, "token_type")?.toLowerCase();
  const tokenType = tokenTypeValue === "bearer"
    ? "Bearer"
    : tokenTypeValue === "dpop"
      ? "DPoP"
      : null;
  const accessToken = stringField(payload, "access_token");
  const expiresIn = integerField(payload, "expires_in");
  const scopeValue = stringField(payload, "scope");
  const refreshToken = stringField(payload, "refresh_token");
  const idToken = stringField(payload, "id_token");
  if (
    !tokenType ||
    !accessToken ||
    expiresIn === null ||
    expiresIn < 0
  ) {
    throw invalidResponse();
  }
  let scopes: string[];
  try {
    scopes = scopeValue === null
      ? [...requestedScopes]
      : normalizeScopes(scopeValue);
  } catch {
    throw invalidResponse();
  }
  if (scopes.some((scope) => !requestedScopes.includes(scope))) {
    throw invalidResponse();
  }
  return {
    tokenType,
    accessToken,
    expiresIn,
    scopes,
    ...(refreshToken ? { refreshToken } : {}),
    ...(idToken ? { idToken } : {})
  };
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  try {
    const payload: unknown = await response.json();
    if (payload && typeof payload === "object" && !Array.isArray(payload)) {
      return payload as Record<string, unknown>;
    }
  } catch {
    // Invalid protocol responses are reported without exposing response bodies.
  }
  throw invalidResponse();
}

function clientForm(
  clientId: string,
  clientSecret: string | undefined,
  method: DeviceFlowClientAuthenticationMethod
): URLSearchParams {
  const form = new URLSearchParams();
  if (method !== "client_secret_basic") form.set("client_id", clientId);
  if (method === "client_secret_post") form.set("client_secret", clientSecret!);
  return form;
}

function authenticationHeaders(
  clientId: string,
  clientSecret: string | undefined,
  method: DeviceFlowClientAuthenticationMethod
): Headers {
  const headers = new Headers({
    accept: "application/json",
    "content-type": "application/x-www-form-urlencoded"
  });
  if (method === "client_secret_basic") {
    headers.set("authorization", encodeOAuthBasicCredentials(clientId, clientSecret!));
  }
  return headers;
}

function validateClientAuthentication(
  method: DeviceFlowClientAuthenticationMethod,
  clientSecret: string | undefined
): void {
  if (
    !["none", "client_secret_basic", "client_secret_post"].includes(method) ||
    (method === "none" && clientSecret !== undefined) ||
    (method !== "none" && !clientSecret)
  ) {
    throw new Error("client authentication configuration is invalid");
  }
}

function normalizeScopes(value: string | readonly string[]): string[] {
  const scopes = typeof value === "string"
    ? value.trim().split(/\s+/).filter(Boolean)
    : [...value];
  if (
    scopes.length < 1 ||
    scopes.length > 100 ||
    new Set(scopes).size !== scopes.length ||
    scopes.some((scope) => typeof scope !== "string" || !scope || /\s/.test(scope))
  ) {
    throw new Error("scope must contain unique space-separated values");
  }
  return scopes;
}

function requiredHttpUrl(value: string, field: string): string {
  const normalized = normalizeProtectedResourceUrl(value, true);
  if (!normalized) {
    throw new Error(
      `${field} must be an HTTPS or local development URL without a query or fragment`
    );
  }
  return normalized;
}

function requiredText(value: string, field: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${field} is required`);
  return value;
}

function positiveInteger(value: number, field: string): number {
  if (!Number.isInteger(value) || value < 1) throw new Error(`${field} must be positive`);
  return value;
}

function stringField(payload: Record<string, unknown>, field: string): string | null {
  const value = payload[field];
  return typeof value === "string" ? value : null;
}

function integerField(payload: Record<string, unknown>, field: string): number | null {
  const value = payload[field];
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}

function invalidResponse(): DeviceFlowClientError {
  return new DeviceFlowClientError(
    "invalid_response",
    "The authorization server returned an invalid response"
  );
}

function delay(milliseconds: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const onAbort = () => {
      clearTimeout(timeout);
      reject(signal?.reason);
    };
    const timeout = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, milliseconds);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
