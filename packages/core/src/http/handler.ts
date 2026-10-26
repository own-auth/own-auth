import type { OwnAuth } from "../auth-engine.js";
import { isAuthError } from "../errors.js";
import type { RequestContext } from "../types.js";
import { OAuthCallbackError } from "../oauth-types.js";
import { SamlCallbackError } from "../saml-callback-error.js";
import { OwnAuthPluginError } from "../plugin-definition.js";
import {
  getOwnAuthEndpointsForPath,
  type OwnAuthErrorPayload,
  type OwnAuthHttpErrorCode
} from "./contract.js";
import {
  clearMfaChallengeCookie,
  clearOAuthBrowserCookie,
  clearSessionCookie,
  createMfaChallengeCookie,
  createOAuthBrowserCookie,
  createSessionCookie,
  readMfaChallengeToken,
  readOAuthBrowserToken,
  readSessionToken,
  type OwnAuthMfaCookieOptions,
  type OwnAuthSessionCookieOptions
} from "./cookies.js";
import { assertCsrfSafe } from "./csrf.js";
import { OwnAuthHttpError } from "./errors.js";
import { executeEndpoint, type EndpointExecution } from "./execution.js";
import { createOAuthCallbackResponse } from "./oauth-response.js";
import { createSamlCallbackResponse } from "./saml-response.js";
import { pluginInputContract, readEndpointInput, readLimitedBody } from "./request-input.js";
import { getOwnAuthRoutePath, normalizeOwnAuthBasePath } from "./routing.js";
import { traceHttpEndpoint } from "../telemetry.js";
import { CloudChallengeError } from "../cloud-errors.js";
import type { CloudChallengeResponsePayload } from "../cloud-types.js";

export interface OwnAuthHandlerOptions {
  basePath?: string;
  cookie?: OwnAuthSessionCookieOptions;
  mfaCookie?: OwnAuthMfaCookieOptions;
  trustedOrigins?: readonly string[];
  maxRequestBodyBytes?: number;
  getRequestContext?: (request: Request) => RequestContext | Promise<RequestContext>;
  onError?: (error: unknown, request: Request) => void | Promise<void>;
}

export type OwnAuthHandler = (request: Request) => Promise<Response>;

export function createOwnAuthHandler(
  auth: OwnAuth<string, string>,
  options: OwnAuthHandlerOptions = {}
): OwnAuthHandler {
  const basePath = normalizeOwnAuthBasePath(options.basePath ?? "/api/auth");
  const maxRequestBodyBytes = options.maxRequestBodyBytes ?? 64 * 1024;
  if (!Number.isInteger(maxRequestBodyBytes) || maxRequestBodyBytes < 1) {
    throw new Error("maxRequestBodyBytes must be a positive integer");
  }

  return async (request) => {
    const requestUrl = new URL(request.url);
    if (auth.cloud.webhookPath === requestUrl.pathname) {
      return handleCloudWebhook(auth, request, maxRequestBodyBytes);
    }
    const routePath = getOwnAuthRoutePath(requestUrl.pathname, basePath);
    if (!routePath) return errorResponse("not_found", "Auth endpoint not found", 404);

    const candidates = getOwnAuthEndpointsForPath(routePath).filter(
      (candidate) => endpointIsEnabled(auth, candidate.feature)
    );
    const endpoint = candidates.find((candidate) => candidate.method === request.method);
    const pluginEndpoint = endpoint ? null : auth.findPluginEndpoint(routePath, request.method);
    if (!endpoint) {
      if (pluginEndpoint) {
        return traceHttpEndpoint(
          {
            endpointId: `plugin.${pluginEndpoint.plugin.id}.${pluginEndpoint.endpoint.id}`,
            method: request.method,
            route: `${basePath}${pluginEndpoint.path}`
          },
          () => handlePluginEndpoint(auth, pluginEndpoint, request, requestUrl, options)
        );
      }
      const pluginMethods = auth.getPluginEndpointMethods(routePath);
      if (candidates.length === 0 && pluginMethods.length === 0) {
        return errorResponse("not_found", "Auth endpoint not found", 404);
      }
      return errorResponse("method_not_allowed", "Method not allowed", 405, {
        allow: [...candidates.map((candidate) => candidate.method), ...pluginMethods].join(", ")
      });
    }

    return traceHttpEndpoint(
      {
        endpointId: endpoint.id,
        method: request.method,
        route: `${basePath}${endpoint.path}`
      },
      async () => {
        const sessionCredential = readSessionToken(request, options.cookie);
        let oauthState: string | null = null;
        try {
          if (endpoint.csrf !== "oauth_state" && endpoint.csrf !== "saml_state") {
            assertCsrfSafe(
              request,
              sessionCredential.source === "cookie",
              options.trustedOrigins ?? []
            );
          }
          const input = await readEndpointInput(
            request,
            endpoint,
            endpoint.requestTransport === "form"
              ? Math.min(maxRequestBodyBytes, 64 * 1024)
              : maxRequestBodyBytes
          );
          if (endpoint.responseKind === "oauth_callback" && typeof input?.state === "string") {
            oauthState = input.state;
          }
          const providedContext = options.getRequestContext
            ? await options.getRequestContext(request)
            : defaultRequestContext(request);
          const context = cloudRequestContext(request, providedContext);
          const execution = await executeEndpoint(
            auth,
            endpoint.id,
            input,
            sessionCredential.token,
            readMfaChallengeToken(request, options.mfaCookie),
            context,
            oauthState ? readOAuthBrowserToken(request, oauthState) : null
          );
          const headers = responseHeaders();
          applyCookies(headers, execution, requestUrl, options);

          if (endpoint.responseKind === "oauth_callback") {
            if (oauthState) headers.append("set-cookie", clearOAuthBrowserCookie(oauthState, requestUrl));
            return createOAuthCallbackResponse(execution, requestUrl, headers);
          }
          if (endpoint.responseKind === "saml_callback") {
            return createSamlCallbackResponse(execution, requestUrl, headers);
          }
          if (endpoint.responseKind === "xml") {
            headers.set("content-type", "application/samlmetadata+xml; charset=utf-8");
            return new Response(execution.body as string, { status: 200, headers });
          }
          return new Response(JSON.stringify(execution.body), { status: 200, headers });
        } catch (error) {
          const response = await handleRequestError(
            error,
            request,
            requestUrl,
            options,
            endpoint.responseKind === "oauth_callback",
            endpoint.responseKind === "saml_callback"
          );
          if (oauthState && error instanceof OAuthCallbackError) {
            response.headers.append("set-cookie", clearOAuthBrowserCookie(oauthState, requestUrl));
          }
          return response;
        }
      }
    );
  };
}

function endpointIsEnabled(
  auth: OwnAuth<string, string>,
  feature: "administration" | "saml" | undefined
): boolean {
  if (feature === "administration") return auth.isAdministrationConfigured();
  if (feature === "saml") return auth.saml.isConfigured();
  return true;
}

async function handlePluginEndpoint(
  auth: OwnAuth<string, string>,
  registered: NonNullable<ReturnType<OwnAuth<string, string>["findPluginEndpoint"]>>,
  request: Request,
  requestUrl: URL,
  options: OwnAuthHandlerOptions
): Promise<Response> {
  const credential = readSessionToken(request, options.cookie);
  try {
    assertCsrfSafe(
      request,
      credential.source === "cookie",
      pluginTrustedOrigins(registered, options)
    );
    const contract = pluginInputContract(registered.endpoint.input, registered.endpoint.method);
    const input = await readEndpointInput(
      request,
      contract,
      options.maxRequestBodyBytes ?? 64 * 1024
    );
    const providedContext = options.getRequestContext
      ? await options.getRequestContext(request)
      : defaultRequestContext(request);
    const context = cloudRequestContext(request, providedContext);
    const body = await auth.executePluginEndpoint(
      registered,
      input,
      credential.token,
      context
    );
    const headers = responseHeaders();
    headers.set("x-own-auth-plugin-fingerprint", auth.pluginContractFingerprint);
    return new Response(JSON.stringify(body), { status: 200, headers });
  } catch (error) {
    return handleRequestError(error, request, requestUrl, options, false);
  }
}

async function handleRequestError(
  error: unknown,
  request: Request,
  requestUrl: URL,
  options: OwnAuthHandlerOptions,
  oauthCallback: boolean,
  samlCallback = false
): Promise<Response> {
  if (error instanceof CloudChallengeError) {
    const payload: CloudChallengeResponsePayload = {
      error: { code: "cloud_challenge_required", message: error.safeMessage },
      challenge: error.challenge
    };
    return new Response(JSON.stringify(payload), {
      status: error.statusCode,
      headers: responseHeaders()
    });
  }
  if (oauthCallback && error instanceof OAuthCallbackError) {
    if (error.statusCode >= 500) await reportError(options.onError, error, request);
    return createOAuthCallbackResponse(
      {
        body: {
          status: "failure",
          error: { code: error.code, message: error.safeMessage }
        },
        oauthCallback: error.callback
      },
      requestUrl,
      responseHeaders()
    );
  }

  if (samlCallback && error instanceof SamlCallbackError) {
    await reportError(options.onError, error, request);
    const code = error.code === "saml_signature_algorithm_unsupported"
      ? "saml_response_invalid"
      : error.code;
    return createSamlCallbackResponse(
      {
        body: {
          status: "failure",
          error: { code, message: "SAML sign-in failed" }
        },
        samlCallback: { destination: error.destination }
      },
      requestUrl,
      responseHeaders()
    );
  }

  const known = knownHttpError(error);
  if (known) {
    if (known.status >= 500) await reportError(options.onError, error, request);
    return errorResponse(known.code, known.message, known.status);
  }

  await reportError(options.onError, error, request);
  return errorResponse("internal_error", "Authentication request failed", 500);
}

function knownHttpError(error: unknown): {
  code: OwnAuthHttpErrorCode;
  message: string;
  status: number;
} | null {
  if (isAuthError(error)) {
    return { code: error.code, message: error.safeMessage, status: error.statusCode };
  }
  if (error instanceof OwnAuthPluginError) {
    return { code: error.code, message: error.safeMessage, status: error.statusCode };
  }
  if (error instanceof OwnAuthHttpError) {
    return { code: error.code, message: error.message, status: error.statusCode };
  }
  return null;
}

function pluginTrustedOrigins(
  registered: NonNullable<ReturnType<OwnAuth<string, string>["findPluginEndpoint"]>>,
  options: OwnAuthHandlerOptions
): string[] {
  return [...new Set([
    ...(options.trustedOrigins ?? []),
    ...(registered.plugin.trustedOrigins ?? [])
  ])];
}

function applyCookies(
  headers: Headers,
  execution: EndpointExecution,
  requestUrl: URL,
  options: OwnAuthHandlerOptions
): void {
  if (execution.setOAuthBrowser) {
    headers.append("set-cookie", createOAuthBrowserCookie(
      execution.setOAuthBrowser.state,
      execution.setOAuthBrowser.token,
      execution.setOAuthBrowser.expiresAt,
      requestUrl
    ));
  }
  if (execution.setSession) {
    headers.append("set-cookie", createSessionCookie(
      execution.setSession.token,
      execution.setSession.expiresAt,
      requestUrl,
      options.cookie
    ));
  } else if (execution.clearSession) {
    headers.append("set-cookie", clearSessionCookie(requestUrl, options.cookie));
  }

  if (execution.setMfaChallenge) {
    headers.append("set-cookie", createMfaChallengeCookie(
      execution.setMfaChallenge.token,
      execution.setMfaChallenge.expiresAt,
      requestUrl,
      options.mfaCookie
    ));
  } else if (execution.clearMfaChallenge) {
    headers.append("set-cookie", clearMfaChallengeCookie(requestUrl, options.mfaCookie));
  }
}

function defaultRequestContext(request: Request): RequestContext {
  return { userAgent: request.headers.get("user-agent") ?? undefined };
}

function cloudRequestContext(request: Request, context: RequestContext): RequestContext {
  return {
    ...context,
    cloudChallengeResponse:
      request.headers.get("x-ownauth-challenge-response") ?? undefined,
    cloudAppeal: request.headers.get("x-ownauth-appeal") === "1",
    path: new URL(request.url).pathname
  };
}

async function handleCloudWebhook(
  auth: OwnAuth<string, string>,
  request: Request,
  maxBodyBytes: number
): Promise<Response> {
  if (request.method !== "POST") {
    return errorResponse("method_not_allowed", "Method not allowed", 405, { allow: "POST" });
  }
  if (request.headers.get("content-type")?.split(";", 1)[0]?.trim() !== "application/json") {
    return errorResponse("invalid_request", "content-type must be application/json", 415);
  }
  try {
    const body = await readLimitedBody(request, maxBodyBytes);
    const result = await auth.cloud.handleCommand(request, body);
    const headers = responseHeaders();
    if (result.retryAfter !== undefined) headers.set("retry-after", String(result.retryAfter));
    return new Response(JSON.stringify(result.body), { status: result.status, headers });
  } catch (error) {
    const known = knownHttpError(error);
    if (known) return errorResponse(known.code, known.message, known.status);
    return errorResponse("internal_error", "Cloud command failed", 500);
  }
}

function responseHeaders(): Headers {
  return new Headers({
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff"
  });
}

function errorResponse(
  code: OwnAuthHttpErrorCode,
  message: string,
  status: number,
  extraHeaders: Record<string, string> = {}
): Response {
  const payload: OwnAuthErrorPayload = { error: { code, message } };
  const headers = responseHeaders();
  for (const [name, value] of Object.entries(extraHeaders)) headers.set(name, value);
  return new Response(JSON.stringify(payload), { status, headers });
}

async function reportError(
  onError: OwnAuthHandlerOptions["onError"],
  error: unknown,
  request: Request
): Promise<void> {
  if (!onError) return;
  try {
    await onError(error, request);
  } catch {
    // Error reporting must not replace the original auth response.
  }
}
