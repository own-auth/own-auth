import type { OwnAuth } from "./auth-engine.js";
import { authorizationServerPaths } from "./authorization-server-constants.js";
import { authorizationRedirectUrl } from "./authorization-server-helpers.js";
import {
  parseAuthorizationRequest,
  readAuthorizationAccessToken,
  readAuthorizationClientCredentials,
  readDpopProofHeader,
  readAuthorizationForm,
  singleAuthorizationParameter
} from "./authorization-server-http-input.js";
import { AuthorizationProtocolError } from "./authorization-server-protocol-error.js";
import type {
  AuthorizationTokenActionInput,
  AuthorizationTokenRequestInput
} from "./authorization-server-types.js";
import { AuthError } from "./errors.js";
import {
  readSessionToken,
  type OwnAuthSessionCookieOptions
} from "./http/cookies.js";
import { OwnAuthHttpError } from "./http/errors.js";
import { traceHttpEndpoint } from "./telemetry.js";
import type { RequestContext } from "./types.js";

export {
  createOwnAuthAuthorizationServerOpenApiDocument
} from "./authorization-server-openapi.js";
export type {
  OwnAuthAuthorizationServerOpenApiDocument,
  OwnAuthAuthorizationServerOpenApiOptions
} from "./authorization-server-openapi.js";

const defaultBodyLimit = 16 * 1024;
const discoveryPaths = new Set([
  "/.well-known/oauth-authorization-server",
  "/.well-known/openid-configuration"
]);

export interface OwnAuthAuthorizationServerHandlerOptions {
  cookie?: OwnAuthSessionCookieOptions;
  maxRequestBodyBytes?: number;
  getRequestContext?: (request: Request) => RequestContext | Promise<RequestContext>;
  onError?: (error: unknown, request: Request) => void | Promise<void>;
}

export type OwnAuthAuthorizationServerHandler = (
  request: Request
) => Promise<Response>;

export function createOwnAuthAuthorizationServerHandler(
  auth: OwnAuth<string, string>,
  options: OwnAuthAuthorizationServerHandlerOptions = {}
): OwnAuthAuthorizationServerHandler {
  const maximumBodyBytes = options.maxRequestBodyBytes ?? defaultBodyLimit;
  if (!Number.isInteger(maximumBodyBytes) || maximumBodyBytes < 1) {
    throw new Error("maxRequestBodyBytes must be a positive integer");
  }

  return async (request) => {
    if (!auth.authorizationServer.isConfigured()) {
      return protocolJson({ error: "not_found" }, 404);
    }
    const url = new URL(request.url);
    const path = normalizePath(url.pathname);
    if (
      path === authorizationServerPaths.deviceAuthorization &&
      !auth.authorizationServer.isDeviceAuthorizationConfigured()
    ) {
      return protocolJson({ error: "not_found" }, 404);
    }
    const route = protocolRoute(path);
    return traceHttpEndpoint({
      endpointId: `authorizationServer.${route.id}`,
      method: request.method,
      route: route.path
    }, async () => {
      try {
        if (discoveryPaths.has(path) && request.method === "GET") {
          return protocolJson(await auth.authorizationServer.metadata());
        }
        if (path === authorizationServerPaths.jwks && request.method === "GET") {
          return protocolJson(await auth.authorizationServer.jwks());
        }
        if (
          path === authorizationServerPaths.authorization &&
          request.method === "GET"
        ) {
          const session = readSessionToken(request, options.cookie);
          const result = await auth.authorizationServer.start({
            ...parseAuthorizationRequest(url.searchParams),
            sessionToken: session.token,
            request: await requestContext(request, options)
          });
          return redirectResponse(result.redirectUrl);
        }
        if (path === authorizationServerPaths.token && request.method === "POST") {
          const form = await readAuthorizationForm(request, maximumBodyBytes);
          const credentials = readAuthorizationClientCredentials(request, form);
          const input: AuthorizationTokenRequestInput = {
            grantType: singleAuthorizationParameter(form, "grant_type"),
            ...credentials,
            code: singleAuthorizationParameter(form, "code"),
            redirectUri: singleAuthorizationParameter(form, "redirect_uri"),
            codeVerifier: singleAuthorizationParameter(form, "code_verifier"),
            refreshToken: singleAuthorizationParameter(form, "refresh_token"),
            deviceCode: singleAuthorizationParameter(form, "device_code"),
            scope: singleAuthorizationParameter(form, "scope"),
            resource: singleAuthorizationParameter(form, "resource"),
            dpopProof: readDpopProofHeader(request),
            requestMethod: request.method,
            requestUrl: request.url,
            request: await requestContext(request, options)
          };
          return protocolJson(await auth.authorizationServer.exchangeToken(input));
        }
        if (
          path === authorizationServerPaths.deviceAuthorization &&
          request.method === "POST"
        ) {
          const form = await readAuthorizationForm(request, maximumBodyBytes);
          return protocolJson(await auth.authorizationServer.startDeviceAuthorization({
            ...readAuthorizationClientCredentials(request, form),
            scope: singleAuthorizationParameter(form, "scope"),
            resource: singleAuthorizationParameter(form, "resource"),
            dpopJkt: singleAuthorizationParameter(form, "dpop_jkt"),
            request: await requestContext(request, options)
          }));
        }
        if (
          path === authorizationServerPaths.revocation &&
          request.method === "POST"
        ) {
          const form = await readAuthorizationForm(request, maximumBodyBytes);
          const input: AuthorizationTokenActionInput = {
            ...readAuthorizationClientCredentials(request, form),
            token: singleAuthorizationParameter(form, "token"),
            tokenTypeHint: singleAuthorizationParameter(form, "token_type_hint"),
            dpopProof: readDpopProofHeader(request),
            requestMethod: request.method,
            requestUrl: request.url,
            request: await requestContext(request, options)
          };
          await auth.authorizationServer.revokeToken(input);
          return protocolJson({});
        }
        if (
          path === authorizationServerPaths.introspection &&
          request.method === "POST"
        ) {
          const form = await readAuthorizationForm(request, maximumBodyBytes);
          return protocolJson(await auth.authorizationServer.introspectToken({
            ...readAuthorizationClientCredentials(request, form),
            token: singleAuthorizationParameter(form, "token"),
            tokenTypeHint: singleAuthorizationParameter(form, "token_type_hint"),
            dpopProof: singleAuthorizationParameter(form, "dpop_proof"),
            requestMethod: singleAuthorizationParameter(form, "request_method"),
            requestUrl: singleAuthorizationParameter(form, "request_url"),
            request: await requestContext(request, options)
          }));
        }
        if (
          path === authorizationServerPaths.userinfo &&
          (request.method === "GET" || request.method === "POST")
        ) {
          const token = readAuthorizationAccessToken(request);
          return protocolJson(await auth.authorizationServer.userInfo({
            ...token,
            dpopProof: readDpopProofHeader(request),
            requestMethod: request.method,
            requestUrl: request.url
          }));
        }
        const existingRoute = routeExists(path);
        return protocolJson(
          {
            error: existingRoute ? "method_not_allowed" : "not_found"
          },
          existingRoute ? 405 : 404
        );
      } catch (error) {
        return handleProtocolError(error, request, options);
      }
    });
  };
}

async function handleProtocolError(
  error: unknown,
  request: Request,
  options: OwnAuthAuthorizationServerHandlerOptions
): Promise<Response> {
  const protocol = toProtocolError(error);
  if (protocol.statusCode >= 500) {
    await reportError(options.onError, error, request);
  }
  if (protocol.redirectUri) {
    return redirectResponse(authorizationRedirectUrl(protocol.redirectUri, {
      error: protocol.code,
      error_description: protocol.safeDescription,
      state: protocol.state
    }));
  }
  const headers = protocolHeaders();
  if (protocol.code === "invalid_client") {
    headers.set("www-authenticate", 'Basic realm="Own Auth OAuth"');
  } else if (protocol.code === "invalid_token") {
    headers.set("www-authenticate", 'Bearer error="invalid_token"');
  } else if (protocol.code === "invalid_dpop_proof") {
    headers.set("www-authenticate", 'DPoP error="invalid_dpop_proof"');
  }
  return new Response(JSON.stringify({
    error: protocol.code,
    error_description: protocol.safeDescription
  }), {
    status: protocol.statusCode,
    headers
  });
}

function toProtocolError(error: unknown): AuthorizationProtocolError {
  if (error instanceof AuthorizationProtocolError) return error;
  if (error instanceof AuthError) {
    if (error.code === "rate_limited") {
      return new AuthorizationProtocolError(
        "temporarily_unavailable",
        "Too many requests",
        { statusCode: 429 }
      );
    }
    if (error.code === "authorization_server_not_configured") {
      return new AuthorizationProtocolError(
        "server_error",
        "Authorization server is unavailable",
        { statusCode: 503 }
      );
    }
    return new AuthorizationProtocolError(
      "invalid_request",
      error.statusCode >= 500 ? "Authorization request failed" : error.safeMessage,
      { statusCode: error.statusCode }
    );
  }
  if (error instanceof OwnAuthHttpError) {
    return new AuthorizationProtocolError(
      "invalid_request",
      error.message,
      { statusCode: error.statusCode }
    );
  }
  return new AuthorizationProtocolError(
    "server_error",
    "Authorization request failed",
    { statusCode: 500 }
  );
}

function redirectResponse(location: string): Response {
  const headers = protocolHeaders();
  headers.set("location", location);
  return new Response(null, { status: 302, headers });
}

function protocolJson(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: protocolHeaders()
  });
}

function protocolHeaders(): Headers {
  return new Headers({
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    pragma: "no-cache",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff"
  });
}

function routeExists(path: string): boolean {
  return (
    discoveryPaths.has(path) ||
    Object.values(authorizationServerPaths).some(
      (routePath) => routePath === path
    )
  );
}

function protocolRoute(path: string): { id: string; path: string } {
  if (discoveryPaths.has(path)) return { id: "metadata", path };
  for (const [id, routePath] of Object.entries(authorizationServerPaths)) {
    if (path === routePath) return { id, path: routePath };
  }
  return { id: "not_found", path: "not_found" };
}

function normalizePath(path: string): string {
  return path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;
}

function requestContext(
  request: Request,
  options: OwnAuthAuthorizationServerHandlerOptions
): RequestContext | Promise<RequestContext> {
  return options.getRequestContext
    ? options.getRequestContext(request)
    : { userAgent: request.headers.get("user-agent") ?? undefined };
}

async function reportError(
  onError: OwnAuthAuthorizationServerHandlerOptions["onError"],
  error: unknown,
  request: Request
): Promise<void> {
  if (!onError) return;
  try {
    await onError(error, request);
  } catch {
    // Error reporting must not replace the protocol response.
  }
}
