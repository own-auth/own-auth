import type { AuthEngineContext } from "./auth-engine-context.js";
import { rateLimit } from "./auth-engine-helpers.js";
import {
  authorizationServerRateLimits,
  authorizationServerRateLimitWindowMs
} from "./authorization-server-constants.js";
import { requireAuthorizationServer } from "./authorization-server-helpers.js";
import type { RequestContext } from "./types.js";
import { rateLimitIpIdentifier } from "./rate-limit-ip.js";

interface ProtocolRateLimitInput {
  clientId?: string;
  request?: RequestContext;
}

export function rateLimitAuthorizationServerProtocol(
  ctx: AuthEngineContext,
  operation: "token" | "introspection" | "revocation",
  input: ProtocolRateLimitInput
): Promise<void> {
  return rateLimit(
    ctx,
    `authorization_server_${operation}`,
    input.request?.ipAddress ? rateLimitIpIdentifier(input.request.ipAddress) : input.clientId ?? "unknown",
    authorizationServerRateLimits.protocol,
    authorizationServerRateLimitWindowMs
  );
}

export function rateLimitProtectedResourceIntrospection(
  ctx: AuthEngineContext,
  protectedResourceId: string
): Promise<void> {
  const { config } = requireAuthorizationServer(ctx);
  return rateLimit(
    ctx,
    "authorization_server_resource_introspection",
    protectedResourceId,
    config.resourceIntrospectionRequestsPerMinute,
    60_000
  );
}

export function rateLimitFailedProtectedResourceAuthentication(
  ctx: AuthEngineContext,
  ipAddress: string | undefined
): Promise<void> {
  if (!ipAddress) return Promise.resolve();
  const { config } = requireAuthorizationServer(ctx);
  return rateLimit(
    ctx,
    "authorization_server_introspection_auth_failed",
    rateLimitIpIdentifier(ipAddress),
    config.failedIntrospectionAttemptsPerMinute,
    60_000
  );
}
