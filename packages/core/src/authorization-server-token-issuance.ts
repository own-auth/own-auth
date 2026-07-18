import type { AuthEngineContext } from "./auth-engine-context.js";
import {
  authorizationTokenPrefix,
  createAccessToken,
  createRefreshToken,
  hashAuthorizationSecret,
  normalizeProtectedResourceIdentifier,
  requireAuthorizationServer
} from "./authorization-server-helpers.js";
import { isActiveProtectedResource } from "./authorization-server-protected-resources.js";
import { AuthorizationProtocolError } from "./authorization-server-protocol-error.js";
import type {
  AuthorizationAccessToken,
  AuthorizationClient,
  AuthorizationRefreshToken,
  AuthorizationTokenResponse,
  ProtectedResource
} from "./authorization-server-types.js";
import { createId } from "./crypto.js";
import { isExpired } from "./normalise.js";
import type { Session, User } from "./types.js";

export function createAuthorizationTokenPair(
  ctx: AuthEngineContext,
  client: AuthorizationClient,
  grantId: string,
  user: User,
  protectedResourceId: string | null,
  scopes: string[],
  refreshGeneration: number,
  dpopJkt: string | null,
  forceRefresh = false
): {
  access: { raw: string; entity: AuthorizationAccessToken };
  refresh: { raw: string; entity: AuthorizationRefreshToken } | null;
} {
  const { config } = requireAuthorizationServer(ctx);
  const now = new Date();
  const rawAccess = createAccessToken();
  const access: AuthorizationAccessToken = {
    id: createId("oat"),
    tokenHash: hashAuthorizationSecret(ctx, rawAccess),
    prefix: authorizationTokenPrefix(rawAccess),
    grantId,
    authorizationClientId: client.id,
    userId: user.id,
    protectedResourceId,
    scopes: [...scopes],
    dpopJkt,
    expiresAt: new Date(now.getTime() + config.accessTokenTtlMs),
    revokedAt: null,
    createdAt: now
  };
  if (!forceRefresh && !scopes.includes("offline_access")) {
    return { access: { raw: rawAccess, entity: access }, refresh: null };
  }
  const rawRefresh = createRefreshToken();
  return {
    access: { raw: rawAccess, entity: access },
    refresh: {
      raw: rawRefresh,
      entity: {
        id: createId("ort"),
        tokenHash: hashAuthorizationSecret(ctx, rawRefresh),
        prefix: authorizationTokenPrefix(rawRefresh),
        grantId,
        authorizationClientId: client.id,
        userId: user.id,
        protectedResourceId,
        scopes: [...scopes],
        generation: refreshGeneration,
        replacedByTokenId: null,
        dpopJkt,
        expiresAt: new Date(now.getTime() + config.refreshTokenTtlMs),
        consumedAt: null,
        revokedAt: null,
        createdAt: now
      }
    }
  };
}

export function authorizationTokenResponse(
  accessToken: string,
  expiresAt: Date,
  scopes: readonly string[],
  dpopJkt: string | null,
  refreshToken?: string,
  idToken?: string
): AuthorizationTokenResponse {
  return {
    token_type: dpopJkt ? "DPoP" : "Bearer",
    access_token: accessToken,
    expires_in: Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000)),
    scope: scopes.join(" "),
    ...(refreshToken ? { refresh_token: refreshToken } : {}),
    ...(idToken ? { id_token: idToken } : {})
  };
}

export function usableAuthorizationSession(session: Session | null): session is Session {
  return Boolean(
    session &&
    !session.revokedAt &&
    !isExpired(session.expiresAt) &&
    !isExpired(session.idleExpiresAt)
  );
}

export function invalidAuthorizationGrant(): AuthorizationProtocolError {
  return new AuthorizationProtocolError(
    "invalid_grant",
    "The authorization grant is invalid, expired, revoked, or already used"
  );
}

export function optionalAuthorizationResource(value: string | undefined): string | null {
  if (value === undefined) return null;
  try {
    return normalizeProtectedResourceIdentifier(value);
  } catch {
    throw new AuthorizationProtocolError(
      "invalid_target",
      "resource must identify a registered protected resource"
    );
  }
}

export async function loadAuthorizationTokenResource(
  ctx: AuthEngineContext,
  protectedResourceId: string | null,
  requestedIdentifier: string | null
): Promise<ProtectedResource | null> {
  if (protectedResourceId === null) {
    if (requestedIdentifier !== null) throw invalidTarget();
    return null;
  }
  const resource = await requireAuthorizationServer(ctx).storage
    .getProtectedResourceById(protectedResourceId);
  if (!isActiveProtectedResource(resource)) throw invalidAuthorizationGrant();
  if (requestedIdentifier !== null && requestedIdentifier !== resource.identifier) {
    throw invalidTarget();
  }
  return resource;
}

function invalidTarget(): AuthorizationProtocolError {
  return new AuthorizationProtocolError(
    "invalid_target",
    "The protected resource does not match the authorization grant"
  );
}
