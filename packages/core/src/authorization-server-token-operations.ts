import type { AuthEngineContext } from "./auth-engine-context.js";
import { audit, rateLimit, requireActiveUser } from "./auth-engine-helpers.js";
import {
  authenticateAuthorizationClient,
  isActiveAuthorizationClient
} from "./authorization-server-clients.js";
import {
  createAuthorizationUserInfo,
  getOrCreateOidcSubject
} from "./authorization-server-claims.js";
import {
  authorizationServerRateLimits,
  authorizationServerRateLimitWindowMs,
  authorizationServerTokenPrefixes
} from "./authorization-server-constants.js";
import {
  epochSeconds,
  hashAuthorizationSecret,
  requireAuthorizationServer
} from "./authorization-server-helpers.js";
import { AuthorizationProtocolError } from "./authorization-server-protocol-error.js";
import type {
  AuthorizationAccessToken,
  AuthorizationClient,
  AuthorizationGrant,
  AuthorizationIntrospectionResponse,
  AuthorizationTokenActionInput,
  AuthorizationUserGrant,
  AuthorizationUserInfo,
  ListAuthorizationUserGrantsInput,
  RevokeAuthorizationUserGrantInput,
  VerifiedAuthorizationAccessToken,
  VerifyAuthorizationAccessTokenInput
} from "./authorization-server-types.js";
import { AuthError } from "./errors.js";
import { isExpired } from "./normalise.js";
import type { User } from "./types.js";

export async function verifyAuthorizationAccessToken(
  ctx: AuthEngineContext,
  input: VerifyAuthorizationAccessTokenInput
): Promise<VerifiedAuthorizationAccessToken> {
  const resolved = await resolveAccessToken(ctx, input.accessToken);
  const requiredScopes = input.requiredScopes ?? [];
  if (
    !Array.isArray(requiredScopes) ||
    requiredScopes.some(
      (scope) => typeof scope !== "string" || !resolved.token.scopes.includes(scope)
    )
  ) {
    throw new AuthError(
      "insufficient_scope",
      "Access token does not include the required scope",
      403
    );
  }
  return {
    client: resolved.client,
    grant: resolved.grant,
    userId: resolved.user.id,
    scopes: [...resolved.token.scopes],
    expiresAt: resolved.token.expiresAt
  };
}

export async function getAuthorizationUserInfo(
  ctx: AuthEngineContext,
  accessToken: string
): Promise<AuthorizationUserInfo> {
  const resolved = await resolveAccessToken(ctx, accessToken);
  if (!resolved.token.scopes.includes("openid")) {
    throw invalidAccessToken();
  }
  return createAuthorizationUserInfo(ctx, resolved.user, resolved.token.scopes);
}

export async function revokeAuthorizationProtocolToken(
  ctx: AuthEngineContext,
  input: AuthorizationTokenActionInput
): Promise<void> {
  await rateLimitProtocolClient(ctx, "revocation", input);
  const client = await authenticateAuthorizationClient(ctx, input);
  const rawToken = requiredProtocolToken(input.token);
  const { storage } = requireAuthorizationServer(ctx);
  const tokenHash = hashAuthorizationSecret(ctx, rawToken);
  const [accessToken, refreshToken] = await Promise.all([
    storage.getAuthorizationAccessTokenByHash(tokenHash),
    storage.getAuthorizationRefreshTokenByHash(tokenHash)
  ]);
  const token = refreshToken ?? accessToken;
  if (!token || token.authorizationClientId !== client.id) return;
  await storage.revokeAuthorizationToken(tokenHash, client.id, new Date());
  await audit(ctx, {
    eventType: "authorization_server.token_revoked",
    actorUserId: token.userId,
    targetUserId: token.userId,
    context: input.request,
    metadata: {
      authorizationClientId: client.id,
      grantId: token.grantId,
      tokenKind: refreshToken ? "refresh_token" : "access_token"
    }
  });
  if (refreshToken) {
    await audit(ctx, {
      eventType: "authorization_server.grant_revoked",
      actorUserId: token.userId,
      targetUserId: token.userId,
      context: input.request,
      metadata: {
        authorizationClientId: client.id,
        grantId: token.grantId,
        reason: "refresh_token_revoked"
      }
    });
  }
}

export async function introspectAuthorizationToken(
  ctx: AuthEngineContext,
  input: AuthorizationTokenActionInput
): Promise<AuthorizationIntrospectionResponse> {
  await rateLimitProtocolClient(ctx, "introspection", input);
  const client = await authenticateAuthorizationClient(ctx, input);
  if (client.clientType !== "confidential") {
    throw new AuthorizationProtocolError(
      "unauthorized_client",
      "Token introspection requires a confidential client",
      { statusCode: 403 }
    );
  }
  const rawToken = requiredProtocolToken(input.token);
  const { storage } = requireAuthorizationServer(ctx);
  const tokenHash = hashAuthorizationSecret(ctx, rawToken);
  const [accessToken, refreshToken] = await Promise.all([
    storage.getAuthorizationAccessTokenByHash(tokenHash),
    storage.getAuthorizationRefreshTokenByHash(tokenHash)
  ]);
  const token = accessToken ?? refreshToken;
  if (!token || token.authorizationClientId !== client.id) return { active: false };
  const [grant, user] = await Promise.all([
    storage.getAuthorizationGrant(client.id, token.userId),
    ctx.storage.getUserById(token.userId)
  ]);
  if (
    !grant ||
    grant.id !== token.grantId ||
    grant.revokedAt ||
    token.revokedAt ||
    isExpired(token.expiresAt) ||
    !user ||
    user.disabledAt ||
    (refreshToken && Boolean(refreshToken.consumedAt))
  ) {
    return { active: false };
  }
  const subject = await getOrCreateOidcSubject(ctx, user.id);
  return {
    active: true,
    scope: token.scopes.join(" "),
    client_id: client.clientId,
    ...(accessToken ? { token_type: "Bearer" as const } : {}),
    exp: epochSeconds(token.expiresAt),
    iat: epochSeconds(token.createdAt),
    sub: subject.subject
  };
}

export async function listAuthorizationUserGrants(
  ctx: AuthEngineContext,
  input: ListAuthorizationUserGrantsInput
): Promise<AuthorizationUserGrant[]> {
  await requireActiveUser(ctx, input.actorUserId);
  const { storage } = requireAuthorizationServer(ctx);
  const grants = await storage.listAuthorizationGrantsByUserId(input.actorUserId);
  const active = grants.filter((grant) => !grant.revokedAt);
  const clients = await Promise.all(
    active.map((grant) => storage.getAuthorizationClientById(grant.authorizationClientId))
  );
  return active.flatMap((grant, index) => {
    const client = clients[index];
    return isActiveAuthorizationClient(client)
      ? [{ grant, client }]
      : [];
  });
}

export async function revokeAuthorizationUserGrant(
  ctx: AuthEngineContext,
  input: RevokeAuthorizationUserGrantInput
): Promise<void> {
  await requireActiveUser(ctx, input.actorUserId);
  const { storage } = requireAuthorizationServer(ctx);
  const client = await storage.getAuthorizationClientByClientId(input.clientId);
  if (!client) return;
  const grant = await storage.getAuthorizationGrant(client.id, input.actorUserId);
  if (!grant || grant.revokedAt) return;
  await storage.revokeAuthorizationGrant(grant.id, new Date());
  await audit(ctx, {
    eventType: "authorization_server.grant_revoked",
    actorUserId: input.actorUserId,
    targetUserId: input.actorUserId,
    context: input.request,
    metadata: {
      authorizationClientId: client.id,
      grantId: grant.id,
      reason: "user_revoked"
    }
  });
}

async function resolveAccessToken(
  ctx: AuthEngineContext,
  rawToken: string
): Promise<{
  token: AuthorizationAccessToken;
  client: AuthorizationClient;
  grant: AuthorizationGrant;
  user: User;
}> {
  if (
    typeof rawToken !== "string" ||
    !rawToken.startsWith(authorizationServerTokenPrefixes.accessToken) ||
    rawToken.length > 512
  ) {
    throw invalidAccessToken();
  }
  const { storage } = requireAuthorizationServer(ctx);
  const token = await storage.getAuthorizationAccessTokenByHash(
    hashAuthorizationSecret(ctx, rawToken)
  );
  if (!token || token.revokedAt || isExpired(token.expiresAt)) {
    throw invalidAccessToken();
  }
  const [client, grant, user] = await Promise.all([
    storage.getAuthorizationClientById(token.authorizationClientId),
    storage.getAuthorizationGrant(token.authorizationClientId, token.userId),
    ctx.storage.getUserById(token.userId)
  ]);
  if (
    !isActiveAuthorizationClient(client) ||
    !grant ||
    grant.id !== token.grantId ||
    grant.revokedAt ||
    !user ||
    user.disabledAt
  ) {
    throw invalidAccessToken();
  }
  return { token, client, grant, user };
}

function requiredProtocolToken(value: string | undefined): string {
  if (typeof value !== "string" || !value || value.length > 512) {
    throw new AuthorizationProtocolError("invalid_request", "token is required");
  }
  return value;
}

function invalidAccessToken(): AuthorizationProtocolError {
  return new AuthorizationProtocolError(
    "invalid_token",
    "The access token is invalid, expired, or revoked",
    { statusCode: 401 }
  );
}

function rateLimitProtocolClient(
  ctx: AuthEngineContext,
  operation: "introspection" | "revocation",
  input: AuthorizationTokenActionInput
): Promise<void> {
  return rateLimit(
    ctx,
    `authorization_server_${operation}`,
    input.request?.ipAddress ?? input.clientId ?? "unknown",
    authorizationServerRateLimits.protocol,
    authorizationServerRateLimitWindowMs
  );
}
