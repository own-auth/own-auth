import type { AuthEngineContext } from "./auth-engine-context.js";
import { audit, requireActiveUser } from "./auth-engine-helpers.js";
import {
  authenticateAuthorizationClient,
  isActiveAuthorizationClient
} from "./authorization-server-clients.js";
import { createAuthorizationUserInfo } from "./authorization-server-claims.js";
import { authorizationServerTokenPrefixes } from "./authorization-server-constants.js";
import {
  rejectDpopProofWhenDisabled,
  verifyAndConsumeDpopProof
} from "./authorization-server-dpop.js";
import {
  hashAuthorizationSecret,
  normalizeProtectedResourceIdentifier,
  requireAuthorizationProtocolToken,
  requireAuthorizationServer
} from "./authorization-server-helpers.js";
import {
  authorizationTokenScopesAreActive,
  isActiveProtectedResourceBinding,
  resolveProtectedResource
} from "./authorization-server-protected-resources.js";
import { AuthorizationProtocolError } from "./authorization-server-protocol-error.js";
import { rateLimitAuthorizationServerProtocol } from "./authorization-server-rate-limits.js";
import type {
  AuthorizationAccessToken,
  AuthorizationClient,
  AuthorizationGrant,
  ProtectedResource,
  AuthorizationTokenActionInput,
  AuthorizationUserGrant,
  AuthorizationUserInfo,
  AuthorizationUserInfoRequestInput,
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
  const expectedResource = input.resource === undefined
    ? undefined
    : normalizeVerificationResource(input.resource);
  const resolved = await resolveAccessToken(ctx, input.accessToken, {
    expectedResource
  });
  if (
    resolved.token.dpopJkt ||
    resolved.client.dpopBoundAccessTokens ||
    resolved.resource?.requireDpop
  ) {
    throw invalidAccessToken();
  }
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
    resource: resolved.resource?.identifier ?? null,
    scopes: [...resolved.token.scopes],
    expiresAt: resolved.token.expiresAt
  };
}

export async function getAuthorizationUserInfo(
  ctx: AuthEngineContext,
  input: AuthorizationUserInfoRequestInput
): Promise<AuthorizationUserInfo> {
  rejectDpopProofWhenDisabled(ctx, input.dpopProof);
  const resolved = await resolveAccessToken(ctx, input.accessToken, {
    allowAnyResource: true
  });
  if (
    (resolved.token.dpopJkt && input.tokenType !== "DPoP") ||
    (!resolved.token.dpopJkt && input.tokenType !== "Bearer")
  ) {
    throw invalidAccessToken();
  }
  await verifyAndConsumeDpopProof(ctx, {
    proof: input.dpopProof,
    expectedJkt: resolved.token.dpopJkt ?? null,
    bindingRequired:
      resolved.client.dpopBoundAccessTokens || Boolean(resolved.resource?.requireDpop),
    method: input.requestMethod,
    url: input.requestUrl,
    accessToken: input.accessToken,
    statusCode: 401
  });
  if (!resolved.token.scopes.includes("openid")) {
    throw invalidAccessToken();
  }
  return createAuthorizationUserInfo(ctx, resolved.user, resolved.token.scopes);
}

export async function revokeAuthorizationProtocolToken(
  ctx: AuthEngineContext,
  input: AuthorizationTokenActionInput
): Promise<void> {
  await rateLimitAuthorizationServerProtocol(ctx, "revocation", input);
  const client = await authenticateAuthorizationClient(ctx, input);
  rejectDpopProofWhenDisabled(ctx, input.dpopProof);
  const rawToken = requireAuthorizationProtocolToken(input.token);
  const { storage } = requireAuthorizationServer(ctx);
  const tokenHash = hashAuthorizationSecret(ctx, rawToken);
  const [accessToken, refreshToken] = await Promise.all([
    storage.getAuthorizationAccessTokenByHash(tokenHash),
    storage.getAuthorizationRefreshTokenByHash(tokenHash)
  ]);
  const token = refreshToken ?? accessToken;
  if (!token || token.authorizationClientId !== client.id) {
    return;
  }
  const resource = token.protectedResourceId
    ? await storage.getProtectedResourceById(token.protectedResourceId)
    : null;
  await verifyAndConsumeDpopProof(ctx, {
    proof: input.dpopProof,
    expectedJkt: token.dpopJkt ?? null,
    bindingRequired: client.dpopBoundAccessTokens || Boolean(resource?.requireDpop),
    method: input.requestMethod ?? "",
    url: input.requestUrl ?? ""
  });
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
  const resources = await Promise.all(
    active.map((grant) => grant.protectedResourceId
      ? storage.getProtectedResourceById(grant.protectedResourceId)
      : Promise.resolve(null))
  );
  return active.flatMap((grant, index) => {
    const client = clients[index];
    const resource = resources[index] ?? null;
    return isActiveAuthorizationClient(client) && isActiveProtectedResourceBinding(
      grant.protectedResourceId,
      resource
    )
      ? [{ grant, client, resource }]
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
  const resource = input.resource === undefined
    ? null
    : await resolveProtectedResource(ctx, input.resource);
  const grant = await storage.getAuthorizationGrant(
    client.id,
    input.actorUserId,
    resource?.id ?? null
  );
  if (!grant || grant.revokedAt) return;
  const revoked = await storage.revokeAuthorizationGrant(grant.id, new Date());
  if (!revoked) return;
  await audit(ctx, {
    eventType: "authorization_server.grant_revoked",
    actorUserId: input.actorUserId,
    targetUserId: input.actorUserId,
    context: input.request,
    metadata: {
      authorizationClientId: client.id,
      grantId: grant.id,
      ...(resource ? { protectedResourceId: resource.id } : {}),
      reason: "user_revoked"
    }
  });
}

async function resolveAccessToken(
  ctx: AuthEngineContext,
  rawToken: string,
  options: {
    allowAnyResource?: boolean;
    expectedResource?: string | null;
  }
): Promise<{
  token: AuthorizationAccessToken;
  client: AuthorizationClient;
  grant: AuthorizationGrant;
  resource: ProtectedResource | null;
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
  const [client, grant, resource, user] = await Promise.all([
    storage.getAuthorizationClientById(token.authorizationClientId),
    storage.getAuthorizationGrant(
      token.authorizationClientId,
      token.userId,
      token.protectedResourceId
    ),
    token.protectedResourceId
      ? storage.getProtectedResourceById(token.protectedResourceId)
      : Promise.resolve(null),
    ctx.storage.getUserById(token.userId)
  ]);
  if (
    !isActiveAuthorizationClient(client) ||
    !grant ||
    grant.id !== token.grantId ||
    grant.revokedAt ||
    !isActiveProtectedResourceBinding(token.protectedResourceId, resource) ||
    (!options.allowAnyResource &&
      !resourceMatchesExpected(
        token.protectedResourceId,
        resource,
        options.expectedResource
      )) ||
    !authorizationTokenScopesAreActive(resource, grant.scopes, token.scopes) ||
    !user ||
    user.disabledAt
  ) {
    throw invalidAccessToken();
  }
  return { token, client, grant, resource, user };
}

function resourceMatchesExpected(
  protectedResourceId: string | null,
  resource: ProtectedResource | null,
  expectedResource: string | null | undefined
): boolean {
  if (protectedResourceId === null) {
    return expectedResource === undefined || expectedResource === null;
  }
  return typeof expectedResource === "string" && resource?.identifier === expectedResource;
}

function normalizeVerificationResource(value: string): string {
  try {
    return normalizeProtectedResourceIdentifier(value);
  } catch {
    throw new AuthError(
      "validation_error",
      "resource must identify a registered protected resource",
      400
    );
  }
}

function invalidAccessToken(): AuthorizationProtocolError {
  return new AuthorizationProtocolError(
    "invalid_token",
    "The access token is invalid, expired, or revoked",
    { statusCode: 401 }
  );
}
