import type { AuthEngineContext } from "./auth-engine-context.js";
import { audit } from "./auth-engine-helpers.js";
import { authenticateAuthorizationClient } from "./authorization-server-clients.js";
import { createAuthorizationIdToken } from "./authorization-server-claims.js";
import { authorizationServerTokenPrefixes } from "./authorization-server-constants.js";
import {
  rejectDpopProofWhenDisabled,
  verifyAndConsumeDpopProof
} from "./authorization-server-dpop.js";
import {
  calculateCodeChallenge,
  decryptAuthorizationNonce,
  hashAuthorizationSecret,
  requireAuthorizationServer
} from "./authorization-server-helpers.js";
import { authorizationTokenScopesAreActive } from "./authorization-server-protected-resources.js";
import { AuthorizationProtocolError } from "./authorization-server-protocol-error.js";
import { rateLimitAuthorizationServerProtocol } from "./authorization-server-rate-limits.js";
import type {
  AuthorizationClient,
  AuthorizationTokenRequestInput,
  AuthorizationTokenResponse
} from "./authorization-server-types.js";
import { deviceAuthorizationGrantType } from "./authorization-server-device-types.js";
import { exchangeDeviceAuthorizationToken } from "./authorization-server-device-token.js";
import { isExpired } from "./normalise.js";
import {
  authorizationTokenResponse,
  createAuthorizationTokenPair,
  invalidAuthorizationGrant,
  loadAuthorizationTokenResource,
  optionalAuthorizationResource,
  usableAuthorizationSession
} from "./authorization-server-token-issuance.js";

export async function exchangeAuthorizationToken(
  ctx: AuthEngineContext,
  input: AuthorizationTokenRequestInput
): Promise<AuthorizationTokenResponse> {
  await rateLimitAuthorizationServerProtocol(ctx, "token", input);
  const client = await authenticateAuthorizationClient(ctx, input);
  rejectDpopProofWhenDisabled(ctx, input.dpopProof);
  if (!input.grantType) {
    throw new AuthorizationProtocolError("invalid_request", "grant_type is required");
  }
  if (input.grantType === "authorization_code") {
    assertClientGrantType(client, "authorization_code");
    return exchangeAuthorizationCode(ctx, client, input);
  }
  if (input.grantType === "refresh_token") {
    assertClientGrantType(client, "refresh_token");
    return exchangeRefreshToken(ctx, client, input);
  }
  if (input.grantType === deviceAuthorizationGrantType) {
    assertClientGrantType(client, deviceAuthorizationGrantType);
    return exchangeDeviceAuthorizationToken(ctx, client, input);
  }
  throw new AuthorizationProtocolError(
    "unsupported_grant_type",
    "The requested grant type is not supported"
  );
}

async function exchangeAuthorizationCode(
  ctx: AuthEngineContext,
  client: AuthorizationClient,
  input: AuthorizationTokenRequestInput
): Promise<AuthorizationTokenResponse> {
  const { storage } = requireAuthorizationServer(ctx);
  const rawCode = requiredToken(
    input.code,
    "code",
    authorizationServerTokenPrefixes.authorizationCode
  );
  const redirectUri = requiredText(input.redirectUri, "redirect_uri");
  const codeVerifier = requiredText(input.codeVerifier, "code_verifier");
  const requestedResource = optionalAuthorizationResource(input.resource);
  const codeChallenge = await calculateCodeChallenge(codeVerifier);
  const codeHash = hashAuthorizationSecret(ctx, rawCode);
  const exchangedAt = new Date();
  const dpopStorage = ctx.dpopStorage;
  const dpopBinding = ctx.authorizationServer?.dpop && dpopStorage
    ? await dpopStorage.findAuthorizationCodeDpopBinding({
        codeHash,
        authorizationClientId: client.id,
        redirectUri,
        codeChallenge,
        resourceIdentifier: requestedResource,
        now: exchangedAt
      })
    : null;
  if (ctx.authorizationServer?.dpop && !dpopBinding) throw invalidAuthorizationGrant();
  await verifyAndConsumeDpopProof(ctx, {
    proof: input.dpopProof,
    expectedJkt: dpopBinding?.dpopJkt ?? null,
    bindingRequired: dpopBinding?.dpopRequired ?? client.dpopBoundAccessTokens,
    method: input.requestMethod ?? "",
    url: input.requestUrl ?? "",
    now: exchangedAt
  });
  const code = dpopBinding && dpopStorage
    ? await dpopStorage.consumeDpopAuthorizationCode(
        codeHash,
        client.id,
        redirectUri,
        codeChallenge,
        requestedResource,
        dpopBinding.dpopJkt,
        exchangedAt
      )
    : await storage.consumeAuthorizationCode(
        codeHash,
        client.id,
        redirectUri,
        codeChallenge,
        requestedResource,
        exchangedAt
      );
  if (!code) throw invalidAuthorizationGrant();
  if ((code.dpopJkt ?? null) !== (dpopBinding?.dpopJkt ?? null)) {
    throw invalidAuthorizationGrant();
  }

  const [grant, user, sessions, resource] = await Promise.all([
    storage.getAuthorizationGrant(
      client.id,
      code.userId,
      code.protectedResourceId
    ),
    ctx.storage.getUserById(code.userId),
    ctx.storage.listSessionsByUserId(code.userId),
    loadAuthorizationTokenResource(ctx, code.protectedResourceId, requestedResource)
  ]);
  const session = sessions.find((candidate) => candidate.id === code.sessionId) ?? null;
  if (
    !grant ||
    grant.id !== code.grantId ||
    grant.revokedAt ||
    !user ||
    user.disabledAt ||
    !usableAuthorizationSession(session) ||
    !authorizationTokenScopesAreActive(resource, grant?.scopes ?? [], code.scopes)
  ) {
    throw invalidAuthorizationGrant();
  }

  const issued = createAuthorizationTokenPair(
    ctx,
    client,
    grant.id,
    user,
    code.protectedResourceId,
    code.scopes,
    0,
    code.dpopJkt ?? null
  );
  const nonce = code.nonceCiphertext && code.nonceNonce && code.encryptionKeyId
    ? await decryptAuthorizationNonce(ctx, {
        id: code.id,
        authorizationClientId: code.authorizationClientId,
        nonceCiphertext: code.nonceCiphertext,
        nonceNonce: code.nonceNonce,
        encryptionKeyId: code.encryptionKeyId
      })
    : null;
  const idToken = code.scopes.includes("openid")
    ? await createAuthorizationIdToken(ctx, {
        client,
        user,
        session,
        scopes: code.scopes,
        accessToken: issued.access.raw,
        accessTokenExpiresAt: issued.access.entity.expiresAt,
        nonce
      })
    : undefined;
  await storage.createAuthorizationTokens(issued.access.entity, issued.refresh?.entity ?? null);
  await audit(ctx, {
    eventType: "authorization_server.code_exchanged",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request,
    metadata: {
      authorizationClientId: client.id,
      grantId: grant.id,
      scopes: code.scopes,
      ...(resource ? { protectedResourceId: resource.id } : {})
    }
  });
  return authorizationTokenResponse(
    issued.access.raw,
    issued.access.entity.expiresAt,
    code.scopes,
    code.dpopJkt ?? null,
    issued.refresh?.raw,
    idToken
  );
}

async function exchangeRefreshToken(
  ctx: AuthEngineContext,
  client: AuthorizationClient,
  input: AuthorizationTokenRequestInput
): Promise<AuthorizationTokenResponse> {
  const { storage } = requireAuthorizationServer(ctx);
  const rawRefreshToken = requiredToken(
    input.refreshToken,
    "refresh_token",
    authorizationServerTokenPrefixes.refreshToken
  );
  const tokenHash = hashAuthorizationSecret(ctx, rawRefreshToken);
  const requestedResource = optionalAuthorizationResource(input.resource);
  const current = await storage.getAuthorizationRefreshTokenByHash(tokenHash);
  if (
    !current ||
    current.authorizationClientId !== client.id ||
    current.revokedAt ||
    isExpired(current.expiresAt)
  ) {
    throw invalidAuthorizationGrant();
  }
  const [grant, user, resource] = await Promise.all([
    storage.getAuthorizationGrant(
      client.id,
      current.userId,
      current.protectedResourceId
    ),
    ctx.storage.getUserById(current.userId),
    loadAuthorizationTokenResource(ctx, current.protectedResourceId, requestedResource)
  ]);
  if (
    !grant ||
    grant.id !== current.grantId ||
    grant.revokedAt ||
    !user ||
    user.disabledAt ||
    !authorizationTokenScopesAreActive(resource, grant?.scopes ?? [], current.scopes)
  ) {
    throw invalidAuthorizationGrant();
  }
  await verifyAndConsumeDpopProof(ctx, {
    proof: input.dpopProof,
    expectedJkt: current.dpopJkt ?? null,
    bindingRequired: client.dpopBoundAccessTokens || Boolean(resource?.requireDpop),
    method: input.requestMethod ?? "",
    url: input.requestUrl ?? "",
    now: new Date()
  });
  const scopes = refreshScopes(input.scope, current.scopes);
  const issued = createAuthorizationTokenPair(
    ctx,
    client,
    current.grantId,
    user,
    current.protectedResourceId,
    scopes,
    current.generation + 1,
    current.dpopJkt ?? null,
    true
  );
  if (!issued.refresh) throw new Error("Refresh rotation did not create a refresh token");
  const rotatedAt = new Date();
  const result = await storage.rotateAuthorizationRefreshToken({
    tokenHash,
    authorizationClientId: client.id,
    replacementRefreshToken: issued.refresh.entity,
    accessToken: issued.access.entity,
    rotatedAt
  });
  if (result === "reused") {
    await audit(ctx, {
      eventType: "authorization_server.refresh_reuse_detected",
      actorUserId: user.id,
      targetUserId: user.id,
      context: input.request,
      metadata: {
        authorizationClientId: client.id,
        grantId: current.grantId
      }
    });
    await audit(ctx, {
      eventType: "authorization_server.grant_revoked",
      actorUserId: user.id,
      targetUserId: user.id,
      context: input.request,
      metadata: {
        authorizationClientId: client.id,
        grantId: current.grantId,
        reason: "refresh_token_reuse"
      }
    });
    throw invalidAuthorizationGrant();
  }
  if (result !== "rotated") throw invalidAuthorizationGrant();

  await audit(ctx, {
    eventType: "authorization_server.token_refreshed",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request,
    metadata: {
      authorizationClientId: client.id,
      grantId: current.grantId,
      scopes,
      ...(resource ? { protectedResourceId: resource.id } : {})
    }
  });
  return authorizationTokenResponse(
    issued.access.raw,
    issued.access.entity.expiresAt,
    scopes,
    current.dpopJkt ?? null,
    issued.refresh.raw
  );
}

function refreshScopes(value: string | undefined, current: string[]): string[] {
  if (value === undefined) return [...current];
  if (value.length > 4_096) {
    throw new AuthorizationProtocolError("invalid_scope", "scope is too long");
  }
  const scopes = value.trim().split(/\s+/).filter(Boolean);
  if (
    scopes.length === 0 ||
    scopes.length > 100 ||
    new Set(scopes).size !== scopes.length ||
    scopes.some((scope) => !current.includes(scope))
  ) {
    throw new AuthorizationProtocolError(
      "invalid_scope",
      "Refresh token scopes must be a subset of the original grant"
    );
  }
  return scopes;
}

function requiredToken(
  value: string | undefined,
  field: string,
  prefix: string
): string {
  const token = requiredText(value, field);
  if (!token.startsWith(prefix) || token.length > 512) {
    throw invalidAuthorizationGrant();
  }
  return token;
}

function requiredText(value: string | undefined, field: string): string {
  if (typeof value !== "string" || !value || value.length > 2_048) {
    throw new AuthorizationProtocolError("invalid_request", `${field} is required`);
  }
  return value;
}

function assertClientGrantType(
  client: AuthorizationClient,
  grantType: AuthorizationClient["grantTypes"][number]
): void {
  if (!client.grantTypes.includes(grantType)) {
    throw new AuthorizationProtocolError(
      "unauthorized_client",
      "The authorization client cannot use this grant type"
    );
  }
}
