import type { AuthEngineContext } from "./auth-engine-context.js";
import { audit, rateLimit } from "./auth-engine-helpers.js";
import { authenticateAuthorizationClient } from "./authorization-server-clients.js";
import { createAuthorizationIdToken } from "./authorization-server-claims.js";
import {
  authorizationServerRateLimits,
  authorizationServerRateLimitWindowMs,
  authorizationServerTokenPrefixes
} from "./authorization-server-constants.js";
import {
  authorizationTokenPrefix,
  calculateCodeChallenge,
  createAccessToken,
  createRefreshToken,
  decryptAuthorizationNonce,
  hashAuthorizationSecret,
  requireAuthorizationServer
} from "./authorization-server-helpers.js";
import { AuthorizationProtocolError } from "./authorization-server-protocol-error.js";
import type {
  AuthorizationAccessToken,
  AuthorizationClient,
  AuthorizationRefreshToken,
  AuthorizationTokenRequestInput,
  AuthorizationTokenResponse
} from "./authorization-server-types.js";
import { createId } from "./crypto.js";
import { isExpired } from "./normalise.js";
import type { Session, User } from "./types.js";

export async function exchangeAuthorizationToken(
  ctx: AuthEngineContext,
  input: AuthorizationTokenRequestInput
): Promise<AuthorizationTokenResponse> {
  await rateLimit(
    ctx,
    "authorization_server_token",
    input.request?.ipAddress ?? input.clientId ?? "unknown",
    authorizationServerRateLimits.protocol,
    authorizationServerRateLimitWindowMs
  );
  const client = await authenticateAuthorizationClient(ctx, input);
  if (!input.grantType) {
    throw new AuthorizationProtocolError("invalid_request", "grant_type is required");
  }
  if (input.grantType === "authorization_code") {
    return exchangeAuthorizationCode(ctx, client, input);
  }
  if (input.grantType === "refresh_token") {
    return exchangeRefreshToken(ctx, client, input);
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
  const codeChallenge = await calculateCodeChallenge(codeVerifier);
  const code = await storage.consumeAuthorizationCode(
    hashAuthorizationSecret(ctx, rawCode),
    client.id,
    redirectUri,
    codeChallenge,
    new Date()
  );
  if (!code) throw invalidGrant();

  const [grant, user, sessions] = await Promise.all([
    storage.getAuthorizationGrant(client.id, code.userId),
    ctx.storage.getUserById(code.userId),
    ctx.storage.listSessionsByUserId(code.userId)
  ]);
  const session = sessions.find((candidate) => candidate.id === code.sessionId) ?? null;
  if (
    !grant ||
    grant.id !== code.grantId ||
    grant.revokedAt ||
    !user ||
    user.disabledAt ||
    !usableSession(session)
  ) {
    throw invalidGrant();
  }

  const issued = createTokenPair(ctx, client, grant.id, user, code.scopes, 0);
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
      scopes: code.scopes
    }
  });
  return tokenResponse(
    issued.access.raw,
    issued.access.entity.expiresAt,
    code.scopes,
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
  const current = await storage.getAuthorizationRefreshTokenByHash(tokenHash);
  if (
    !current ||
    current.authorizationClientId !== client.id ||
    current.revokedAt ||
    isExpired(current.expiresAt)
  ) {
    throw invalidGrant();
  }
  const [grant, user] = await Promise.all([
    storage.getAuthorizationGrant(client.id, current.userId),
    ctx.storage.getUserById(current.userId)
  ]);
  if (
    !grant ||
    grant.id !== current.grantId ||
    grant.revokedAt ||
    !user ||
    user.disabledAt
  ) {
    throw invalidGrant();
  }
  const scopes = refreshScopes(input.scope, current.scopes);
  const issued = createTokenPair(
    ctx,
    client,
    current.grantId,
    user,
    scopes,
    current.generation + 1,
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
    throw invalidGrant();
  }
  if (result !== "rotated") throw invalidGrant();

  await audit(ctx, {
    eventType: "authorization_server.token_refreshed",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request,
    metadata: {
      authorizationClientId: client.id,
      grantId: current.grantId,
      scopes
    }
  });
  return tokenResponse(
    issued.access.raw,
    issued.access.entity.expiresAt,
    scopes,
    issued.refresh.raw
  );
}

function createTokenPair(
  ctx: AuthEngineContext,
  client: AuthorizationClient,
  grantId: string,
  user: User,
  scopes: string[],
  refreshGeneration: number,
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
    scopes: [...scopes],
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
        scopes: [...scopes],
        generation: refreshGeneration,
        replacedByTokenId: null,
        expiresAt: new Date(now.getTime() + config.refreshTokenTtlMs),
        consumedAt: null,
        revokedAt: null,
        createdAt: now
      }
    }
  };
}

function tokenResponse(
  accessToken: string,
  expiresAt: Date,
  scopes: readonly string[],
  refreshToken?: string,
  idToken?: string
): AuthorizationTokenResponse {
  return {
    token_type: "Bearer",
    access_token: accessToken,
    expires_in: Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000)),
    scope: scopes.join(" "),
    ...(refreshToken ? { refresh_token: refreshToken } : {}),
    ...(idToken ? { id_token: idToken } : {})
  };
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

function usableSession(session: Session | null): session is Session {
  return Boolean(
    session &&
    !session.revokedAt &&
    !isExpired(session.expiresAt) &&
    !isExpired(session.idleExpiresAt)
  );
}

function requiredToken(
  value: string | undefined,
  field: string,
  prefix: string
): string {
  const token = requiredText(value, field);
  if (!token.startsWith(prefix) || token.length > 512) throw invalidGrant();
  return token;
}

function requiredText(value: string | undefined, field: string): string {
  if (typeof value !== "string" || !value || value.length > 2_048) {
    throw new AuthorizationProtocolError("invalid_request", `${field} is required`);
  }
  return value;
}

function invalidGrant(): AuthorizationProtocolError {
  return new AuthorizationProtocolError(
    "invalid_grant",
    "The authorization grant is invalid, expired, revoked, or already used"
  );
}
