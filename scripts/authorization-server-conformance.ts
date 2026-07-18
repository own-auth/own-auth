import type { AuthorizationServerStorage } from "../packages/core/src/authorization-server-storage.js";
import type { AuthStorage } from "../packages/core/src/storage.js";

export async function assertAuthorizationRefreshRace(
  storage: AuthStorage,
  authorization: AuthorizationServerStorage
): Promise<void> {
  const suffix = crypto.randomUUID();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 60_000);
  const userId = `usr_${suffix}`;
  const clientRecordId = `ocli_${suffix}`;
  const grantId = `ogrant_${suffix}`;

  await storage.createUser({
    id: userId,
    email: `${suffix}@example.com`,
    emailVerifiedAt: now,
    phone: null,
    phoneVerifiedAt: null,
    passwordHash: null,
    name: null,
    imageUrl: null,
    disabledAt: null,
    metadata: {},
    createdAt: now,
    updatedAt: now,
    lastLoginAt: null
  });
  await authorization.createAuthorizationClient({
    id: clientRecordId,
    clientId: `oa_client_${suffix}`,
    name: "D1 refresh race client",
    clientType: "public",
    applicationType: "web",
    tokenEndpointAuthMethod: "none",
    redirectUris: ["https://client.example.com/callback"],
    allowedScopes: ["openid", "offline_access"],
    grantTypes: ["authorization_code", "refresh_token"],
    dpopBoundAccessTokens: false,
    status: "active",
    createdAt: now,
    updatedAt: now,
    revokedAt: null
  }, null);
  await authorization.upsertAuthorizationGrant({
    id: grantId,
    authorizationClientId: clientRecordId,
    userId,
    protectedResourceId: null,
    scopes: ["openid", "offline_access"],
    createdAt: now,
    updatedAt: now,
    revokedAt: null
  });
  await authorization.createAuthorizationTokens(
    accessToken("initial", suffix, grantId, clientRecordId, userId, now, expiresAt),
    refreshToken("initial", suffix, grantId, clientRecordId, userId, now, expiresAt, 0)
  );
  const attempts = [0, 1].map((index) => ({
    access: accessToken(
      `winner_${index}`,
      suffix,
      grantId,
      clientRecordId,
      userId,
      now,
      expiresAt
    ),
    refresh: refreshToken(
      `winner_${index}`,
      suffix,
      grantId,
      clientRecordId,
      userId,
      now,
      expiresAt,
      1
    )
  }));
  const results = await Promise.all(attempts.map((attempt) =>
    authorization.rotateAuthorizationRefreshToken({
      tokenHash: `refresh_hash_initial_${suffix}`,
      authorizationClientId: clientRecordId,
      replacementRefreshToken: attempt.refresh,
      accessToken: attempt.access,
      rotatedAt: new Date()
    })
  ));
  if (JSON.stringify(results.sort()) !== JSON.stringify(["reused", "rotated"])) {
    throw new Error("D1 authorization refresh race did not rotate once and detect reuse once");
  }
  const grant = await authorization.getAuthorizationGrant(clientRecordId, userId, null);
  const accessTokens = await Promise.all(attempts.map(({ access }) =>
    authorization.getAuthorizationAccessTokenByHash(access.tokenHash)
  ));
  const refreshTokens = await Promise.all(attempts.map(({ refresh }) =>
    authorization.getAuthorizationRefreshTokenByHash(refresh.tokenHash)
  ));
  if (
    !grant?.revokedAt ||
    accessTokens.filter(Boolean).length !== 1 ||
    !accessTokens.find(Boolean)?.revokedAt ||
    refreshTokens.filter(Boolean).length !== 1 ||
    !refreshTokens.find(Boolean)?.revokedAt
  ) {
    throw new Error("D1 authorization refresh reuse did not revoke the winning grant family");
  }
}

function accessToken(
  label: string,
  suffix: string,
  grantId: string,
  authorizationClientId: string,
  userId: string,
  createdAt: Date,
  expiresAt: Date
) {
  return {
    id: `oat_${label}_${suffix}`,
    tokenHash: `access_hash_${label}_${suffix}`,
    prefix: `oa_at_${label}`,
    grantId,
    authorizationClientId,
    userId,
    protectedResourceId: null,
    scopes: ["openid", "offline_access"],
    dpopJkt: null,
    expiresAt,
    revokedAt: null,
    createdAt
  };
}

function refreshToken(
  label: string,
  suffix: string,
  grantId: string,
  authorizationClientId: string,
  userId: string,
  createdAt: Date,
  expiresAt: Date,
  generation: number
) {
  return {
    id: `ort_${label}_${suffix}`,
    tokenHash: `refresh_hash_${label}_${suffix}`,
    prefix: `oa_rt_${label}`,
    grantId,
    authorizationClientId,
    userId,
    protectedResourceId: null,
    scopes: ["openid", "offline_access"],
    generation,
    replacedByTokenId: null,
    dpopJkt: null,
    expiresAt,
    consumedAt: null,
    revokedAt: null,
    createdAt
  };
}
