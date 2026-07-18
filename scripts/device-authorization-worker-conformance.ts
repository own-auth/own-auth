import type {
  DeviceAuthorizationStorage
} from "../packages/core/src/authorization-server-device-storage.js";
import {
  deviceAuthorizationGrantType,
  type DeviceAuthorization
} from "../packages/core/src/authorization-server-device-types.js";
import type {
  AuthorizationAccessToken,
  AuthorizationGrant
} from "../packages/core/src/authorization-server-types.js";
import type {
  AuthorizationServerStorage
} from "../packages/core/src/authorization-server-storage.js";
import type { AuthStorage } from "../packages/core/src/storage.js";

export async function assertDeviceAuthorizationRaces(
  storage: AuthStorage,
  authorizationStorage: AuthorizationServerStorage,
  deviceStorage: readonly [DeviceAuthorizationStorage, DeviceAuthorizationStorage]
): Promise<void> {
  const first = await createFixture(storage, authorizationStorage, deviceStorage[0]);
  const decisions = await Promise.all([
    deviceStorage[0].approveDeviceAuthorization({
      userCodeHash: first.authorization.userCodeHash,
      userId: first.userId,
      sessionId: first.sessionId,
      approvedScopes: first.grant.scopes,
      grant: first.grant,
      decidedAt: new Date()
    }),
    deviceStorage[1].denyDeviceAuthorization({
      userCodeHash: first.authorization.userCodeHash,
      userId: first.userId,
      sessionId: first.sessionId,
      decidedAt: new Date()
    })
  ]);
  const decisionStatuses = decisions.map(({ status }) => status);
  if (
    decisionStatuses.filter((status) => status === "already_decided").length !== 1 ||
    decisionStatuses.filter((status) => status === "approved" || status === "denied")
      .length !== 1
  ) {
    throw new Error("D1 device authorization decision race did not produce one winner");
  }

  const second = await createFixture(storage, authorizationStorage, deviceStorage[0]);
  const approval = await deviceStorage[0].approveDeviceAuthorization({
    userCodeHash: second.authorization.userCodeHash,
    userId: second.userId,
    sessionId: second.sessionId,
    approvedScopes: second.grant.scopes,
    grant: second.grant,
    decidedAt: new Date()
  });
  if (approval.status !== "approved") {
    throw new Error("D1 device authorization fixture could not be approved");
  }
  const accessTokens = [0, 1].map((index) => createAccessToken(second, index));
  const consumed = await Promise.all(accessTokens.map((accessToken, index) =>
    deviceStorage[index as 0 | 1].consumeDeviceAuthorization({
      id: second.authorization.id,
      deviceCodeHash: second.authorization.deviceCodeHash,
      authorizationClientId: second.clientRecordId,
      consumedAt: new Date(),
      accessToken,
      refreshToken: null
    })
  ));
  if (consumed.filter(Boolean).length !== 1) {
    throw new Error("D1 device authorization issued tokens more than once");
  }
  const stored = await Promise.all(accessTokens.map(({ tokenHash }) =>
    authorizationStorage.getAuthorizationAccessTokenByHash(tokenHash)
  ));
  if (stored.filter(Boolean).length !== 1) {
    throw new Error("D1 device authorization did not persist exactly one access token");
  }
}

interface DeviceFixture {
  authorization: DeviceAuthorization;
  clientRecordId: string;
  grant: AuthorizationGrant;
  sessionId: string;
  userId: string;
}

async function createFixture(
  storage: AuthStorage,
  authorizationStorage: AuthorizationServerStorage,
  deviceStorage: DeviceAuthorizationStorage
): Promise<DeviceFixture> {
  const suffix = crypto.randomUUID();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 60_000);
  const userId = `usr_device_${suffix}`;
  const sessionId = `ses_device_${suffix}`;
  const clientRecordId = `ocli_device_${suffix}`;
  const grant: AuthorizationGrant = {
    id: `ogrant_device_${suffix}`,
    authorizationClientId: clientRecordId,
    userId,
    protectedResourceId: null,
    scopes: ["openid"],
    createdAt: now,
    updatedAt: now,
    revokedAt: null
  };
  const deviceAuthorization: DeviceAuthorization = {
    id: `oda_${suffix}`,
    deviceCodeHash: `device_code_${suffix}`,
    userCodeHash: `user_code_${suffix}`,
    authorizationClientId: clientRecordId,
    protectedResourceId: null,
    requestCiphertext: `ciphertext_${suffix}`,
    requestNonce: `nonce_${suffix}`,
    encryptionKeyId: "worker-conformance",
    dpopJkt: null,
    status: "pending",
    userId: null,
    sessionId: null,
    grantId: null,
    approvedScopes: [],
    pollingIntervalSeconds: 5,
    nextPollAt: new Date(now.getTime() + 5_000),
    expiresAt,
    approvedAt: null,
    deniedAt: null,
    consumedAt: null,
    createdAt: now
  };

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
  await storage.createSession({
    id: sessionId,
    userId,
    tokenHash: `session_${suffix}`,
    createdAt: now,
    lastActiveAt: now,
    expiresAt,
    idleExpiresAt: expiresAt,
    ipAddress: null,
    userAgent: null,
    revokedAt: null,
    revokeReason: null,
    authenticationMethods: ["password"],
    assuranceLevel: "aal1",
    authenticatedAt: now
  });
  await authorizationStorage.createAuthorizationClient({
    id: clientRecordId,
    clientId: `oa_client_${suffix}`,
    name: "D1 device race client",
    clientType: "public",
    applicationType: "native",
    tokenEndpointAuthMethod: "none",
    redirectUris: [],
    allowedScopes: ["openid"],
    grantTypes: [deviceAuthorizationGrantType],
    dpopBoundAccessTokens: false,
    status: "active",
    createdAt: now,
    updatedAt: now,
    revokedAt: null
  }, null);
  await deviceStorage.createDeviceAuthorization(deviceAuthorization);
  return {
    authorization: deviceAuthorization,
    clientRecordId,
    grant,
    sessionId,
    userId
  };
}

function createAccessToken(
  fixture: DeviceFixture,
  index: number
): AuthorizationAccessToken {
  const now = new Date();
  return {
    id: `oat_${fixture.authorization.id}_${index}`,
    tokenHash: `access_${fixture.authorization.id}_${index}`,
    prefix: `oa_at_device_${index}`,
    grantId: fixture.grant.id,
    authorizationClientId: fixture.clientRecordId,
    userId: fixture.userId,
    protectedResourceId: null,
    scopes: fixture.grant.scopes,
    dpopJkt: null,
    expiresAt: new Date(now.getTime() + 60_000),
    revokedAt: null,
    createdAt: now
  };
}
