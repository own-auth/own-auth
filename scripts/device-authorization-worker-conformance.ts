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
  const outsider = await createFixture(storage, authorizationStorage, deviceStorage[0]);
  const unclaimed = await Promise.all([
    deviceStorage[0].approveDeviceAuthorization(decisionInput(first)),
    deviceStorage[1].denyDeviceAuthorization(decisionInput(first))
  ]);
  if (unclaimed.some(({ status }) => status !== "invalid")) {
    throw new Error("An unclaimed device request accepted a decision");
  }
  const claims = await Promise.all([first, outsider].map((reviewer, index) =>
    deviceStorage[index as 0 | 1].claimDeviceAuthorization({
      ...reviewerInput(first, reviewer), claimedAt: new Date()
    })
  ));
  if (claims.filter(Boolean).length !== 1) throw new Error("Device reviewer claim race did not produce one winner");
  const winner = claims[0] ? first : outsider;
  const loser = claims[0] ? outsider : first;
  await assertReviewerRejected(first, loser, deviceStorage, authorizationStorage);
  const reviewingSession = (await storage.listSessionsByUserId(winner.userId))
    .find((session) => session.id === winner.sessionId);
  if (!reviewingSession) throw new Error("Device reviewer session fixture is missing");
  const alternateSession = await storage.createSession({ ...reviewingSession,
    id: `${winner.sessionId}_alternate`, tokenHash: `${reviewingSession.tokenHash}_alternate` });
  await assertReviewerRejected(first, { userId: winner.userId, sessionId: alternateSession.id },
    deviceStorage, authorizationStorage);
  const decisions = await Promise.all([
    deviceStorage[0].approveDeviceAuthorization(decisionInput(first, winner)),
    deviceStorage[1].denyDeviceAuthorization(decisionInput(first, winner))
  ]);
  const decisionStatuses = decisions.map(({ status }) => status);
  if (
    decisionStatuses.filter((status) => status === "already_decided").length !== 1 ||
    decisionStatuses.filter((status) => status === "approved" || status === "denied")
      .length !== 1
  ) {
    throw new Error("Device authorization decision race did not produce one winner");
  }

  const second = await createFixture(storage, authorizationStorage, deviceStorage[0]);
  if (await deviceStorage[0].claimDeviceAuthorization({ ...reviewerInput(second), claimedAt: second.authorization.expiresAt })) {
    throw new Error("An expired device request accepted a reviewer");
  }
  await deviceStorage[0].claimDeviceAuthorization({ ...reviewerInput(second), claimedAt: new Date() });
  const approval = await deviceStorage[0].approveDeviceAuthorization(decisionInput(second));
  if (approval.status !== "approved") {
    throw new Error("Device authorization fixture could not be approved");
  }
  if (await deviceStorage[1].claimDeviceAuthorization({ ...reviewerInput(second), claimedAt: new Date() })) {
    throw new Error("A decided device request accepted another reviewer claim");
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
    throw new Error("Device authorization issued tokens more than once");
  }
  const stored = await Promise.all(accessTokens.map(({ tokenHash }) =>
    authorizationStorage.getAuthorizationAccessTokenByHash(tokenHash)
  ));
  if (stored.filter(Boolean).length !== 1) {
    throw new Error("Device authorization did not persist exactly one access token");
  }
}

interface DeviceFixture {
  authorization: DeviceAuthorization;
  clientRecordId: string;
  grant: AuthorizationGrant;
  sessionId: string;
  userId: string;
}

type DeviceReviewer = Pick<DeviceFixture, "userId" | "sessionId">;

function reviewerInput(fixture: DeviceFixture, reviewer: DeviceReviewer = fixture) {
  return { userCodeHash: fixture.authorization.userCodeHash, userId: reviewer.userId, sessionId: reviewer.sessionId };
}

function decisionInput(fixture: DeviceFixture, reviewer: DeviceReviewer = fixture) {
  return { ...reviewerInput(fixture, reviewer), approvedScopes: fixture.grant.scopes,
    grant: { ...fixture.grant, userId: reviewer.userId }, decidedAt: new Date() };
}

async function assertReviewerRejected(
  fixture: DeviceFixture,
  reviewer: DeviceReviewer,
  storage: readonly [DeviceAuthorizationStorage, DeviceAuthorizationStorage],
  authorizationStorage: AuthorizationServerStorage
): Promise<void> {
  const decisions = await Promise.all([
    storage[0].approveDeviceAuthorization(decisionInput(fixture, reviewer)),
    storage[1].denyDeviceAuthorization(decisionInput(fixture, reviewer))
  ]);
  const claim = await storage[1].claimDeviceAuthorization({ ...reviewerInput(fixture, reviewer), claimedAt: new Date() });
  if (claim || decisions.some(({ status }) => status !== "invalid")) {
    throw new Error("Another session changed the claimed device request");
  }
  if (await authorizationStorage.getAuthorizationGrant(fixture.clientRecordId, reviewer.userId, null)) {
    throw new Error("A rejected device decision persisted an unauthorized grant");
  }
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
    name: "Device race client",
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
