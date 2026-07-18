import type {
  AuthorizationAccessToken,
  AuthorizationGrant,
  DeviceAuthorization,
  Session,
  User
} from "../../src/index.js";

export const deviceFixtureNow = new Date("2026-07-18T12:00:00.000Z");
export const deviceFixtureExpiry = new Date("2026-07-18T12:10:00.000Z");

export function deviceAuthorization(
  patch: Partial<DeviceAuthorization> = {}
): DeviceAuthorization {
  return {
    id: "oda_1",
    deviceCodeHash: "device-code-hash",
    userCodeHash: "user-code-hash",
    authorizationClientId: "ocli_1",
    protectedResourceId: null,
    requestCiphertext: "encrypted-request",
    requestNonce: "request-nonce",
    encryptionKeyId: "key-1",
    dpopJkt: null,
    status: "pending",
    userId: null,
    sessionId: null,
    grantId: null,
    approvedScopes: [],
    pollingIntervalSeconds: 5,
    nextPollAt: new Date(deviceFixtureNow.getTime() + 5_000),
    expiresAt: deviceFixtureExpiry,
    approvedAt: null,
    deniedAt: null,
    consumedAt: null,
    createdAt: deviceFixtureNow,
    ...patch
  };
}

export function deviceAuthorizationRow(
  dialect: "postgres" | "d1",
  patch: Record<string, unknown> = {}
): Record<string, unknown> {
  const timestamp = (date: Date) => dialect === "d1" ? date.getTime() : date;
  return {
    id: "oda_1",
    device_code_hash: "device-code-hash",
    user_code_hash: "user-code-hash",
    authorization_client_id: "ocli_1",
    protected_resource_id: null,
    request_ciphertext: "encrypted-request",
    request_nonce: "request-nonce",
    encryption_key_id: "key-1",
    dpop_jkt: null,
    status: "pending",
    user_id: null,
    session_id: null,
    grant_id: null,
    approved_scopes: dialect === "d1" ? "[]" : [],
    polling_interval_seconds: 5,
    next_poll_at: timestamp(new Date(deviceFixtureNow.getTime() + 5_000)),
    expires_at: timestamp(deviceFixtureExpiry),
    approved_at: null,
    denied_at: null,
    consumed_at: null,
    created_at: timestamp(deviceFixtureNow),
    ...patch
  };
}

export function deviceGrant(): AuthorizationGrant {
  return {
    id: "ogrant_1",
    authorizationClientId: "ocli_1",
    userId: "usr_1",
    protectedResourceId: null,
    scopes: ["openid"],
    createdAt: deviceFixtureNow,
    updatedAt: deviceFixtureNow,
    revokedAt: null
  };
}

export function deviceAccessToken(): AuthorizationAccessToken {
  return {
    id: "oat_1",
    tokenHash: "access-token-hash",
    prefix: "oa_at_example",
    grantId: "ogrant_1",
    authorizationClientId: "ocli_1",
    userId: "usr_1",
    protectedResourceId: null,
    scopes: ["openid"],
    dpopJkt: null,
    expiresAt: new Date(deviceFixtureNow.getTime() + 5 * 60 * 1_000),
    revokedAt: null,
    createdAt: deviceFixtureNow
  };
}

export function deviceUser(id = "usr_1"): User {
  return {
    id,
    email: `${id}@example.com`,
    emailVerifiedAt: deviceFixtureNow,
    phone: null,
    phoneVerifiedAt: null,
    passwordHash: null,
    name: null,
    imageUrl: null,
    disabledAt: null,
    metadata: {},
    createdAt: deviceFixtureNow,
    updatedAt: deviceFixtureNow,
    lastLoginAt: null
  };
}

export function deviceSession(userId = "usr_1"): Session {
  return {
    id: "ses_1",
    userId,
    tokenHash: "session-token-hash",
    createdAt: deviceFixtureNow,
    lastActiveAt: deviceFixtureNow,
    expiresAt: deviceFixtureExpiry,
    idleExpiresAt: deviceFixtureExpiry,
    ipAddress: null,
    userAgent: null,
    revokedAt: null,
    revokeReason: null,
    authenticationMethods: ["password"],
    assuranceLevel: "aal1",
    authenticatedAt: deviceFixtureNow
  };
}
