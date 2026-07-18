import type { AuthEngineContext } from "./auth-engine-context.js";
import { audit, rateLimit } from "./auth-engine-helpers.js";
import { getCurrentSession } from "./auth-engine-sessions.js";
import {
  authenticateAuthorizationClient,
  isActiveAuthorizationClient
} from "./authorization-server-clients.js";
import { scopeDetails } from "./authorization-server-config.js";
import {
  authorizationServerRateLimits,
  authorizationServerRateLimitWindowMs,
  authorizationServerTokenPrefixes
} from "./authorization-server-constants.js";
import type {
  CleanupDeviceAuthorizationsInput,
  CompleteDeviceAuthorizationInput,
  DenyDeviceAuthorizationInput,
  DeviceAuthorizationDecisionResult,
  DeviceAuthorizationRequestInput,
  DeviceAuthorizationResponse,
  GetDeviceAuthorizationInput,
  PublicDeviceAuthorization,
  StoredDeviceAuthorizationRequest
} from "./authorization-server-device-types.js";
import { deviceAuthorizationGrantType } from "./authorization-server-device-types.js";
import {
  createDeviceUserCode,
  formatDeviceUserCode,
  hashDeviceCode,
  hashDeviceUserCode,
  invalidDeviceAuthorization,
  normalizeDeviceUserCode
} from "./authorization-server-device-codes.js";
import {
  authorizationRequestDpopJkt
} from "./authorization-server-dpop.js";
import {
  parseRequestedScopes,
  requireAuthorizationServer
} from "./authorization-server-helpers.js";
import {
  decryptDeviceAuthorizationRequest,
  encryptDeviceAuthorizationRequest
} from "./authorization-server-device-request.js";
import { approvedAuthorizationScopes } from "./authorization-server-interaction-rules.js";
import {
  protectedResourceAllowsScopes,
  resolveProtectedResource
} from "./authorization-server-protected-resources.js";
import { AuthorizationProtocolError } from "./authorization-server-protocol-error.js";
import { optionalAuthorizationResource } from "./authorization-server-token-issuance.js";
import type { AuthorizationGrant, ProtectedResource } from "./authorization-server-types.js";
import { createId, randomBase64Url } from "./crypto.js";
import { AuthError } from "./errors.js";
import type { CurrentSession } from "./types.js";

export async function startDeviceAuthorization(
  ctx: AuthEngineContext,
  input: DeviceAuthorizationRequestInput
): Promise<DeviceAuthorizationResponse> {
  const { config, deviceConfig } = requireDeviceAuthorization(ctx);
  const client = await authenticateAuthorizationClient(ctx, input);
  requireDeviceGrant(client);
  await rateLimitDeviceStart(ctx, client.id, input.request?.ipAddress);
  const resourceIdentifier = optionalAuthorizationResource(input.resource);
  const resource = await resolveProtectedResource(ctx, resourceIdentifier);
  const scopes = parseRequestedScopes(config, client, input.scope);
  assertDeviceScopes(client, resource, scopes);
  const dpopJkt = authorizationRequestDpopJkt(
    ctx,
    client,
    input.dpopJkt,
    resource?.requireDpop ?? false
  );
  const now = new Date();
  const id = createId("oda");
  const deviceCode = `${authorizationServerTokenPrefixes.deviceCode}${randomBase64Url(32)}`;
  const userCode = createDeviceUserCode();
  const request: StoredDeviceAuthorizationRequest = {
    scopes,
    resource: resource?.identifier ?? null
  };
  const encrypted = await encryptDeviceAuthorizationRequest(
    ctx,
    id,
    client.id,
    request
  );
  const expiresAt = new Date(now.getTime() + deviceConfig.ttlMs);
  await ctx.deviceAuthorizationStorage!.createDeviceAuthorization({
    id,
    deviceCodeHash: hashDeviceCode(ctx, deviceCode),
    userCodeHash: hashDeviceUserCode(ctx, userCode),
    authorizationClientId: client.id,
    protectedResourceId: resource?.id ?? null,
    requestCiphertext: encrypted.ciphertext,
    requestNonce: encrypted.nonce,
    encryptionKeyId: encrypted.encryptionKeyId,
    dpopJkt,
    status: "pending",
    userId: null,
    sessionId: null,
    grantId: null,
    approvedScopes: [],
    pollingIntervalSeconds: deviceConfig.pollingIntervalSeconds,
    nextPollAt: new Date(
      now.getTime() + deviceConfig.pollingIntervalSeconds * 1000
    ),
    expiresAt,
    approvedAt: null,
    deniedAt: null,
    consumedAt: null,
    createdAt: now
  });
  await audit(ctx, {
    eventType: "authorization_server.device_authorization_started",
    metadata: auditMetadata(client.id, resource, scopes),
    context: input.request
  });
  const complete = new URL(deviceConfig.verificationUrl);
  complete.searchParams.set("user_code", formatDeviceUserCode(userCode));
  return {
    device_code: deviceCode,
    user_code: formatDeviceUserCode(userCode),
    verification_uri: deviceConfig.verificationUrl,
    verification_uri_complete: complete.toString(),
    expires_in: Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000)),
    interval: deviceConfig.pollingIntervalSeconds
  };
}

export async function getDeviceAuthorization(
  ctx: AuthEngineContext,
  input: GetDeviceAuthorizationInput
): Promise<PublicDeviceAuthorization> {
  const current = input.sessionToken
    ? await getCurrentSession(ctx, input.sessionToken)
    : null;
  await rateLimitDeviceLookup(ctx, input.request?.ipAddress, current?.user.id);
  const loaded = await loadPageAuthorization(ctx, input.userCode);
  if (!current) return publicDeviceAuthorization(loaded, "sign_in");
  const grant = await loaded.storage.getAuthorizationGrant(
    loaded.client.id,
    current.user.id,
    loaded.resource?.id ?? null
  );
  return publicDeviceAuthorization(
    loaded,
    deviceInteractionAction(grant, loaded.request.scopes)
  );
}

function publicDeviceAuthorization(
  loaded: Awaited<ReturnType<typeof loadPageAuthorization>>,
  action: PublicDeviceAuthorization["action"]
): PublicDeviceAuthorization {
  return {
    action,
    userCode: loaded.formattedUserCode,
    client: {
      name: loaded.client.name,
      applicationType: loaded.client.applicationType
    },
    resource: loaded.resource
      ? { name: loaded.resource.name }
      : null,
    scopes: scopeDetails(loaded.config, loaded.request.scopes),
    requiredAssuranceLevel: null,
    expiresAt: loaded.authorization.expiresAt
  };
}

export async function approveDeviceAuthorization(
  ctx: AuthEngineContext,
  input: CompleteDeviceAuthorizationInput
): Promise<void> {
  const current = await requireDeviceSession(ctx, input.sessionToken);
  await rateLimitDeviceLookup(ctx, input.request?.ipAddress, current.user.id);
  const loaded = await loadPageAuthorization(ctx, input.userCode);
  const existingGrant = await loaded.storage.getAuthorizationGrant(
    loaded.client.id,
    current.user.id,
    loaded.resource?.id ?? null
  );
  const action = deviceInteractionAction(existingGrant, loaded.request.scopes);
  const approvedScopes = approvedAuthorizationScopes(
    loaded.request.scopes,
    existingGrant,
    action,
    input.approvedScopes ?? loaded.request.scopes
  );
  const now = new Date();
  const grant: AuthorizationGrant = {
    id: existingGrant?.id ?? createId("ogrant"),
    authorizationClientId: loaded.client.id,
    userId: current.user.id,
    protectedResourceId: loaded.resource?.id ?? null,
    scopes: [...new Set([...(existingGrant?.scopes ?? []), ...approvedScopes])],
    createdAt: existingGrant?.createdAt ?? now,
    updatedAt: now,
    revokedAt: null
  };
  const result = await loaded.deviceStorage.approveDeviceAuthorization({
    userCodeHash: loaded.authorization.userCodeHash,
    userId: current.user.id,
    sessionId: current.session.id,
    approvedScopes,
    grant,
    decidedAt: now
  });
  assertDeviceDecision(result.status);
  await audit(ctx, {
    eventType: "authorization_server.device_authorization_approved",
    actorUserId: current.user.id,
    targetUserId: current.user.id,
    metadata: {
      ...auditMetadata(loaded.client.id, loaded.resource, approvedScopes),
      grantId: result.status === "approved" ? result.grant.id : grant.id
    },
    context: input.request
  });
}

export async function denyDeviceAuthorization(
  ctx: AuthEngineContext,
  input: DenyDeviceAuthorizationInput
): Promise<void> {
  const current = await requireDeviceSession(ctx, input.sessionToken);
  await rateLimitDeviceLookup(ctx, input.request?.ipAddress, current.user.id);
  const loaded = await loadPageAuthorization(ctx, input.userCode);
  const result = await loaded.deviceStorage.denyDeviceAuthorization({
    userCodeHash: loaded.authorization.userCodeHash,
    userId: current.user.id,
    sessionId: current.session.id,
    decidedAt: new Date()
  });
  assertDeviceDecision(result.status);
  await audit(ctx, {
    eventType: "authorization_server.device_authorization_denied",
    actorUserId: current.user.id,
    targetUserId: current.user.id,
    metadata: auditMetadata(
      loaded.client.id,
      loaded.resource,
      loaded.request.scopes
    ),
    context: input.request
  });
}

export function cleanupDeviceAuthorizations(
  ctx: AuthEngineContext,
  input: CleanupDeviceAuthorizationsInput
): Promise<number> {
  requireDeviceAuthorization(ctx);
  if (!(input.olderThan instanceof Date) || !Number.isFinite(input.olderThan.getTime())) {
    throw new AuthError("validation_error", "olderThan must be a valid date", 400);
  }
  return ctx.deviceAuthorizationStorage!.cleanupDeviceAuthorizations(input.olderThan);
}

async function loadPageAuthorization(ctx: AuthEngineContext, rawCode: string) {
  const { config, storage, deviceStorage } = requireDeviceAuthorization(ctx);
  const userCode = normalizeDeviceUserCode(rawCode);
  const authorization = await deviceStorage.getDeviceAuthorizationByUserCodeHash(
    hashDeviceUserCode(ctx, userCode)
  );
  if (!authorization) throw invalidDeviceAuthorization();
  if (authorization.expiresAt.getTime() <= Date.now()) throw invalidDeviceAuthorization();
  if (authorization.status !== "pending") throw alreadyDecided();
  const client = await storage.getAuthorizationClientById(
    authorization.authorizationClientId
  );
  if (
    !isActiveAuthorizationClient(client) ||
    !client.grantTypes.includes(deviceAuthorizationGrantType)
  ) {
    throw invalidDeviceAuthorization();
  }
  const request = await decryptDeviceAuthorizationRequest(ctx, authorization);
  const resource = await resolveProtectedResource(ctx, request.resource).catch(() => {
    throw invalidDeviceAuthorization();
  });
  if (
    authorization.protectedResourceId !== (resource?.id ?? null) ||
    !protectedResourceAllowsScopes(resource, request.scopes) ||
    request.scopes.some((scope) => !client.allowedScopes.includes(scope))
  ) {
    throw invalidDeviceAuthorization();
  }
  return {
    authorization,
    client,
    config,
    deviceStorage,
    formattedUserCode: formatDeviceUserCode(userCode),
    request,
    resource,
    storage
  };
}

function requireDeviceAuthorization(ctx: AuthEngineContext) {
  const { config, storage } = requireAuthorizationServer(ctx);
  const deviceConfig = config.deviceAuthorization;
  const deviceStorage = ctx.deviceAuthorizationStorage;
  if (!deviceConfig || !deviceStorage) {
    throw new AuthError(
      "authorization_server_not_configured",
      "OAuth device authorization is not configured",
      404
    );
  }
  return { config, deviceConfig, storage, deviceStorage };
}

function requireDeviceGrant(client: { grantTypes: readonly string[] }): void {
  if (!client.grantTypes.includes(deviceAuthorizationGrantType)) {
    throw new AuthorizationProtocolError(
      "unauthorized_client",
      "The authorization client cannot use device authorization"
    );
  }
}

function assertDeviceScopes(
  client: { grantTypes: readonly string[] },
  resource: ProtectedResource | null,
  scopes: readonly string[]
): void {
  if (!protectedResourceAllowsScopes(resource, scopes)) {
    throw new AuthorizationProtocolError(
      "invalid_scope",
      "Requested scope is not allowed for the protected resource"
    );
  }
  if (scopes.includes("offline_access") && !client.grantTypes.includes("refresh_token")) {
    throw new AuthorizationProtocolError(
      "invalid_scope",
      "offline_access requires the refresh_token grant"
    );
  }
}

function deviceInteractionAction(
  grant: AuthorizationGrant | null,
  scopes: readonly string[]
): "consent" | "continue" {
  return !grant || grant.revokedAt || scopes.some((scope) => !grant.scopes.includes(scope))
    ? "consent"
    : "continue";
}

async function requireDeviceSession(
  ctx: AuthEngineContext,
  sessionToken: string
): Promise<CurrentSession> {
  const current = await getCurrentSession(ctx, sessionToken);
  if (!current) throw new AuthError("invalid_session", "A valid session is required", 401);
  return current;
}

async function rateLimitDeviceStart(
  ctx: AuthEngineContext,
  clientId: string,
  ipAddress: string | undefined
): Promise<void> {
  await rateLimit(
    ctx,
    "authorization_server_device_start_client",
    clientId,
    authorizationServerRateLimits.deviceStart,
    authorizationServerRateLimitWindowMs
  );
  if (ipAddress) {
    await rateLimit(
      ctx,
      "authorization_server_device_start_ip",
      ipAddress,
      authorizationServerRateLimits.deviceStart,
      authorizationServerRateLimitWindowMs
    );
  }
}

async function rateLimitDeviceLookup(
  ctx: AuthEngineContext,
  ipAddress: string | undefined,
  userId: string | undefined
): Promise<void> {
  if (ipAddress) {
    await rateLimit(
      ctx,
      "authorization_server_device_lookup_ip",
      ipAddress,
      authorizationServerRateLimits.deviceLookup,
      authorizationServerRateLimitWindowMs
    );
  }
  if (userId) {
    await rateLimit(
      ctx,
      "authorization_server_device_lookup_user",
      userId,
      authorizationServerRateLimits.deviceLookup,
      authorizationServerRateLimitWindowMs
    );
  }
}

function assertDeviceDecision(
  status: DeviceAuthorizationDecisionResult["status"]
): void {
  if (status === "already_decided") throw alreadyDecided();
  if (status === "invalid") throw invalidDeviceAuthorization();
}

function alreadyDecided(): AuthError {
  return new AuthError(
    "device_authorization_already_decided",
    "Device authorization has already been approved or denied",
    409
  );
}

function auditMetadata(
  authorizationClientId: string,
  resource: ProtectedResource | null,
  scopes: readonly string[]
) {
  return {
    authorizationClientId,
    scopes: [...scopes],
    ...(resource ? { protectedResourceId: resource.id } : {})
  };
}
