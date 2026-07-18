import type { AuthEngineContext } from "./auth-engine-context.js";
import { audit } from "./auth-engine-helpers.js";
import { createAuthorizationIdToken } from "./authorization-server-claims.js";
import { isActiveAuthorizationClient } from "./authorization-server-clients.js";
import { authorizationServerTokenPrefixes } from "./authorization-server-constants.js";
import { hashDeviceCode } from "./authorization-server-device-codes.js";
import { deviceAuthorizationGrantType } from "./authorization-server-device-types.js";
import { requireAuthorizationServer } from "./authorization-server-helpers.js";
import { decryptDeviceAuthorizationRequest } from "./authorization-server-device-request.js";
import { verifyAndConsumeDpopProof } from "./authorization-server-dpop.js";
import { authorizationTokenScopesAreActive } from "./authorization-server-protected-resources.js";
import { AuthorizationProtocolError } from "./authorization-server-protocol-error.js";
import {
  authorizationTokenResponse,
  createAuthorizationTokenPair,
  invalidAuthorizationGrant,
  loadAuthorizationTokenResource,
  optionalAuthorizationResource,
  usableAuthorizationSession
} from "./authorization-server-token-issuance.js";
import type {
  AuthorizationClient,
  AuthorizationTokenRequestInput,
  AuthorizationTokenResponse
} from "./authorization-server-types.js";

export async function exchangeDeviceAuthorizationToken(
  ctx: AuthEngineContext,
  client: AuthorizationClient,
  input: AuthorizationTokenRequestInput
): Promise<AuthorizationTokenResponse> {
  const { storage } = requireAuthorizationServer(ctx);
  const deviceStorage = ctx.deviceAuthorizationStorage;
  if (!ctx.authorizationServer?.deviceAuthorization || !deviceStorage) {
    throw new AuthorizationProtocolError(
      "unsupported_grant_type",
      "Device authorization is not enabled"
    );
  }
  const deviceCode = requiredDeviceCode(input.deviceCode);
  const deviceCodeHash = hashDeviceCode(ctx, deviceCode);
  const authorization = await deviceStorage.getDeviceAuthorizationByDeviceCodeHash(
    deviceCodeHash
  );
  if (
    !authorization ||
    authorization.authorizationClientId !== client.id
  ) {
    throw invalidAuthorizationGrant();
  }
  const storedRequest = await decryptDeviceAuthorizationRequest(ctx, authorization);
  const requestedResource = optionalAuthorizationResource(input.resource);
  const resource = await loadAuthorizationTokenResource(
    ctx,
    authorization.protectedResourceId,
    requestedResource
  );
  await verifyAndConsumeDpopProof(ctx, {
    proof: input.dpopProof,
    expectedJkt: authorization.dpopJkt,
    bindingRequired: client.dpopBoundAccessTokens || Boolean(resource?.requireDpop),
    method: input.requestMethod ?? "",
    url: input.requestUrl ?? "",
    now: new Date()
  });
  const poll = await deviceStorage.pollDeviceAuthorization({
    deviceCodeHash,
    authorizationClientId: client.id,
    polledAt: new Date()
  });
  if (poll.status !== "approved") throw devicePollError(poll.status);
  const approved = poll.authorization;
  if (
    approved.dpopJkt !== authorization.dpopJkt ||
    approved.protectedResourceId !== authorization.protectedResourceId ||
    storedRequest.resource !== (resource?.identifier ?? null) ||
    approved.approvedScopes.length === 0 ||
    approved.approvedScopes.some((scope) => !storedRequest.scopes.includes(scope)) ||
    !approved.userId ||
    !approved.sessionId ||
    !approved.grantId
  ) {
    throw invalidAuthorizationGrant();
  }
  const [grant, user, sessions, currentClient] = await Promise.all([
    storage.getAuthorizationGrant(
      client.id,
      approved.userId,
      approved.protectedResourceId
    ),
    ctx.storage.getUserById(approved.userId),
    ctx.storage.listSessionsByUserId(approved.userId),
    storage.getAuthorizationClientById(client.id)
  ]);
  const session = sessions.find((candidate) => candidate.id === approved.sessionId) ?? null;
  if (
    !isActiveAuthorizationClient(currentClient) ||
    !currentClient.grantTypes.includes(deviceAuthorizationGrantType) ||
    !grant ||
    grant.id !== approved.grantId ||
    grant.revokedAt ||
    !user ||
    user.disabledAt ||
    !usableAuthorizationSession(session) ||
    !authorizationTokenScopesAreActive(
      resource,
      grant.scopes,
      approved.approvedScopes
    )
  ) {
    throw invalidAuthorizationGrant();
  }
  const issued = createAuthorizationTokenPair(
    ctx,
    client,
    grant.id,
    user,
    approved.protectedResourceId,
    approved.approvedScopes,
    0,
    approved.dpopJkt
  );
  const idToken = approved.approvedScopes.includes("openid")
    ? await createAuthorizationIdToken(ctx, {
        client,
        user,
        session,
        scopes: approved.approvedScopes,
        accessToken: issued.access.raw,
        accessTokenExpiresAt: issued.access.entity.expiresAt,
        nonce: null
      })
    : undefined;
  const consumed = await deviceStorage.consumeDeviceAuthorization({
    id: approved.id,
    deviceCodeHash,
    authorizationClientId: client.id,
    consumedAt: new Date(),
    accessToken: issued.access.entity,
    refreshToken: issued.refresh?.entity ?? null
  });
  if (!consumed) throw invalidAuthorizationGrant();
  await audit(ctx, {
    eventType: "authorization_server.device_token_exchanged",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request,
    metadata: {
      authorizationClientId: client.id,
      grantId: grant.id,
      scopes: approved.approvedScopes,
      ...(resource ? { protectedResourceId: resource.id } : {})
    }
  });
  return authorizationTokenResponse(
    issued.access.raw,
    issued.access.entity.expiresAt,
    approved.approvedScopes,
    approved.dpopJkt,
    issued.refresh?.raw,
    idToken
  );
}

function requiredDeviceCode(value: string | undefined): string {
  if (
    !value ||
    !value.startsWith(authorizationServerTokenPrefixes.deviceCode) ||
    value.length > 512
  ) {
    throw invalidAuthorizationGrant();
  }
  return value;
}

function devicePollError(
  status: "invalid" | "expired" | "denied" | "consumed" |
    "authorization_pending" | "slow_down"
): AuthorizationProtocolError {
  if (status === "authorization_pending") {
    return new AuthorizationProtocolError(
      "authorization_pending",
      "The user has not completed authorization"
    );
  }
  if (status === "slow_down") {
    return new AuthorizationProtocolError(
      "slow_down",
      "The client is polling too quickly"
    );
  }
  if (status === "denied") {
    return new AuthorizationProtocolError(
      "access_denied",
      "The user denied the authorization request"
    );
  }
  if (status === "expired") {
    return new AuthorizationProtocolError(
      "expired_token",
      "The device code has expired"
    );
  }
  return invalidAuthorizationGrant();
}
