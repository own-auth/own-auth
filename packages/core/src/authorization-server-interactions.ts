import type { AuthEngineContext } from "./auth-engine-context.js";
import { audit, rateLimit } from "./auth-engine-helpers.js";
import { getCurrentSession } from "./auth-engine-sessions.js";
import { isActiveAuthorizationClient } from "./authorization-server-clients.js";
import { scopeDetails } from "./authorization-server-config.js";
import {
  authorizationServerRateLimits,
  authorizationServerRateLimitWindowMs,
  authorizationServerTokenPrefixes
} from "./authorization-server-constants.js";
import {
  authorizationRedirectUrl,
  decryptAuthorizationRequest,
  hashAuthorizationSecret,
  requiredAssuranceLevel,
  requireAuthorizationServer
} from "./authorization-server-helpers.js";
import {
  approvedInteractionScopes,
  assertInteractionRequirementsSatisfied,
  interactionAction,
  issueAuthorizationCode
} from "./authorization-server-interaction-rules.js";
import type {
  AuthorizationRedirectResult,
  CompleteAuthorizationInteractionInput,
  DenyAuthorizationInteractionInput,
  GetAuthorizationInteractionInput,
  PublicAuthorizationInteraction
} from "./authorization-server-types.js";
import { createId } from "./crypto.js";
import { AuthError } from "./errors.js";
import type { CurrentSession } from "./types.js";

export async function getAuthorizationInteraction(
  ctx: AuthEngineContext,
  input: GetAuthorizationInteractionInput
): Promise<PublicAuthorizationInteraction> {
  const now = new Date();
  const loaded = await loadInteraction(ctx, input.interactionToken, now);
  const requiredLevel = requiredAssuranceLevel(loaded.request.acrValues);
  if (!input.sessionToken) {
    return unauthenticatedInteraction(loaded.interaction.expiresAt);
  }
  const current = await getCurrentSession(ctx, input.sessionToken);
  if (!current) {
    return unauthenticatedInteraction(loaded.interaction.expiresAt);
  }
  const grant = await loaded.storage.getAuthorizationGrant(
    loaded.client.id,
    current.user.id
  );
  const action = interactionAction(
    loaded.request,
    current,
    grant,
    now,
    loaded.interaction
  );
  if (!["sign_in", "reauthenticate", "select_account"].includes(action)) {
    const bound = await loaded.storage.bindAuthorizationInteractionToUser(
      loaded.interaction.interactionHash,
      current.user.id,
      now
    );
    if (!bound) throw invalidInteraction();
  }
  return {
    action,
    client: {
      clientId: loaded.client.clientId,
      name: loaded.client.name,
      applicationType: loaded.client.applicationType
    },
    scopes: scopeDetails(loaded.config, loaded.request.scopes),
    requiredAssuranceLevel: requiredLevel,
    expiresAt: loaded.interaction.expiresAt
  };
}

export async function approveAuthorizationInteraction(
  ctx: AuthEngineContext,
  input: CompleteAuthorizationInteractionInput
): Promise<AuthorizationRedirectResult> {
  const now = new Date();
  const loaded = await loadInteraction(ctx, input.interactionToken, now);
  const current = await requireInteractionSession(ctx, input.sessionToken);
  await rateLimit(
    ctx,
    "authorization_server_interaction",
    current.user.id,
    authorizationServerRateLimits.interaction,
    authorizationServerRateLimitWindowMs
  );
  const bound = await loaded.storage.bindAuthorizationInteractionToUser(
    loaded.interaction.interactionHash,
    current.user.id,
    now
  );
  if (!bound) throw invalidInteraction();

  const existingGrant = await loaded.storage.getAuthorizationGrant(
    loaded.client.id,
    current.user.id
  );
  const action = interactionAction(
    loaded.request,
    current,
    existingGrant,
    now,
    bound
  );
  assertInteractionRequirementsSatisfied(action);
  const approvedScopes = approvedInteractionScopes(
    loaded.request,
    existingGrant,
    action,
    input.approvedScopes
  );
  const consumed = await loaded.storage.consumeAuthorizationInteraction(
    bound.interactionHash,
    current.user.id,
    "approved",
    now
  );
  if (!consumed) throw invalidInteraction();

  const grant = await loaded.storage.upsertAuthorizationGrant({
    id: existingGrant?.id ?? createId("ogrant"),
    authorizationClientId: loaded.client.id,
    userId: current.user.id,
    scopes: [...new Set([...(existingGrant?.scopes ?? []), ...approvedScopes])],
    createdAt: existingGrant?.createdAt ?? now,
    updatedAt: now,
    revokedAt: null
  });
  return issueAuthorizationCode(
    ctx,
    loaded.client,
    current,
    grant,
    { ...loaded.request, scopes: approvedScopes },
    input.request
  );
}

export async function denyAuthorizationInteraction(
  ctx: AuthEngineContext,
  input: DenyAuthorizationInteractionInput
): Promise<AuthorizationRedirectResult> {
  const now = new Date();
  const loaded = await loadInteraction(ctx, input.interactionToken, now);
  const current = await requireInteractionSession(ctx, input.sessionToken);
  const bound = await loaded.storage.bindAuthorizationInteractionToUser(
    loaded.interaction.interactionHash,
    current.user.id,
    now
  );
  if (!bound) throw invalidInteraction();
  const consumed = await loaded.storage.consumeAuthorizationInteraction(
    bound.interactionHash,
    current.user.id,
    "denied",
    now
  );
  if (!consumed) throw invalidInteraction();
  await audit(ctx, {
    eventType: "authorization_server.authorization_denied",
    actorUserId: current.user.id,
    targetUserId: current.user.id,
    context: input.request,
    metadata: { authorizationClientId: loaded.client.id }
  });
  return {
    redirectUrl: authorizationRedirectUrl(loaded.request.redirectUri, {
      error: "access_denied",
      error_description: "The user denied the authorization request",
      state: loaded.request.state
    })
  };
}

async function loadInteraction(
  ctx: AuthEngineContext,
  rawToken: string,
  now: Date
) {
  if (
    typeof rawToken !== "string" ||
    !rawToken.startsWith(authorizationServerTokenPrefixes.interaction)
  ) {
    throw invalidInteraction();
  }
  const { config, storage } = requireAuthorizationServer(ctx);
  const interaction = await storage.getAuthorizationInteractionByHash(
    hashAuthorizationSecret(ctx, rawToken),
    now
  );
  if (!interaction) throw invalidInteraction();
  const client = await storage.getAuthorizationClientById(
    interaction.authorizationClientId
  );
  if (!isActiveAuthorizationClient(client)) {
    throw invalidInteraction();
  }
  const request = await decryptAuthorizationRequest(ctx, interaction);
  return { client, config, interaction, request, storage };
}

async function requireInteractionSession(
  ctx: AuthEngineContext,
  sessionToken: string
): Promise<CurrentSession> {
  const current = await getCurrentSession(ctx, sessionToken);
  if (!current) {
    throw new AuthError("invalid_session", "A valid session is required", 401);
  }
  return current;
}

function unauthenticatedInteraction(
  expiresAt: Date
): PublicAuthorizationInteraction {
  return {
    action: "sign_in",
    client: null,
    scopes: [],
    requiredAssuranceLevel: null,
    expiresAt
  };
}

function invalidInteraction(): AuthError {
  return new AuthError(
    "authorization_interaction_invalid",
    "Authorization interaction is invalid or expired",
    400
  );
}
