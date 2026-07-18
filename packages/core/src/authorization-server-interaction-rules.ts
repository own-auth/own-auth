import type { AuthEngineContext } from "./auth-engine-context.js";
import { audit } from "./auth-engine-helpers.js";
import {
  authorizationRedirectUrl,
  createAuthorizationCodeToken,
  encryptAuthorizationNonce,
  hashAuthorizationSecret,
  requiredAssuranceLevel,
  requireAuthorizationServer
} from "./authorization-server-helpers.js";
import type {
  AuthorizationClient,
  AuthorizationGrant,
  AuthorizationInteraction,
  AuthorizationInteractionAction,
  AuthorizationRedirectResult,
  AuthorizationRequestInput,
  ProtectedResource,
  StoredAuthorizationRequest
} from "./authorization-server-types.js";
import { createId } from "./crypto.js";
import { AuthError } from "./errors.js";
import type { CurrentSession } from "./types.js";

export async function issueAuthorizationCode(
  ctx: AuthEngineContext,
  client: AuthorizationClient,
  current: CurrentSession,
  grant: AuthorizationGrant,
  request: StoredAuthorizationRequest,
  resource: ProtectedResource | null,
  context: AuthorizationRequestInput["request"]
): Promise<AuthorizationRedirectResult> {
  const { config, storage } = requireAuthorizationServer(ctx);
  const rawCode = createAuthorizationCodeToken();
  const codeId = createId("ocode");
  const encryptedNonce = request.nonce
    ? await encryptAuthorizationNonce(ctx, codeId, client.id, request.nonce)
    : null;
  const now = new Date();
  await storage.createAuthorizationCode({
    id: codeId,
    codeHash: hashAuthorizationSecret(ctx, rawCode),
    grantId: grant.id,
    authorizationClientId: client.id,
    userId: current.user.id,
    protectedResourceId: resource?.id ?? null,
    sessionId: current.session.id,
    redirectUri: request.redirectUri,
    scopes: [...request.scopes],
    codeChallenge: request.codeChallenge,
    nonceCiphertext: encryptedNonce?.ciphertext ?? null,
    nonceNonce: encryptedNonce?.nonce ?? null,
    encryptionKeyId: encryptedNonce?.encryptionKeyId ?? null,
    dpopJkt: request.dpopJkt,
    expiresAt: new Date(now.getTime() + config.authorizationCodeTtlMs),
    consumedAt: null,
    createdAt: now
  });
  await audit(ctx, {
    eventType: "authorization_server.authorization_approved",
    actorUserId: current.user.id,
    targetUserId: current.user.id,
    context,
    metadata: {
      authorizationClientId: client.id,
      grantId: grant.id,
      scopes: request.scopes,
      ...(resource ? { protectedResourceId: resource.id } : {})
    }
  });
  return {
    redirectUrl: authorizationRedirectUrl(request.redirectUri, {
      code: rawCode,
      state: request.state
    })
  };
}

export function interactionAction(
  request: StoredAuthorizationRequest,
  current: CurrentSession | null,
  grant: AuthorizationGrant | null,
  now: Date,
  interaction: AuthorizationInteraction | null
): AuthorizationInteractionAction {
  if (!current) return "sign_in";
  if (
    request.prompts.includes("login") &&
    (!interaction ||
      current.session.authenticatedAt.getTime() <= interaction.createdAt.getTime())
  ) {
    return "reauthenticate";
  }
  if (
    request.maxAgeSeconds !== null &&
    (request.maxAgeSeconds === 0 ||
      now.getTime() - current.session.authenticatedAt.getTime() >
        request.maxAgeSeconds * 1000)
  ) {
    return "reauthenticate";
  }
  if (
    requiredAssuranceLevel(request.acrValues) === "aal2" &&
    current.session.assuranceLevel !== "aal2"
  ) {
    return "mfa";
  }
  if (request.prompts.includes("select_account") && !interaction?.userId) {
    return "select_account";
  }
  if (
    request.prompts.includes("consent") ||
    !grant ||
    grant.revokedAt ||
    request.scopes.some((scope) => !grant.scopes.includes(scope))
  ) {
    return "consent";
  }
  return "continue";
}

export function approvedInteractionScopes(
  request: StoredAuthorizationRequest,
  grant: AuthorizationGrant | null,
  action: AuthorizationInteractionAction,
  approved: string[] | undefined
): string[] {
  return approvedAuthorizationScopes(
    request.scopes,
    grant,
    action,
    approved
  );
}

export function approvedAuthorizationScopes(
  requestedScopes: readonly string[],
  grant: AuthorizationGrant | null,
  action: AuthorizationInteractionAction,
  approved: string[] | undefined
): string[] {
  if (action !== "consent" && approved === undefined) return [...requestedScopes];
  if (!approved || approved.length === 0 || new Set(approved).size !== approved.length) {
    throw new AuthError("validation_error", "approvedScopes must not be empty", 400);
  }
  if (approved.some((scope) => !requestedScopes.includes(scope))) {
    throw new AuthError(
      "validation_error",
      "approvedScopes must be requested by the client",
      400
    );
  }
  if (requestedScopes.includes("openid") && !approved.includes("openid")) {
    throw new AuthError("validation_error", "The openid scope cannot be removed", 400);
  }
  if (action !== "consent" && grant) {
    return approved.filter((scope) => grant.scopes.includes(scope));
  }
  return [...approved];
}

export function assertInteractionRequirementsSatisfied(
  action: AuthorizationInteractionAction
): void {
  if (action === "sign_in" || action === "reauthenticate") {
    throw new AuthError("invalid_session", "A recent sign-in is required", 401);
  }
  if (action === "mfa") {
    throw new AuthError("mfa_required", "Multi-factor authentication is required", 401);
  }
}
