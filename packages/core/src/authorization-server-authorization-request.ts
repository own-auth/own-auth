import type { AuthEngineContext } from "./auth-engine-context.js";
import { audit, rateLimit } from "./auth-engine-helpers.js";
import { getCurrentSession } from "./auth-engine-sessions.js";
import { requireProtocolClient } from "./authorization-server-clients.js";
import type { AuthorizationServerRuntimeConfig } from "./authorization-server-config.js";
import {
  authorizationServerRateLimits,
  authorizationServerRateLimitWindowMs
} from "./authorization-server-constants.js";
import {
  assertCodeChallenge,
  createInteractionToken,
  encryptAuthorizationRequest,
  hashAuthorizationSecret,
  parseMaxAge,
  parseOptionalList,
  parsePrompts,
  parseRequestedScopes,
  requireAuthorizationServer
} from "./authorization-server-helpers.js";
import {
  interactionAction,
  issueAuthorizationCode
} from "./authorization-server-interaction-rules.js";
import { AuthorizationProtocolError } from "./authorization-server-protocol-error.js";
import type {
  AuthorizationClient,
  AuthorizationInteractionAction,
  AuthorizationRedirectResult,
  AuthorizationRequestInput,
  StoredAuthorizationRequest
} from "./authorization-server-types.js";
import { createId } from "./crypto.js";
import { AuthError } from "./errors.js";

export async function startAuthorization(
  ctx: AuthEngineContext,
  input: AuthorizationRequestInput
): Promise<AuthorizationRedirectResult> {
  const { config, storage } = requireAuthorizationServer(ctx);
  const client = await requireProtocolClient(
    ctx,
    requiredText(input.clientId, "client_id")
  );
  const redirectUri = requireRegisteredRedirect(client, input.redirectUri);
  const state = optionalText(input.state, "state", 2_048);
  if (input.responseType !== "code") {
    throw redirectError(
      "unsupported_response_type",
      "Only the authorization code flow is supported",
      redirectUri,
      state
    );
  }
  if (input.responseMode !== undefined && input.responseMode !== "query") {
    throw redirectError(
      "unsupported_response_mode",
      "Only query authorization responses are supported",
      redirectUri,
      state
    );
  }
  if (input.requestObject !== undefined || input.requestUri !== undefined) {
    throw redirectError(
      "invalid_request",
      "Signed request objects are not supported",
      redirectUri,
      state
    );
  }
  await enforceProtocolRateLimit(
    ctx,
    input.request?.ipAddress,
    redirectUri,
    state
  );

  const request = buildStoredAuthorizationRequest(
    config,
    client,
    input,
    redirectUri,
    state
  );
  const current = input.sessionToken
    ? await getCurrentSession(ctx, input.sessionToken)
    : null;
  const grant = current
    ? await storage.getAuthorizationGrant(client.id, current.user.id)
    : null;
  const now = new Date();
  const action = interactionAction(request, current, grant, now, null);

  if (request.prompts.includes("none")) {
    assertSilentAuthorizationAllowed(action, redirectUri, state);
  }
  if (current && action === "continue" && grant) {
    await auditAuthorizationStarted(ctx, client, current.user.id, input);
    return issueAuthorizationCode(
      ctx,
      client,
      current,
      grant,
      request,
      input.request
    );
  }

  const rawInteraction = createInteractionToken();
  const interactionId = createId("oint");
  const encrypted = await encryptAuthorizationRequest(
    ctx,
    interactionId,
    client.id,
    request
  );
  await storage.createAuthorizationInteraction({
    id: interactionId,
    interactionHash: hashAuthorizationSecret(ctx, rawInteraction),
    authorizationClientId: client.id,
    userId: null,
    requestCiphertext: encrypted.ciphertext,
    requestNonce: encrypted.nonce,
    encryptionKeyId: encrypted.encryptionKeyId,
    status: "pending",
    expiresAt: new Date(now.getTime() + config.interactionTtlMs),
    consumedAt: null,
    createdAt: now
  });
  await auditAuthorizationStarted(ctx, client, current?.user.id ?? null, input);
  const interactionUrl = new URL(config.interactionUrl);
  interactionUrl.searchParams.set("interaction", rawInteraction);
  return { redirectUrl: interactionUrl.toString() };
}

function buildStoredAuthorizationRequest(
  config: AuthorizationServerRuntimeConfig,
  client: AuthorizationClient,
  input: AuthorizationRequestInput,
  redirectUri: string,
  state: string | null
): StoredAuthorizationRequest {
  let scopes: string[];
  try {
    scopes = parseRequestedScopes(config, client, input.scope);
  } catch (error) {
    if (error instanceof AuthError) {
      throw redirectError(
        "invalid_scope",
        error.safeMessage,
        redirectUri,
        state
      );
    }
    throw error;
  }

  try {
    const nonce = optionalText(input.nonce, "nonce", 512);
    if (nonce && !scopes.includes("openid")) {
      throw new AuthError("validation_error", "nonce requires the openid scope", 400);
    }
    return {
      redirectUri,
      scopes,
      state,
      nonce,
      codeChallenge: assertCodeChallenge(
        input.codeChallenge,
        input.codeChallengeMethod
      ),
      prompts: parsePrompts(input.prompt),
      maxAgeSeconds: parseMaxAge(input.maxAge),
      acrValues: parseOptionalList(input.acrValues, "acr_values"),
      display: optionalText(input.display, "display", 64),
      uiLocales: parseOptionalList(input.uiLocales, "ui_locales"),
      claimsLocales: parseOptionalList(input.claimsLocales, "claims_locales"),
      loginHint: optionalText(input.loginHint, "login_hint", 320)
    };
  } catch (error) {
    if (error instanceof AuthError) {
      throw redirectError(
        "invalid_request",
        error.safeMessage,
        redirectUri,
        state
      );
    }
    throw error;
  }
}

function assertSilentAuthorizationAllowed(
  action: AuthorizationInteractionAction,
  redirectUri: string,
  state: string | null
): void {
  if (action === "sign_in" || action === "reauthenticate") {
    throw redirectError("login_required", "The user must sign in", redirectUri, state);
  }
  if (action === "consent") {
    throw redirectError(
      "consent_required",
      "The requested access has not been approved",
      redirectUri,
      state
    );
  }
  if (action === "mfa" || action === "select_account") {
    throw redirectError(
      "interaction_required",
      "Additional user interaction is required",
      redirectUri,
      state
    );
  }
}

function requireRegisteredRedirect(
  client: AuthorizationClient,
  value: string | undefined
): string {
  if (!value || !client.redirectUris.includes(value)) {
    throw new AuthorizationProtocolError(
      "invalid_request",
      "redirect_uri is not registered for this client"
    );
  }
  return value;
}

function requiredText(value: string | undefined, field: string): string {
  const result = optionalText(value, field, 512);
  if (!result) {
    throw new AuthorizationProtocolError("invalid_request", `${field} is required`);
  }
  return result;
}

function optionalText(
  value: string | undefined,
  field: string,
  maximumLength: number
): string | null {
  if (value === undefined) return null;
  if (typeof value !== "string" || value.length > maximumLength) {
    throw new AuthError("validation_error", `${field} is invalid`, 400);
  }
  return value;
}

async function enforceProtocolRateLimit(
  ctx: AuthEngineContext,
  identifier: string | undefined,
  redirectUri: string,
  state: string | null
): Promise<void> {
  if (!identifier) return;
  try {
    await rateLimit(
      ctx,
      "authorization_server_start",
      identifier,
      authorizationServerRateLimits.start,
      authorizationServerRateLimitWindowMs
    );
  } catch (error) {
    if (error instanceof AuthError && error.code === "rate_limited") {
      throw redirectError(
        "temporarily_unavailable",
        "Too many authorization requests",
        redirectUri,
        state
      );
    }
    throw error;
  }
}

function auditAuthorizationStarted(
  ctx: AuthEngineContext,
  client: AuthorizationClient,
  userId: string | null,
  input: AuthorizationRequestInput
): Promise<void> {
  return audit(ctx, {
    eventType: "authorization_server.authorization_started",
    actorUserId: userId,
    targetUserId: userId,
    context: input.request,
    metadata: { authorizationClientId: client.id }
  });
}

function redirectError(
  code: ConstructorParameters<typeof AuthorizationProtocolError>[0],
  description: string,
  redirectUri: string,
  state: string | null
): AuthorizationProtocolError {
  return new AuthorizationProtocolError(code, description, {
    redirectUri,
    state
  });
}
