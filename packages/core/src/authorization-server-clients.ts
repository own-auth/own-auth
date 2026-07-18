import type { AuthEngineContext } from "./auth-engine-context.js";
import { audit } from "./auth-engine-helpers.js";
import { authorizationClientAuthenticationMethods } from "./authorization-server-constants.js";
import { requireDpopConfiguration } from "./authorization-server-dpop.js";
import {
  createClientId,
  createClientSecret,
  extractClientSecretPrefix,
  hashAuthorizationSecret,
  normalizeAllowedScopes,
  normalizeClientGrantTypes,
  normalizeClientRedirectUris,
  requireAuthorizationServer
} from "./authorization-server-helpers.js";
import {
  AuthorizationProtocolError,
  invalidAuthorizationClient
} from "./authorization-server-protocol-error.js";
import type {
  AuthorizationClient,
  CreatedAuthorizationClient,
  CreateAuthorizationClientInput,
  RevokeAuthorizationClientInput,
  RotateAuthorizationClientSecretInput,
  TokenEndpointAuthMethod,
  UpdateAuthorizationClientInput
} from "./authorization-server-types.js";
import { createId, safeEqual } from "./crypto.js";
import { AuthError } from "./errors.js";
import type { RequestContext } from "./types.js";

export async function createAuthorizationClient(
  ctx: AuthEngineContext,
  input: CreateAuthorizationClientInput
): Promise<CreatedAuthorizationClient> {
  const { config, storage } = requireAuthorizationServer(ctx);
  assertClientKinds(input.clientType, input.applicationType);
  const name = clientName(input.name);
  const grantTypes = normalizeClientGrantTypes(input.grantTypes);
  const redirectUris = normalizeClientRedirectUris(
    input.applicationType,
    input.redirectUris ?? [],
    grantTypes
  );
  const allowedScopes = normalizeAllowedScopes(config, input.allowedScopes);
  const tokenEndpointAuthMethod = clientAuthenticationMethod(
    input.clientType,
    input.tokenEndpointAuthMethod
  );
  const dpopBoundAccessTokens = input.dpopBoundAccessTokens ?? false;
  requireDpopConfiguration(
    ctx,
    dpopBoundAccessTokens,
    "dpopBoundAccessTokens"
  );
  const now = new Date();
  const client: AuthorizationClient = {
    id: createId("ocli"),
    clientId: createClientId(),
    name,
    clientType: input.clientType,
    applicationType: input.applicationType,
    tokenEndpointAuthMethod,
    redirectUris,
    allowedScopes,
    grantTypes,
    dpopBoundAccessTokens,
    status: "active",
    createdAt: now,
    updatedAt: now,
    revokedAt: null
  };
  const secret = input.clientType === "confidential" ? createClientSecret() : null;
  const created = await storage.createAuthorizationClient(
    client,
    secret
      ? {
          id: createId("ocsec"),
          authorizationClientId: client.id,
          prefix: secret.prefix,
          secretHash: hashAuthorizationSecret(ctx, secret.raw),
          createdAt: now,
          expiresAt: null,
          revokedAt: null
        }
      : null
  );
  await auditClientChange(
    ctx,
    "authorization_server.client_created",
    created,
    input.actorUserId,
    input.request
  );
  return { client: created, clientSecret: secret?.raw ?? null };
}

export async function listAuthorizationClients(
  ctx: AuthEngineContext
): Promise<AuthorizationClient[]> {
  return requireAuthorizationServer(ctx).storage.listAuthorizationClients();
}

export async function updateAuthorizationClient(
  ctx: AuthEngineContext,
  input: UpdateAuthorizationClientInput
): Promise<AuthorizationClient> {
  const { config, storage } = requireAuthorizationServer(ctx);
  const current = await requireManagedClient(ctx, input.clientId);
  const grantTypes = input.grantTypes === undefined
    ? current.grantTypes
    : normalizeClientGrantTypes(input.grantTypes);
  const redirectUris = normalizeClientRedirectUris(
    current.applicationType,
    input.redirectUris ?? current.redirectUris,
    grantTypes
  );
  requireDpopConfiguration(
    ctx,
    input.dpopBoundAccessTokens ?? false,
    "dpopBoundAccessTokens"
  );
  const updated = await storage.updateAuthorizationClient(current.id, {
    ...(input.name === undefined ? {} : { name: clientName(input.name) }),
    ...(input.redirectUris !== undefined || input.grantTypes !== undefined
      ? { redirectUris }
      : {}),
    ...(input.allowedScopes === undefined
      ? {}
      : { allowedScopes: normalizeAllowedScopes(config, input.allowedScopes) }),
    ...(input.grantTypes === undefined ? {} : { grantTypes }),
    ...(input.dpopBoundAccessTokens === undefined
      ? {}
      : { dpopBoundAccessTokens: input.dpopBoundAccessTokens }),
    updatedAt: new Date()
  });
  if (!updated) {
    throw new AuthError(
      "authorization_client_not_found",
      "Authorization client not found",
      404
    );
  }
  await auditClientChange(
    ctx,
    "authorization_server.client_updated",
    updated,
    input.actorUserId,
    input.request
  );
  return updated;
}

export async function rotateAuthorizationClientSecret(
  ctx: AuthEngineContext,
  input: RotateAuthorizationClientSecretInput
): Promise<string> {
  const { storage } = requireAuthorizationServer(ctx);
  const client = await requireManagedClient(ctx, input.clientId);
  if (client.clientType !== "confidential") {
    throw new AuthError(
      "validation_error",
      "Public authorization clients do not use client secrets",
      400
    );
  }
  const now = new Date();
  if (input.expiresAt && input.expiresAt.getTime() <= now.getTime()) {
    throw new AuthError("validation_error", "expiresAt must be in the future", 400);
  }
  const secret = createClientSecret();
  await storage.replaceAuthorizationClientSecret(
    client.id,
    {
      id: createId("ocsec"),
      authorizationClientId: client.id,
      prefix: secret.prefix,
      secretHash: hashAuthorizationSecret(ctx, secret.raw),
      createdAt: now,
      expiresAt: input.expiresAt ?? null,
      revokedAt: null
    },
    now
  );
  await auditClientChange(
    ctx,
    "authorization_server.client_secret_rotated",
    client,
    input.actorUserId,
    input.request
  );
  return secret.raw;
}

export async function revokeAuthorizationClient(
  ctx: AuthEngineContext,
  input: RevokeAuthorizationClientInput
): Promise<AuthorizationClient> {
  const { storage } = requireAuthorizationServer(ctx);
  const client = await requireManagedClient(ctx, input.clientId, true);
  if (client.revokedAt) return client;
  const revoked = await storage.revokeAuthorizationClient(client.id, new Date());
  if (!revoked) {
    throw new AuthError(
      "authorization_client_not_found",
      "Authorization client not found",
      404
    );
  }
  await auditClientChange(
    ctx,
    "authorization_server.client_revoked",
    revoked,
    input.actorUserId,
    input.request
  );
  return revoked;
}

export async function authenticateAuthorizationClient(
  ctx: AuthEngineContext,
  input: {
    clientId?: string;
    clientSecret?: string;
    clientAuthenticationMethod?: TokenEndpointAuthMethod;
  }
): Promise<AuthorizationClient> {
  const { storage } = requireAuthorizationServer(ctx);
  const clientId = requiredClientId(input.clientId);
  const client = await storage.getAuthorizationClientByClientId(clientId);
  if (!isActiveAuthorizationClient(client)) {
    throw invalidAuthorizationClient();
  }
  const suppliedMethod = input.clientAuthenticationMethod ?? "none";
  if (client.tokenEndpointAuthMethod !== suppliedMethod) {
    throw invalidAuthorizationClient();
  }
  if (client.tokenEndpointAuthMethod === "none") {
    if (input.clientSecret) throw invalidAuthorizationClient();
    return client;
  }
  const rawSecret = input.clientSecret ?? "";
  const prefix = extractClientSecretPrefix(rawSecret);
  if (!prefix) throw invalidAuthorizationClient();
  const secret = await storage.getAuthorizationClientSecretByPrefix(
    client.id,
    prefix
  );
  if (
    !secret ||
    !safeEqual(secret.secretHash, hashAuthorizationSecret(ctx, rawSecret))
  ) {
    throw invalidAuthorizationClient();
  }
  return client;
}

export async function requireProtocolClient(
  ctx: AuthEngineContext,
  clientId: string
): Promise<AuthorizationClient> {
  const client = await requireAuthorizationServer(ctx).storage
    .getAuthorizationClientByClientId(clientId);
  if (!client) {
    throw new AuthorizationProtocolError(
      "invalid_request",
      "The authorization client is invalid"
    );
  }
  if (!isActiveAuthorizationClient(client)) {
    throw new AuthorizationProtocolError(
      "unauthorized_client",
      "The authorization client is not active"
    );
  }
  return client;
}

async function requireManagedClient(
  ctx: AuthEngineContext,
  clientId: string,
  includeRevoked = false
): Promise<AuthorizationClient> {
  const value = requiredClientId(clientId);
  const client = await requireAuthorizationServer(ctx).storage
    .getAuthorizationClientByClientId(value);
  if (!client) {
    throw new AuthError(
      "authorization_client_not_found",
      "Authorization client not found",
      404
    );
  }
  if (!includeRevoked && !isActiveAuthorizationClient(client)) {
    throw new AuthError(
      "authorization_client_revoked",
      "Authorization client is revoked",
      409
    );
  }
  return client;
}

export function isActiveAuthorizationClient(
  client: AuthorizationClient | null | undefined
): client is AuthorizationClient {
  return Boolean(client && client.status === "active" && !client.revokedAt);
}

function clientAuthenticationMethod(
  clientType: AuthorizationClient["clientType"],
  configured: TokenEndpointAuthMethod | undefined
): TokenEndpointAuthMethod {
  const method = configured ?? (
    clientType === "public" ? "none" : "client_secret_basic"
  );
  if (!authorizationClientAuthenticationMethods.includes(method)) {
    throw new AuthError(
      "validation_error",
      "tokenEndpointAuthMethod is invalid",
      400
    );
  }
  if (
    (clientType === "public" && method !== "none") ||
    (clientType === "confidential" && method === "none")
  ) {
    throw new AuthError(
      "validation_error",
      "Public clients use no client secret; confidential clients require one",
      400
    );
  }
  return method;
}

function assertClientKinds(
  clientType: AuthorizationClient["clientType"],
  applicationType: AuthorizationClient["applicationType"]
): void {
  if (!["public", "confidential"].includes(clientType)) {
    throw new AuthError("validation_error", "clientType is invalid", 400);
  }
  if (!["web", "native"].includes(applicationType)) {
    throw new AuthError("validation_error", "applicationType is invalid", 400);
  }
}

function clientName(value: string): string {
  if (typeof value !== "string" || !value.trim() || value.trim().length > 120) {
    throw new AuthError(
      "validation_error",
      "Authorization client name must be between 1 and 120 characters",
      400
    );
  }
  return value.trim();
}

function requiredClientId(value: string | undefined): string {
  if (typeof value !== "string" || !value.trim() || value.length > 200) {
    throw invalidAuthorizationClient();
  }
  return value;
}

function auditClientChange(
  ctx: AuthEngineContext,
  eventType:
    | "authorization_server.client_created"
    | "authorization_server.client_updated"
    | "authorization_server.client_secret_rotated"
    | "authorization_server.client_revoked",
  client: AuthorizationClient,
  actorUserId: string | undefined,
  request: RequestContext | undefined
): Promise<void> {
  return audit(ctx, {
    eventType,
    actorUserId: actorUserId ?? null,
    context: request,
    metadata: {
      authorizationClientId: client.id,
      clientId: client.clientId
    }
  });
}
