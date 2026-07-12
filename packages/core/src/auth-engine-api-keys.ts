import { AuthError } from "./errors.js";
import { createId, randomBase64Url, safeEqual } from "./crypto.js";
import { isExpired } from "./normalise.js";
import type {
  ApiKey,
  ApiKeyDetails,
  Organisation,
  VerifiedApiKey
} from "./types.js";
import {
  hour,
  type CreatedApiKey,
  type CreateApiKeyInput,
  type ListApiKeysInput,
  type RevokeApiKeyInput
} from "./auth-engine-types.js";
import {
  audit,
  cloneMetadata,
  extractApiKeyPrefix,
  hash,
  rateLimit,
  requireActiveUser,
  type AuthEngineContext
} from "./auth-engine-internals.js";
import { requirePermission } from "./auth-engine-organisation-access.js";

export async function createApiKey(
  ctx: AuthEngineContext,
  input: CreateApiKeyInput
): Promise<CreatedApiKey> {
  if (!input.actorUserId) {
    throw new AuthError("permission_denied", "An acting user is required", 403);
  }

  if (input.organisationId) {
    await requirePermission(ctx, input.organisationId, input.actorUserId, "manage_api_keys");
  } else {
    await requireActiveUser(ctx, input.actorUserId);
  }

  await rateLimit(
    ctx,
    "api-key-create",
    input.organisationId ?? input.actorUserId,
    20,
    hour
  );

  const prefix = randomBase64Url(6).replace(/[-_]/g, "").slice(0, 8);
  const rawKey = `oa_${prefix}_${randomBase64Url(32)}`;
  const now = new Date();
  const apiKey = await ctx.storage.createApiKey({
    id: createId("key"),
    keyPrefix: prefix,
    keyHash: hash(ctx, rawKey),
    name: input.name,
    userId: input.organisationId ? null : input.actorUserId,
    organisationId: input.organisationId ?? null,
    scopes: input.scopes ?? [],
    status: "active",
    expiresAt: input.expiresAt ?? null,
    lastUsedAt: null,
    createdAt: now,
    revokedAt: null,
    revokedBy: null,
    metadata: cloneMetadata(input.metadata)
  });

  await audit(ctx, {
    eventType: "api_key.created",
    actorUserId: input.actorUserId,
    targetUserId: input.organisationId ? null : input.actorUserId,
    organisationId: input.organisationId ?? null,
    apiKeyId: apiKey.id,
    context: input.request,
    metadata: { name: input.name, scopes: apiKey.scopes }
  });

  return { apiKey: apiKeyDetails(apiKey), rawKey };
}

export async function verifyApiKey(
  ctx: AuthEngineContext,
  rawKey: string,
  requiredScopes: string[] = []
): Promise<VerifiedApiKey> {
  const prefix = extractApiKeyPrefix(rawKey);
  if (!prefix) {
    throw new AuthError("api_key_invalid", "Invalid API key", 401);
  }

  const apiKey = await ctx.storage.getApiKeyByPrefix(prefix);
  if (!apiKey || !safeEqual(hash(ctx, rawKey), apiKey.keyHash)) {
    throw new AuthError("api_key_invalid", "Invalid API key", 401);
  }

  if (apiKey.status === "revoked" || apiKey.revokedAt) {
    throw new AuthError("api_key_revoked", "API key has been revoked", 401);
  }

  if (apiKey.expiresAt && isExpired(apiKey.expiresAt)) {
    throw new AuthError("api_key_expired", "API key has expired", 401);
  }

  let organisation: Organisation | null = null;
  if (apiKey.organisationId) {
    organisation = await ctx.storage.getOrganisationById(apiKey.organisationId);
    if (!organisation || organisation.disabledAt) {
      throw new AuthError("api_key_revoked", "API key has been revoked", 401);
    }
  }

  const hasAllScopes = requiredScopes.every(
    (scope) => apiKey.scopes.includes("*") || apiKey.scopes.includes(scope)
  );

  if (!hasAllScopes) {
    throw new AuthError("insufficient_scope", "API key does not have the required scope", 403);
  }

  const updatedApiKey = await ctx.storage.updateApiKey(apiKey.id, {
    lastUsedAt: new Date()
  });
  const activeApiKey = updatedApiKey ?? apiKey;

  await audit(ctx, {
    eventType: "api_key.used",
    actorUserId: activeApiKey.userId,
    targetUserId: activeApiKey.userId,
    organisationId: activeApiKey.organisationId,
    apiKeyId: activeApiKey.id,
    metadata: { requiredScopes }
  });

  const user = activeApiKey.userId ? await ctx.storage.getUserById(activeApiKey.userId) : null;
  return {
    apiKey: apiKeyDetails(activeApiKey),
    user,
    organisation
  };
}

export async function revokeApiKey(
  ctx: AuthEngineContext,
  input: RevokeApiKeyInput
): Promise<ApiKeyDetails> {
  let apiKey = await ctx.storage.getApiKeyByPrefix(input.keyPrefix);

  if (!apiKey) {
    throw new AuthError("api_key_invalid", "Invalid API key", 404);
  }

  if (apiKey.organisationId) {
    await requirePermission(
      ctx,
      apiKey.organisationId,
      input.actorUserId,
      "manage_api_keys"
    );
  } else if (apiKey.userId !== input.actorUserId) {
    throw new AuthError("permission_denied", "API key does not belong to this user", 403);
  } else {
    await requireActiveUser(ctx, input.actorUserId);
  }

  const updatedApiKey = await ctx.storage.updateApiKey(apiKey.id, {
    status: "revoked",
    revokedAt: new Date(),
    revokedBy: input.actorUserId
  });
  apiKey = updatedApiKey ?? apiKey;

  await audit(ctx, {
    eventType: "api_key.revoked",
    actorUserId: input.actorUserId,
    targetUserId: apiKey.userId,
    organisationId: apiKey.organisationId,
    apiKeyId: apiKey.id,
    context: input.request
  });

  return apiKeyDetails(apiKey);
}

export async function listApiKeys(
  ctx: AuthEngineContext,
  input: ListApiKeysInput
): Promise<ApiKeyDetails[]> {
  if (input.organisationId) {
    await requirePermission(
      ctx,
      input.organisationId,
      input.actorUserId,
      "manage_api_keys"
    );
    const apiKeys = await ctx.storage.listApiKeysByOrganisationId(input.organisationId);
    return apiKeys.map(apiKeyDetails);
  }

  await requireActiveUser(ctx, input.actorUserId);
  const apiKeys = await ctx.storage.listApiKeysByUserId(input.actorUserId);
  return apiKeys.map(apiKeyDetails);
}

function apiKeyDetails(apiKey: ApiKey): ApiKeyDetails {
  return {
    id: apiKey.id,
    keyPrefix: apiKey.keyPrefix,
    name: apiKey.name,
    userId: apiKey.userId,
    organisationId: apiKey.organisationId,
    scopes: [...apiKey.scopes],
    status: apiKey.status,
    expiresAt: apiKey.expiresAt,
    lastUsedAt: apiKey.lastUsedAt,
    createdAt: apiKey.createdAt,
    revokedAt: apiKey.revokedAt,
    revokedBy: apiKey.revokedBy,
    metadata: { ...apiKey.metadata }
  };
}
