import { createId, randomBase64Url, safeEqual } from "./crypto.js";
import { AuthError } from "./errors.js";
import type { AuthEngineContext } from "./auth-engine-context.js";
import { completeFirstFactor } from "./auth-engine-mfa.js";
import {
  assertRedirectAllowed,
  audit,
  createAuditEvent,
  rateLimit,
  requireActiveUser
} from "./auth-engine-internals.js";
import { resolveSamlIdentity } from "./saml-identity.js";
import { SamlCallbackError } from "./saml-callback-error.js";
import { SamlProtocolError } from "./saml-protocol-error.js";
import type {
  CreateSamlLinkUrlInput,
  CreateSamlSignInUrlInput,
  SamlAuthorizationUrl,
  SamlCompletionInput,
  SamlCompletionResult,
  SamlIntent,
  SamlTransaction,
  UnlinkSamlIdentityInput
} from "./saml-types.js";
import {
  hashSamlAssertion,
  hashSamlRelayState,
  hashSamlRequest,
  protocolConnection,
  requireSaml,
  requireSamlConnection
} from "./saml-helpers.js";
import { prepareAuthEventWrite } from "./webhook-outbox.js";

const tenMinutes = 10 * 60 * 1_000;

export function createSignInUrl(
  ctx: AuthEngineContext,
  input: CreateSamlSignInUrlInput
): Promise<SamlAuthorizationUrl> {
  return createAuthorizationUrl(ctx, input, "sign_in", null);
}

export async function createLinkUrl(
  ctx: AuthEngineContext,
  input: CreateSamlLinkUrlInput
): Promise<SamlAuthorizationUrl> {
  const actor = await requireActiveUser(ctx, input.actorUserId);
  return createAuthorizationUrl(ctx, input, "link", actor.id);
}

export async function completeResponse(
  ctx: AuthEngineContext,
  input: SamlCompletionInput
): Promise<SamlCompletionResult> {
  const { provider, storage } = requireSaml(ctx);
  const relayState = requiredCredential(input.relayState);
  const relayStateHash = hashSamlRelayState(ctx, relayState);
  const transaction = await storage.getTransactionByRelayStateHash(relayStateHash);
  const now = new Date();
  if (!transaction || transaction.consumedAt || transaction.expiresAt <= now) {
    throw transactionInvalid();
  }

  const connection = await requireSamlConnection(ctx, transaction.connectionId);
  await rateLimitByIp(
    ctx,
    "saml-acs",
    connection.id,
    input.request?.ipAddress,
    30,
    tenMinutes
  );

  try {
    const assertion = await provider.verifyResponse({
      connection: await protocolConnection(ctx, connection),
      samlResponse: requiredCredential(input.samlResponse),
      requestCreatedAt: transaction.createdAt,
      acceptsRequestId: (requestId) => safeEqual(
        hashSamlRequest(ctx, requestId),
        transaction.requestIdHash
      )
    });
    const requestIdHash = hashSamlRequest(ctx, assertion.inResponseTo);
    const replayExpiresAt = new Date(Math.max(
      assertion.expiresAt.getTime(),
      now.getTime() + provider.responseTtlMs + provider.clockSkewMs
    ));
    const consumed = await storage.consumeResponse({
      relayStateHash,
      requestIdHash,
      assertion: {
        assertionHash: hashSamlAssertion(ctx, connection.id, assertion.assertionId),
        connectionId: connection.id,
        consumedAt: now,
        expiresAt: replayExpiresAt
      },
      consumedAt: now
    });
    if (!consumed) throw transactionInvalid();

    const resolved = await resolveSamlIdentity(
      ctx,
      connection,
      assertion,
      consumed,
      input.request
    );
    if (consumed.intent === "link") {
      return { status: "linked", destination: consumed.destination };
    }

    const result = await completeFirstFactor(ctx, resolved.user, "saml", input.request);
    await audit(ctx, {
      eventType: "saml.signed_in",
      actorUserId: resolved.user.id,
      targetUserId: resolved.user.id,
      organisationId: connection.organisationId,
      context: input.request,
      metadata: { connectionId: connection.id }
    });
    return { ...result, destination: consumed.destination };
  } catch (error) {
    const failure = mapProtocolError(error);
    await audit(ctx, {
      eventType: "saml.failed",
      actorUserId: transaction.userId,
      targetUserId: transaction.userId,
      organisationId: connection.organisationId,
      context: input.request,
      metadata: { connectionId: connection.id, error: failure.code }
    });
    if (failure.error instanceof AuthError) {
      throw new SamlCallbackError(failure.error, transaction.destination, error);
    }
    throw error;
  }
}

export async function unlinkIdentity(
  ctx: AuthEngineContext,
  input: UnlinkSamlIdentityInput
): Promise<void> {
  const connection = await requireSamlConnection(ctx, input.connectionId, true);
  const user = await requireActiveUser(ctx, input.actorUserId);
  const provider = `saml.${connection.key}` as const;
  const account = (await ctx.storage.listAccountsByUserId(user.id))
    .find((candidate) => candidate.provider === provider);
  if (!account) {
    throw new AuthError("invalid_credentials", "SAML identity not found", 404);
  }
  const removed = await ctx.storage.removeAuthenticationMethodAtomically({
    operationId: createId("op"),
    userId: user.id,
    method: { kind: "account", id: account.id },
    event: prepareAuthEventWrite(ctx, createAuditEvent({
      eventType: "saml.identity_unlinked",
      actorUserId: user.id,
      targetUserId: user.id,
      organisationId: connection.organisationId,
      request: input.request,
      metadata: { connectionId: connection.id }
    }))
  });
  if (removed === "last_method") {
    throw new AuthError(
      "authentication_method_required",
      "Add another sign-in method before unlinking this SAML identity",
      409
    );
  }
  if (removed === "not_found") {
    throw new AuthError("invalid_credentials", "SAML identity not found", 404);
  }
}

async function createAuthorizationUrl(
  ctx: AuthEngineContext,
  input: CreateSamlSignInUrlInput,
  intent: SamlIntent,
  userId: string | null
): Promise<SamlAuthorizationUrl> {
  const { provider, storage } = requireSaml(ctx);
  const connection = await requireSamlConnection(ctx, input.connectionId);
  assertRedirectAllowed(ctx, input.destination);
  await rateLimitByIp(
    ctx,
    "saml-start",
    connection.id,
    input.request?.ipAddress,
    20,
    tenMinutes
  );

  const requestId = `_${randomBase64Url(24)}`;
  const relayState = randomBase64Url(32);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + provider.responseTtlMs);
  const transaction: SamlTransaction = {
    id: createId("samt"),
    connectionId: connection.id,
    requestIdHash: hashSamlRequest(ctx, requestId),
    relayStateHash: hashSamlRelayState(ctx, relayState),
    intent,
    userId,
    destination: input.destination ?? null,
    expiresAt,
    consumedAt: null,
    createdAt: now
  };
  const url = await provider.createAuthorizeUrl({
    connection: await protocolConnection(ctx, connection),
    requestId,
    relayState
  });
  await storage.createTransaction(transaction);
  await audit(ctx, {
    eventType: "saml.started",
    actorUserId: userId,
    targetUserId: userId,
    organisationId: connection.organisationId,
    context: input.request,
    metadata: { connectionId: connection.id, intent }
  });
  return { url, expiresAt };
}

async function rateLimitByIp(
  ctx: AuthEngineContext,
  action: "saml-acs" | "saml-start",
  connectionId: string,
  ipAddress: string | undefined,
  limit: number,
  windowMs: number
): Promise<void> {
  if (ipAddress) {
    await rateLimit(ctx, action, `${connectionId}:${ipAddress}`, limit, windowMs);
  }
}

function mapProtocolError(error: unknown): { code: string; error: unknown } {
  if (error instanceof AuthError) return { code: error.code, error };
  if (error instanceof SamlProtocolError) {
    return {
      code: error.code,
      error: new AuthError(error.code, error.message, 401)
    };
  }
  return { code: "internal_error", error };
}

function requiredCredential(value: string): string {
  if (!value || !value.trim()) throw transactionInvalid();
  return value.trim();
}

function transactionInvalid(): AuthError {
  return new AuthError(
    "saml_transaction_invalid",
    "SAML transaction is invalid or expired",
    401
  );
}
