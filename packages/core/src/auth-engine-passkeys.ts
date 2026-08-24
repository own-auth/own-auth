import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse
} from "@simplewebauthn/server";
import { createId } from "./crypto.js";
import { decodeBase64Url } from "./encoding.js";
import { AuthError } from "./errors.js";
import type { PasskeyCredential } from "./identity-types.js";
import type {
  BeginPasskeyAuthenticationInput,
  BeginPasskeyAuthenticationResult,
  BeginPasskeyRegistrationInput,
  BeginPasskeyRegistrationResult,
  CompletePasskeyAuthenticationInput,
  CompletePasskeyRegistrationInput,
  ListPasskeysInput,
  RenamePasskeyInput,
  RevokePasskeyInput,
  SessionResult
} from "./auth-engine-types.js";
import {
  audit,
  auditSignedIn,
  createAuditEvent,
  createSession,
  hash,
  markUserLoggedIn,
  type AuthEngineContext
} from "./auth-engine-internals.js";
import { finishVerifiedMfa, requireMfaChallenge } from "./auth-engine-mfa.js";
import { requireCurrentSession } from "./auth-engine-sessions.js";
import { prepareAuthEventWrite, recordCommittedAuthEvent } from "./webhook-outbox.js";

export async function beginPasskeyRegistration(
  ctx: AuthEngineContext,
  input: BeginPasskeyRegistrationInput
): Promise<BeginPasskeyRegistrationResult> {
  const config = requirePasskeyConfig(ctx);
  const { user } = await requireCurrentSession(ctx, input.sessionToken);
  const credentials = await ctx.storage.listPasskeyCredentialsByUserId(user.id);
  const options = await generateRegistrationOptions({
    rpID: config.rpId,
    rpName: config.rpName,
    userID: new TextEncoder().encode(user.id),
    userName: user.email ?? user.phone ?? user.id,
    userDisplayName: user.name ?? "",
    timeout: config.timeoutMs,
    attestationType: "none",
    excludeCredentials: credentials.map((credential) => ({
      id: credential.credentialId,
      transports: credential.transports as never[]
    })),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "required"
    },
    extensions: { credProps: true }
  });
  await storeChallenge(ctx, {
    rawChallenge: options.challenge,
    userId: user.id,
    mfaChallengeId: null,
    purpose: "registration",
    ttlMs: config.timeoutMs
  });
  return { options };
}

export async function completePasskeyRegistration(
  ctx: AuthEngineContext,
  input: CompletePasskeyRegistrationInput
): Promise<PasskeyCredential> {
  const config = requirePasskeyConfig(ctx);
  const { user } = await requireCurrentSession(ctx, input.sessionToken);
  const rawChallenge = challengeFromClientData(input.response.response.clientDataJSON);
  const challenge = await ctx.storage.consumeWebAuthnChallenge(
    hash(ctx, rawChallenge),
    "registration",
    new Date()
  );
  if (!challenge || challenge.userId !== user.id) {
    throw invalidPasskey();
  }
  const verification = await verifyRegistrationResponse({
    response: input.response,
    expectedChallenge: rawChallenge,
    expectedOrigin: config.origins,
    expectedRPID: config.rpId,
    requireUserVerification: true
  });
  if (!verification.verified || !verification.registrationInfo?.userVerified) {
    throw invalidPasskey();
  }
  const info = verification.registrationInfo;
  const now = new Date();
  const discoverable = Boolean(
    (input.response.clientExtensionResults as { credProps?: { rk?: boolean } }).credProps?.rk
  );
  if (await ctx.storage.getPasskeyCredentialByCredentialId(info.credential.id)) {
    throw invalidPasskey();
  }
  const candidate = {
    id: createId("psk"),
    userId: user.id,
    credentialId: info.credential.id,
    publicKey: new Uint8Array(info.credential.publicKey),
    counter: info.credential.counter,
    transports: [...(info.credential.transports ?? [])],
    deviceType: info.credentialDeviceType,
    backedUp: info.credentialBackedUp,
    discoverable,
    name: normalizePasskeyName(input.name),
    metadata: { aaguid: info.aaguid },
    createdAt: now,
    updatedAt: now,
    lastUsedAt: null
  };
  let credential: PasskeyCredential;
  try {
    credential = await ctx.storage.createPasskeyCredential(candidate);
  } catch (error) {
    if (await ctx.storage.getPasskeyCredentialByCredentialId(info.credential.id)) {
      throw invalidPasskey();
    }
    throw error;
  }
  await audit(ctx, {
    eventType: "passkey.registered",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request,
    metadata: { passkeyId: credential.id, discoverable }
  });
  return credential;
}

export async function beginPasskeyAuthentication(
  ctx: AuthEngineContext,
  input: BeginPasskeyAuthenticationInput = {}
): Promise<BeginPasskeyAuthenticationResult> {
  const config = requirePasskeyConfig(ctx);
  const mfaChallenge = input.mfaChallengeToken
    ? await requireMfaChallenge(ctx, input.mfaChallengeToken, "passkey")
    : null;
  const userId = mfaChallenge?.userId ?? input.userId ?? null;
  const credentials = userId
    ? await ctx.storage.listPasskeyCredentialsByUserId(userId)
    : [];
  if (mfaChallenge && credentials.length === 0) {
    throw new AuthError("passkey_not_found", "No passkey is available for this challenge", 404);
  }
  const options = await generateAuthenticationOptions({
    rpID: config.rpId,
    timeout: config.timeoutMs,
    userVerification: "required",
    allowCredentials: userId
      ? credentials.map((credential) => ({
          id: credential.credentialId,
          transports: credential.transports as never[]
        }))
      : undefined
  });
  await storeChallenge(ctx, {
    rawChallenge: options.challenge,
    userId,
    mfaChallengeId: mfaChallenge?.id ?? null,
    purpose: mfaChallenge ? "mfa" : "authentication",
    ttlMs: config.timeoutMs
  });
  return { options };
}

export async function completePasskeyAuthentication(
  ctx: AuthEngineContext,
  input: CompletePasskeyAuthenticationInput
): Promise<SessionResult> {
  const config = requirePasskeyConfig(ctx);
  const rawChallenge = challengeFromClientData(input.response.response.clientDataJSON);
  const challenge = await consumeAuthenticationChallenge(ctx, rawChallenge);
  const credential = await ctx.storage.getPasskeyCredentialByCredentialId(input.response.id);
  if (
    !credential ||
    (challenge.userId && challenge.userId !== credential.userId) ||
    (!challenge.userId && !credential.discoverable)
  ) {
    throw invalidPasskey();
  }
  const verification = await verifyAuthenticationResponse({
    response: input.response,
    expectedChallenge: rawChallenge,
    expectedOrigin: config.origins,
    expectedRPID: config.rpId,
    credential: {
      id: credential.credentialId,
      publicKey: Uint8Array.from(credential.publicKey),
      counter: credential.counter,
      transports: credential.transports as never[]
    },
    requireUserVerification: true
  });
  if (!verification.verified || !verification.authenticationInfo.userVerified) {
    throw invalidPasskey();
  }
  await updateCounter(ctx, credential, verification.authenticationInfo.newCounter);
  const user = await ctx.storage.getUserById(credential.userId);
  if (!user || user.disabledAt) {
    throw invalidPasskey();
  }
  await audit(ctx, {
    eventType: "passkey.authenticated",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request,
    metadata: { passkeyId: credential.id, purpose: challenge.purpose }
  });

  if (challenge.purpose === "mfa") {
    const mfaChallenge = challenge.mfaChallengeId
      ? await ctx.storage.getMfaChallengeById(challenge.mfaChallengeId)
      : null;
    if (!mfaChallenge || mfaChallenge.userId !== user.id) {
      throw new AuthError("mfa_challenge_invalid", "MFA challenge is invalid or expired", 401);
    }
    return finishVerifiedMfa(ctx, mfaChallenge, "passkey", input.request);
  }

  const activeUser = await markUserLoggedIn(ctx, user);
  const result = await createSession(ctx, activeUser, input.request, ["passkey"], "aal2");
  await auditSignedIn(ctx, user.id, "passkey", input.request, "aal2");
  return result;
}

export async function listPasskeys(
  ctx: AuthEngineContext,
  input: ListPasskeysInput
): Promise<PasskeyCredential[]> {
  const { user } = await requireCurrentSession(ctx, input.sessionToken);
  return ctx.storage.listPasskeyCredentialsByUserId(user.id);
}

export async function renamePasskey(
  ctx: AuthEngineContext,
  input: RenamePasskeyInput
): Promise<PasskeyCredential> {
  const { user } = await requireCurrentSession(ctx, input.sessionToken);
  const credential = await requireOwnedPasskey(ctx, input.passkeyId, user.id);
  const updated = await ctx.storage.updatePasskeyCredential(credential.id, {
    name: normalizePasskeyName(input.name),
    updatedAt: new Date()
  });
  if (!updated) {
    throw notFound();
  }
  await audit(ctx, {
    eventType: "passkey.renamed",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request,
    metadata: { passkeyId: credential.id }
  });
  return updated;
}

export async function revokePasskey(
  ctx: AuthEngineContext,
  input: RevokePasskeyInput
): Promise<void> {
  const { user } = await requireCurrentSession(ctx, input.sessionToken);
  const credential = await requireOwnedPasskey(ctx, input.passkeyId, user.id);
  const auditEvent = createAuditEvent({
    eventType: "passkey.revoked",
    actorUserId: user.id,
    targetUserId: user.id,
    request: input.request,
    metadata: { passkeyId: credential.id }
  });
  const removed = await ctx.storage.removeAuthenticationMethodAtomically({
    operationId: createId("op"),
    userId: user.id,
    method: { kind: "passkey", id: credential.id },
    event: prepareAuthEventWrite(ctx, auditEvent)
  });
  if (removed === "last_method") {
    throw new AuthError(
      "authentication_method_required",
      "Add another sign-in method before revoking this passkey",
      409
    );
  }
  if (removed === "not_found") {
    throw notFound();
  }
  await recordCommittedAuthEvent(ctx, auditEvent);
}

async function storeChallenge(
  ctx: AuthEngineContext,
  input: {
    rawChallenge: string;
    userId: string | null;
    mfaChallengeId: string | null;
    purpose: "registration" | "authentication" | "mfa";
    ttlMs: number;
  }
): Promise<void> {
  const now = new Date();
  await ctx.storage.createWebAuthnChallenge({
    id: createId("wac"),
    challengeHash: hash(ctx, input.rawChallenge),
    userId: input.userId,
    mfaChallengeId: input.mfaChallengeId,
    purpose: input.purpose,
    expiresAt: new Date(now.getTime() + input.ttlMs),
    consumedAt: null,
    createdAt: now
  });
}

async function consumeAuthenticationChallenge(ctx: AuthEngineContext, rawChallenge: string) {
  const challengeHash = hash(ctx, rawChallenge);
  const now = new Date();
  const authentication = await ctx.storage.consumeWebAuthnChallenge(
    challengeHash,
    "authentication",
    now
  );
  if (authentication) return authentication;

  const mfa = await ctx.storage.consumeWebAuthnChallenge(challengeHash, "mfa", now);
  if (!mfa) throw invalidPasskey();
  return mfa;
}

async function updateCounter(
  ctx: AuthEngineContext,
  credential: PasskeyCredential,
  nextCounter: number
): Promise<void> {
  const now = new Date();
  if (credential.counter === 0 && nextCounter === 0 && credential.deviceType === "multiDevice") {
    const updated = await ctx.storage.updatePasskeyCredential(credential.id, {
      lastUsedAt: now,
      updatedAt: now
    });
    if (!updated) {
      throw invalidPasskey();
    }
    return;
  }
  if (credential.counter === 0 && nextCounter === 0) {
    throw invalidPasskey();
  }
  const updated = await ctx.storage.updatePasskeyCounter(
    credential.id,
    credential.counter,
    nextCounter,
    now
  );
  if (!updated) {
    throw invalidPasskey();
  }
}

async function requireOwnedPasskey(
  ctx: AuthEngineContext,
  id: string,
  userId: string
): Promise<PasskeyCredential> {
  const credential = await ctx.storage.getPasskeyCredentialById(id);
  if (!credential || credential.userId !== userId) {
    throw notFound();
  }
  return credential;
}

function challengeFromClientData(value: string): string {
  try {
    const parsed = JSON.parse(new TextDecoder().decode(decodeBase64Url(value))) as {
      challenge?: unknown;
    };
    if (typeof parsed.challenge === "string") {
      return parsed.challenge;
    }
  } catch {
    // The public error stays generic because client data is attacker-controlled.
  }
  throw invalidPasskey();
}

function normalizePasskeyName(value?: string): string {
  const name = value?.trim() || "Passkey";
  if (name.length > 100) {
    throw new AuthError("validation_error", "Passkey name must be at most 100 characters", 400);
  }
  return name;
}

function requirePasskeyConfig(ctx: AuthEngineContext): NonNullable<AuthEngineContext["passkeys"]> {
  if (!ctx.passkeys) {
    throw new AuthError("validation_error", "Passkeys are not configured", 400);
  }
  return ctx.passkeys;
}

function invalidPasskey(): AuthError {
  return new AuthError("passkey_invalid", "Passkey verification failed", 401);
}

function notFound(): AuthError {
  return new AuthError("passkey_not_found", "Passkey not found", 404);
}
