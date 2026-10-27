import { Secret, TOTP } from "otpauth";
import { createId, randomBase64Url } from "./crypto.js";
import { requireEncryptionKeyRing } from "./encryption.js";
import { AuthError } from "./errors.js";
import type { MfaChallenge, MfaMethod, TotpFactor } from "./identity-types.js";
import type { RequestContext, User } from "./types.js";
import type {
  BeginTotpEnrollmentInput,
  BeginTotpEnrollmentResult,
  CompleteMfaInput,
  ConfirmTotpEnrollmentInput,
  ConfirmTotpEnrollmentResult,
  DisableTotpInput,
  RegenerateRecoveryCodesInput,
  SessionResult,
  SignInResult
} from "./auth-engine-types.js";
import {
  audit,
  auditSignedIn,
  createSession,
  hash,
  markUserLoggedIn,
  rateLimit,
  requireActiveUser,
  type AuthEngineContext
} from "./auth-engine-internals.js";
import { requireCurrentSession } from "./auth-engine-sessions.js";
import { assertIdentityAuthority } from "./identity-authority.js";

const totpPeriodSeconds = 30;
const totpDigits = 6;
const totpWindow = 1;
const recoveryCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export async function getMfaMethods(ctx: AuthEngineContext, userId: string): Promise<MfaMethod[]> {
  const [totp, passkeys] = await Promise.all([
    ctx.storage.getActiveTotpFactorByUserId(userId),
    ctx.storage.listPasskeyCredentialsByUserId(userId)
  ]);
  const methods: MfaMethod[] = [];
  if (totp) methods.push("totp", "recovery_code");
  if (passkeys.length) methods.push("passkey");
  return methods;
}

export async function completeFirstFactor(
  ctx: AuthEngineContext,
  user: User,
  method: string,
  request?: RequestContext,
  authorityExpiresAt?: Date
): Promise<SignInResult> {
  const activeUser = await requireActiveUser(ctx, user.id);
  const methods = await getMfaMethods(ctx, activeUser.id);
  assertIdentityAuthority(authorityExpiresAt);
  if (methods.length === 0) {
    const authenticatedUser = await markUserLoggedIn(ctx, activeUser);
    const result = await createSession(ctx, authenticatedUser, request, [method], "aal1", authorityExpiresAt);
    await auditSignedIn(ctx, authenticatedUser.id, method, request, "aal1");
    return result;
  }

  const challengeToken = randomBase64Url(32);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ctx.mfaChallengeTtlMs);
  await ctx.storage.createMfaChallenge({
    id: createId("mfc"),
    userId: activeUser.id,
    tokenHash: hash(ctx, challengeToken),
    primaryMethod: method,
    methods,
    attempts: 0,
    maxAttempts: ctx.mfaMaxAttempts,
    expiresAt,
    consumedAt: null,
    createdAt: now
  }, authorityExpiresAt);
  return { status: "mfa_required", challengeToken, methods, expiresAt };
}

export async function beginTotpEnrollment(
  ctx: AuthEngineContext,
  input: BeginTotpEnrollmentInput
): Promise<BeginTotpEnrollmentResult> {
  const { user } = await requireCurrentSession(ctx, input.sessionToken);
  if (await ctx.storage.getActiveTotpFactorByUserId(user.id)) {
    throw new AuthError("validation_error", "TOTP is already enabled", 409);
  }
  const encryption = requireEncryptionKeyRing(ctx.encryption, "MFA");
  const factorId = createId("mfa");
  const secret = new Secret({ size: 20 });
  const encrypted = await encryption.encrypt(secret.base32, "totp", {
    factorId,
    userId: user.id
  });
  const now = new Date();
  await ctx.storage.createTotpFactor({
    id: factorId,
    userId: user.id,
    status: "pending",
    ciphertext: encrypted.ciphertext,
    nonce: encrypted.nonce,
    encryptionKeyId: encrypted.encryptionKeyId,
    lastUsedTimestep: null,
    createdAt: now,
    updatedAt: now,
    disabledAt: null
  });
  const totp = totpFor(secret.base32, ctx.mfaIssuer, user.email ?? user.id);
  await audit(ctx, {
    eventType: "mfa.totp_enrollment_started",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request
  });
  return { factorId, secret: secret.base32, uri: totp.toString() };
}

export async function confirmTotpEnrollment(
  ctx: AuthEngineContext,
  input: ConfirmTotpEnrollmentInput
): Promise<ConfirmTotpEnrollmentResult> {
  const { user } = await requireCurrentSession(ctx, input.sessionToken);
  const factor = await ctx.storage.getTotpFactorById(input.factorId);
  if (!factor || factor.userId !== user.id || factor.status !== "pending") {
    throw new AuthError("mfa_code_invalid", "TOTP enrollment is invalid", 400);
  }
  const timestep = await verifyTotpCode(ctx, factor, input.code);
  const activated = await ctx.storage.activateTotpFactor(factor.id, timestep, new Date());
  if (!activated) {
    throw new AuthError("mfa_code_invalid", "TOTP enrollment is no longer pending", 409);
  }
  const recoveryCodes = await replaceRecoveryCodes(ctx, user.id);
  await audit(ctx, {
    eventType: "mfa.totp_enabled",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request
  });
  return { recoveryCodes };
}

export async function disableTotp(
  ctx: AuthEngineContext,
  input: DisableTotpInput
): Promise<void> {
  const { user } = await requireCurrentSession(ctx, input.sessionToken);
  const factor = await requireActiveTotp(ctx, user.id);
  await verifyAndConsumeTotp(ctx, factor, input.code);
  await ctx.storage.replaceRecoveryCodes(user.id, []);
  const disabled = await ctx.storage.updateTotpFactor(factor.id, {
    status: "disabled",
    disabledAt: new Date(),
    updatedAt: new Date()
  });
  if (!disabled) {
    throw new AuthError("mfa_code_invalid", "TOTP is no longer active", 409);
  }
  await audit(ctx, {
    eventType: "mfa.totp_disabled",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request
  });
}

export async function completeMfaWithTotp(
  ctx: AuthEngineContext,
  input: CompleteMfaInput
): Promise<SessionResult> {
  const challenge = await requireMfaChallenge(ctx, input.challengeToken, "totp");
  const factor = await requireActiveTotp(ctx, challenge.userId);
  try {
    await verifyAndConsumeTotp(ctx, factor, input.code);
  } catch (error) {
    await recordFailedChallenge(ctx, challenge, input.request);
    throw error;
  }
  return finishVerifiedMfa(ctx, challenge, "totp", input.request);
}

export async function completeMfaWithRecoveryCode(
  ctx: AuthEngineContext,
  input: CompleteMfaInput
): Promise<SessionResult> {
  const challenge = await requireMfaChallenge(ctx, input.challengeToken, "recovery_code");
  const consumed = await ctx.storage.consumeRecoveryCode(
    challenge.userId,
    hash(ctx, normalizeRecoveryCode(input.code)),
    new Date()
  );
  if (!consumed) {
    await recordFailedChallenge(ctx, challenge, input.request);
    throw new AuthError("mfa_code_invalid", "Invalid recovery code", 401);
  }
  await audit(ctx, {
    eventType: "mfa.recovery_code_used",
    actorUserId: challenge.userId,
    targetUserId: challenge.userId,
    context: input.request,
    metadata: { method: "recovery_code" }
  });
  return finishVerifiedMfa(ctx, challenge, "recovery_code", input.request);
}

export async function regenerateRecoveryCodes(
  ctx: AuthEngineContext,
  input: RegenerateRecoveryCodesInput
): Promise<string[]> {
  const { user } = await requireCurrentSession(ctx, input.sessionToken);
  const factor = await requireActiveTotp(ctx, user.id);
  await verifyAndConsumeTotp(ctx, factor, input.code);
  const codes = await replaceRecoveryCodes(ctx, user.id);
  await audit(ctx, {
    eventType: "mfa.recovery_codes_regenerated",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request
  });
  return codes;
}

export async function finishVerifiedMfa(
  ctx: AuthEngineContext,
  challenge: MfaChallenge,
  method: MfaMethod,
  request?: RequestContext
): Promise<SessionResult> {
  const consumed = await ctx.storage.consumeMfaChallenge(challenge.id, new Date());
  if (!consumed) {
    throw new AuthError("mfa_challenge_invalid", "MFA challenge is invalid or expired", 401);
  }
  const user = await ctx.storage.getUserById(challenge.userId);
  if (!user || user.disabledAt) {
    throw new AuthError("invalid_credentials", "Authentication failed", 401);
  }
  const activeUser = await markUserLoggedIn(ctx, user);
  const result = await createSession(
    ctx,
    activeUser,
    request,
    [challenge.primaryMethod, method],
    "aal2"
  );
  await audit(ctx, {
    eventType: "mfa.challenge_succeeded",
    actorUserId: user.id,
    targetUserId: user.id,
    context: request,
    metadata: { method }
  });
  await audit(ctx, {
    eventType: "session.elevated",
    actorUserId: user.id,
    targetUserId: user.id,
    context: request,
    metadata: { assuranceLevel: "aal2", method }
  });
  await auditSignedIn(ctx, user.id, challenge.primaryMethod, request, "aal2");
  return result;
}

export async function requireMfaChallenge(
  ctx: AuthEngineContext,
  rawToken: string,
  method: MfaMethod
): Promise<MfaChallenge> {
  const challenge = await ctx.storage.getMfaChallengeByTokenHash(hash(ctx, rawToken));
  if (
    !challenge ||
    challenge.consumedAt ||
    challenge.expiresAt <= new Date() ||
    challenge.attempts >= challenge.maxAttempts ||
    !challenge.methods.includes(method)
  ) {
    throw new AuthError("mfa_challenge_invalid", "MFA challenge is invalid or expired", 401);
  }
  return challenge;
}

async function recordFailedChallenge(
  ctx: AuthEngineContext,
  challenge: MfaChallenge,
  request?: RequestContext
): Promise<void> {
  await ctx.storage.incrementMfaChallengeAttempts(challenge.id, new Date());
  await audit(ctx, {
    eventType: "mfa.challenge_failed",
    actorUserId: challenge.userId,
    targetUserId: challenge.userId,
    context: request
  });
}

async function requireActiveTotp(ctx: AuthEngineContext, userId: string): Promise<TotpFactor> {
  const factor = await ctx.storage.getActiveTotpFactorByUserId(userId);
  if (!factor) {
    throw new AuthError("mfa_code_invalid", "TOTP is not enabled", 400);
  }
  return factor;
}

async function verifyAndConsumeTotp(
  ctx: AuthEngineContext,
  factor: TotpFactor,
  code: string
): Promise<void> {
  const timestep = await verifyTotpCode(ctx, factor, code);
  const consumed = await ctx.storage.useTotpTimestep(factor.id, timestep, new Date());
  if (!consumed) {
    throw new AuthError("mfa_timestep_reused", "Authentication code was already used", 401);
  }
}

async function verifyTotpCode(
  ctx: AuthEngineContext,
  factor: TotpFactor,
  code: string
): Promise<number> {
  await rateLimit(ctx, "totp-verify", factor.userId, ctx.mfaMaxAttempts, ctx.mfaChallengeTtlMs);
  const secret = await decryptTotpSecret(ctx, factor);
  const timestep = validateTotp(secret, code);
  if (timestep === null) {
    throw new AuthError("mfa_code_invalid", "Invalid authentication code", 401);
  }
  return timestep;
}

async function decryptTotpSecret(ctx: AuthEngineContext, factor: TotpFactor): Promise<string> {
  const encryption = requireEncryptionKeyRing(ctx.encryption, "MFA");
  const decrypted = await encryption.decrypt(
    {
      ciphertext: factor.ciphertext,
      nonce: factor.nonce,
      encryptionKeyId: factor.encryptionKeyId
    },
    "totp",
    { factorId: factor.id, userId: factor.userId }
  );
  if (decrypted.needsRotation) {
    const rotated = await encryption.encrypt(decrypted.plaintext, "totp", {
      factorId: factor.id,
      userId: factor.userId
    });
    await ctx.storage.updateTotpFactor(factor.id, {
      ciphertext: rotated.ciphertext,
      nonce: rotated.nonce,
      encryptionKeyId: rotated.encryptionKeyId,
      updatedAt: new Date()
    });
  }
  return decrypted.plaintext;
}

function validateTotp(secret: string, code: string): number | null {
  if (!/^\d{6}$/.test(code)) {
    return null;
  }
  const now = Date.now();
  const delta = totpFor(secret, "", "").validate({ token: code, timestamp: now, window: totpWindow });
  return delta === null ? null : TOTP.counter({ period: totpPeriodSeconds, timestamp: now }) + delta;
}

function totpFor(secret: string, issuer: string, label: string): TOTP {
  return new TOTP({
    issuer,
    label,
    secret: Secret.fromBase32(secret),
    algorithm: "SHA1",
    digits: totpDigits,
    period: totpPeriodSeconds
  });
}

async function replaceRecoveryCodes(ctx: AuthEngineContext, userId: string): Promise<string[]> {
  const now = new Date();
  const rawCodes = Array.from({ length: ctx.recoveryCodeCount }, createRecoveryCode);
  await ctx.storage.replaceRecoveryCodes(
    userId,
    rawCodes.map((code) => ({
      id: createId("mfr"),
      userId,
      codeHash: hash(ctx, normalizeRecoveryCode(code)),
      consumedAt: null,
      createdAt: now
    }))
  );
  return rawCodes;
}

function createRecoveryCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  const compact = Array.from(
    bytes,
    (byte) => recoveryCodeAlphabet[byte & 31]
  ).join("");
  return `${compact.slice(0, 6)}-${compact.slice(6, 12)}`;
}

function normalizeRecoveryCode(value: string): string {
  return value.replace(/[^A-Za-z0-9]/g, "").toUpperCase();
}
