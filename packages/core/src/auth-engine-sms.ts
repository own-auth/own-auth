import { AuthError } from "./errors.js";
import { createId, randomNumericCode, safeEqual } from "./crypto.js";
import { isExpired, normalizePhone } from "./normalise.js";
import { minute, type DeliveryResult, type RequestSmsOtpInput, type SmsOtpVerificationResult, type VerifySmsOtpInput } from "./auth-engine-types.js";
import {
  assertUserEnabled,
  audit,
  createSession,
  hash,
  rateLimit,
  type AuthEngineContext
} from "./auth-engine-internals.js";
import { createUser } from "./auth-engine-users.js";

export async function requestSmsOtp(
  ctx: AuthEngineContext,
  input: RequestSmsOtpInput
): Promise<DeliveryResult> {
  const purpose = input.purpose ?? "phone_login";
  const phone = normalizePhone(input.phone);
  await rateLimit(ctx, `sms-${purpose}`, phone, 5, 15 * minute);

  const user = input.userId
    ? await ctx.storage.getUserById(input.userId)
    : await ctx.storage.getUserByPhone(phone);
  const code = randomNumericCode(ctx.smsCodeLength);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ctx.smsOtpTtlMs);

  const otp = await ctx.storage.createSmsOtp({
    id: createId("otp"),
    phone,
    userId: user?.id ?? null,
    codeHash: hash(ctx, code),
    purpose,
    expiresAt,
    attempts: 0,
    maxAttempts: ctx.smsMaxAttempts,
    consumedAt: null,
    createdAt: now,
    lastSentAt: now
  });

  await ctx.smsProvider.send({
    to: phone,
    purpose,
    code,
    expiresAt
  });

  await audit(ctx, {
    eventType: "sms_otp.sent",
    actorUserId: user?.id ?? null,
    targetUserId: user?.id ?? null,
    context: input.request,
    metadata: { purpose, otpId: otp.id }
  });

  const delivery: DeliveryResult = { sent: true, expiresAt };
  if (ctx.exposeRawTokens) {
    delivery.code = code;
  }

  return delivery;
}

export async function verifySmsOtp(
  ctx: AuthEngineContext,
  input: VerifySmsOtpInput
): Promise<SmsOtpVerificationResult> {
  const purpose = input.purpose ?? "phone_login";
  const phone = normalizePhone(input.phone);
  await rateLimit(ctx, `sms-verify-${purpose}`, phone, 10, 15 * minute);

  const otp = await ctx.storage.getLatestSmsOtp(phone, purpose);
  const now = new Date();

  if (!otp || otp.consumedAt || isExpired(otp.expiresAt, now)) {
    throw new AuthError("invalid_otp", "Invalid or expired code", 401);
  }

  if (otp.attempts >= otp.maxAttempts) {
    throw new AuthError("otp_attempts_exceeded", "Too many code attempts", 429);
  }

  const codeHash = hash(ctx, input.code);
  if (!safeEqual(codeHash, otp.codeHash)) {
    await ctx.storage.updateSmsOtp(otp.id, { attempts: otp.attempts + 1 });
    throw new AuthError("invalid_otp", "Invalid or expired code", 401);
  }

  await ctx.storage.updateSmsOtp(otp.id, {
    consumedAt: now,
    attempts: otp.attempts + 1
  });

  let user = otp.userId ? await ctx.storage.getUserById(otp.userId) : null;
  if (!user) {
    user = await ctx.storage.getUserByPhone(phone);
  }

  if (!user && purpose === "phone_login" && ctx.allowPhoneSignup) {
    user = await createUser(ctx, { phone });
  }

  if (!user) {
    throw new AuthError("user_not_found", "User not found", 404);
  }

  assertUserEnabled(user);

  user = (await ctx.storage.updateUser(user.id, {
    phone,
    phoneVerifiedAt: new Date(),
    updatedAt: new Date()
  })) ?? user;

  await audit(ctx, {
    eventType: "sms_otp.verified",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request,
    metadata: { purpose }
  });
  await audit(ctx, {
    eventType: "phone.verified",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request
  });

  if (purpose !== "phone_login") {
    return { user, session: null, sessionToken: null };
  }

  const sessionResult = await createSession(ctx, user, input.request);
  await audit(ctx, {
    eventType: "user.signed_in",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request,
    metadata: { method: "phone_otp" }
  });

  return sessionResult;
}
