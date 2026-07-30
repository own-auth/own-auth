import { AuthError } from "./errors.js";
import { createId, randomNumericCode, safeEqual } from "./crypto.js";
import { isExpired } from "./normalise.js";
import { minute, type DeliveryResult, type RequestSmsOtpInput, type SmsOtpVerificationResult, type VerifySmsOtpInput } from "./auth-engine-types.js";
import type { SmsOtpPurpose, User } from "./types.js";
import {
  assertUserEnabled,
  audit,
  hash,
  rateLimit,
  requireValidPhone,
  type AuthEngineContext
} from "./auth-engine-internals.js";
import { completeFirstFactor } from "./auth-engine-mfa.js";
import { createUser } from "./auth-engine-users.js";
import { sendSms } from "./auth-engine-delivery.js";

export async function requestSmsOtp(
  ctx: AuthEngineContext,
  input: RequestSmsOtpInput
): Promise<DeliveryResult> {
  const purpose = requireSmsPurpose(input.purpose);
  const phone = requireValidPhone(input.phone);
  await rateLimit(ctx, `sms-${purpose}`, phone, 5, 15 * minute);

  let user: User | null;
  if (purpose === "phone_verification") {
    if (!input.userId) {
      throw new AuthError(
        "validation_error",
        "userId is required for phone verification",
        400
      );
    }
    user = await ctx.storage.getUserById(input.userId);
    if (!user) {
      throw new AuthError("user_not_found", "User not found", 404);
    }
    assertUserEnabled(user);
  } else {
    if (input.userId !== undefined) {
      throw new AuthError(
        "validation_error",
        "userId is only allowed for phone verification",
        400
      );
    }
    user = await ctx.storage.getUserByPhone(phone);
  }
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

  await sendSms(ctx, {
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
  const purpose = requireSmsPurpose(input.purpose);
  const phone = requireValidPhone(input.phone);
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
    await ctx.storage.incrementSmsOtpAttempts(otp.id, now);
    throw new AuthError("invalid_otp", "Invalid or expired code", 401);
  }

  const consumedOtp = await ctx.storage.consumeSmsOtp(otp.id, now);
  if (!consumedOtp) {
    throw new AuthError("invalid_otp", "Invalid or expired code", 401);
  }

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
  if (
    otp.userId &&
    purpose !== "phone_verification" &&
    user.phone !== phone
  ) {
    throw new AuthError("invalid_otp", "Invalid or expired code", 401);
  }

  assertUserEnabled(user);

  const updatedUser = await ctx.storage.updateUser(user.id, {
    phone,
    phoneVerifiedAt: new Date(),
    updatedAt: new Date()
  });
  if (!updatedUser) {
    throw new AuthError("user_not_found", "User not found", 404);
  }
  user = updatedUser;

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
    return { status: "verified", user, session: null, sessionToken: null };
  }

  return completeFirstFactor(ctx, user, "phone", input.request);
}

function requireSmsPurpose(value: SmsOtpPurpose | undefined): SmsOtpPurpose {
  const purpose = value ?? "phone_login";
  if (
    purpose !== "phone_login" &&
    purpose !== "phone_verification" &&
    purpose !== "account_recovery"
  ) {
    throw new AuthError("validation_error", "SMS purpose is invalid", 400);
  }
  return purpose;
}
