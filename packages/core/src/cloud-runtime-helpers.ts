import { AuthError } from "./errors.js";
import type { CloudSecurityDecision } from "./cloud-types.js";
import { isRecord } from "./value-guards.js";

export const maximumCloudSecurityCacheAgeMs = 5 * 60_000;

export const cloudSignInOperations = new Set([
  "signInEmailPassword",
  "verifyMagicLink",
  "verifySmsOtp",
  "completeOAuthSignIn",
  "signInWithGoogleOneTap",
  "signInWithVerifiedExternalIdentity",
  "completePasskeyAuthentication"
]);

export function invalidCloudChallenge(): AuthError {
  return new AuthError("cloud_challenge_invalid", "Cloud challenge is invalid or expired", 401);
}

export function clampCloudDifficulty(value: number): number {
  return Math.max(1, Math.min(20, Math.round(value)));
}

export function cloudPositiveInteger(
  value: number,
  min: number,
  max: number,
  label: string
): number {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${label} must be between ${min} and ${max}`);
  }
  return value;
}

export function isCloudSecurityDecision(value: unknown): value is CloudSecurityDecision {
  return Boolean(isRecord(value) && ["allow", "challenge", "deny"].includes(String(value.decision)));
}

export function safeCloudError(error: unknown): string {
  return error instanceof Error ? error.name : "request failed";
}

export function cloudEmailType(type: string): string {
  if (type === "email_verification") return "verification";
  if (type === "organisation_invite") return "invite";
  return type;
}

export function cloudSmsType(purpose: string): string {
  return purpose === "phone_login" ? "sms_login_otp" : purpose;
}
