import type { UserErasureSubject } from "./user-erasure.js";
import { isRecord } from "./value-guards.js";

export const erasureReferenceKeys = [
  "id", "userId", "user_id", "actorUserId", "actor_user_id", "actorId", "targetUserId",
  "target_user_id", "recipientUserId", "ownerUserId", "owner_user_id", "invitedByUserId",
  "invited_by_user_id", "revokedBy", "revoked_by", "accountId", "account_id", "sessionId",
  "session_id", "tokenId", "token_id", "otpId", "apiKeyId", "api_key_id", "grantId",
  "grant_id", "membershipId", "membership_id", "memberId", "scimUserId", "eventId", "event_id",
  "deliveryId", "delivery_id", "mfaChallengeId", "mfa_challenge_id", "organisationId", "organisation_id",
  "connectionId", "connection_id"
] as const;
export const erasureEmailKeys = ["email", "normalizedEmail", "providerEmail", "inviteeEmail"] as const;
export const erasurePhoneKeys = ["phone", "providerPhone"] as const;
const referenceKeys: ReadonlySet<string> = new Set(erasureReferenceKeys);
const emailKeys: ReadonlySet<string> = new Set(erasureEmailKeys);
const phoneKeys: ReadonlySet<string> = new Set(erasurePhoneKeys);

export function erasureLookupIdentifiers(subject: Readonly<UserErasureSubject>): string[] {
  return [...new Set([
    ...subject.references, subject.email, subject.phone,
    ...subject.identities.map((identity) => identity.providerAccountId)
  ].filter((id): id is string => Boolean(id)))];
}

export function matchesErasureSubject(value: unknown, subject: UserErasureSubject): boolean {
  if (Array.isArray(value)) return value.some((item) => matchesErasureSubject(item, subject));
  if (!isRecord(value)) return false;
  return Object.entries(value).some(([key, item]) => {
    if (typeof item === "string") {
      if (referenceKeys.has(key) && subject.references.includes(item)) return true;
      if (key === "targetId" && value.targetType === "user" && item === subject.userId) return true;
      if (emailKeys.has(key) && subject.email && item.toLowerCase() === subject.email.toLowerCase()) return true;
      if (phoneKeys.has(key) && subject.phone && item === subject.phone) return true;
      if (key === "payload") {
        try { return matchesErasureSubject(JSON.parse(item), subject); } catch { return false; }
      }
    }
    return matchesErasureSubject(item, subject);
  });
}

export function matchesErasureIdentity(
  identity: { userId?: string; email?: string | null; phone?: string | null; provider?: string; providerAccountId?: string },
  subject: UserErasureSubject
): boolean {
  return identity.userId === subject.userId ||
    Boolean(identity.email && subject.email && identity.email.toLowerCase() === subject.email.toLowerCase()) ||
    Boolean(identity.phone && identity.phone === subject.phone) ||
    subject.identities.some((account) => account.provider === identity.provider &&
      account.providerAccountId === identity.providerAccountId);
}
