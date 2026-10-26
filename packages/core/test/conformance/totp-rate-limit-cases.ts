import { createOwnAuth, isAuthError } from "../../src/index.js";
import type { AtomicAdapterCase, AtomicAdapterHarness } from "./atomic-adapter-cases.js";
import { assertConformanceEqual } from "./conformance-assertions.js";
import { uniqueConformanceValue as unique } from "./conformance-values.js";
import { createTotpCode, requireCompleteSignIn, requireMfaSignIn } from "../identity-test-helpers.js";

export const totpRateLimitAdapterCases: readonly AtomicAdapterCase[] = [
  {
    name: "shares the TOTP budget across settings, sessions, enrollment, and login challenges",
    async run(harness) {
      const { auth, sessions, email, secret, code, userId } = await fixture(harness);
      await rejectsCode(auth[0].disableTotp({ sessionToken: sessions[0], code }), "mfa_code_invalid");
      await rejectsCode(auth[1].regenerateRecoveryCodes({ sessionToken: sessions[1], code }), "mfa_code_invalid");
      const challenge = requireMfaSignIn(await auth[1].signInEmailPassword({ email, password: "correct-horse" }));
      await rejectsCode(auth[1].completeMfaWithTotp({ challengeToken: challenge.challengeToken, code }), "mfa_code_invalid");
      // Enrollment consumed the first of the four available checks.
      await rejectsCode(auth[0].disableTotp({ sessionToken: sessions[0], code: createTotpCode(secret) }), "rate_limited");
      await rejectsCode(auth[1].regenerateRecoveryCodes({ sessionToken: sessions[1], code }), "rate_limited");
      const freshChallenge = requireMfaSignIn(await auth[0].signInEmailPassword({ email, password: "correct-horse" }));
      await rejectsCode(auth[0].completeMfaWithTotp({ challengeToken: freshChallenge.challengeToken, code }), "rate_limited");
      assertConformanceEqual((await harness.storage[0].getActiveTotpFactorByUserId(userId))?.status,
        "active", "denied settings requests leave TOTP enabled");
    }
  },
  {
    name: "reserves TOTP checks atomically across simultaneous settings requests and connections",
    async run(harness) {
      const { auth, sessions, code } = await fixture(harness);
      const results = await Promise.allSettled(Array.from({ length: 12 }, (_, index) =>
        index % 2 === 0
          ? auth[0].disableTotp({ sessionToken: sessions[0], code })
          : auth[1].regenerateRecoveryCodes({ sessionToken: sessions[1], code })
      ));
      const errors = results.map((result) => result.status === "rejected" && isAuthError(result.reason)
        ? result.reason.code : "unexpected_result");
      assertConformanceEqual(errors.filter((code) => code === "mfa_code_invalid").length,
        3, "only the remaining three checks can validate a code");
      assertConformanceEqual(errors.filter((code) => code === "rate_limited").length,
        9, "all other concurrent requests are denied before verification");
    }
  }
];

async function fixture({ storage, rateLimits }: AtomicAdapterHarness) {
  const auth = storage.map((adapter, index) => createOwnAuth({
    storage: adapter,
    rateLimitStore: rateLimits[index],
    tokenPepper: "totp-conformance-pepper",
    encryption: { current: { id: "totp", key: new Uint8Array(32).fill(11) } },
    mfa: { maxAttempts: 4, challengeTtlMs: 300_000 }
  }));
  const email = `${unique("totp")}@example.com`;
  const first = await auth[0]!.signUpEmailPassword({ email, password: "correct-horse" });
  const second = requireCompleteSignIn(await auth[1]!.signInEmailPassword({ email, password: "correct-horse" }));
  const enrollment = await auth[0]!.beginTotpEnrollment({ sessionToken: first.sessionToken });
  await auth[0]!.confirmTotpEnrollment({
    sessionToken: first.sessionToken, factorId: enrollment.factorId, code: createTotpCode(enrollment.secret)
  });
  const now = Date.now();
  const validCodes = new Set([-30_000, 0, 30_000].map((offset) => createTotpCode(enrollment.secret, now + offset)));
  const code = Array.from({ length: 10 }, (_, index) => String(index).padStart(6, "0"))
    .find((candidate) => !validCodes.has(candidate))!;
  return {
    auth: [auth[0]!, auth[1]!] as const,
    sessions: [first.sessionToken, second.sessionToken] as const,
    email, secret: enrollment.secret, code, userId: first.user.id
  };
}

async function rejectsCode(result: Promise<unknown>, code: string): Promise<void> {
  try { await result; } catch (error) {
    assertConformanceEqual(isAuthError(error) ? error.code : "unexpected_error", code, "TOTP rejection");
    return;
  }
  throw new Error(`Expected TOTP rejection ${code}`);
}
