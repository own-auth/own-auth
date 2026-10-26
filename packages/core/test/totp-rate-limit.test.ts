import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createOwnAuth,
  createOwnAuthHandler,
  InMemoryAuthStorage,
  InMemoryRateLimitStore
} from "../src/index.js";
import { createTotpCode } from "./identity-test-helpers.js";
import { jsonRequest } from "./http-test-helpers.js";

const windowMs = 300_000;
const start = Date.UTC(2026, 9, 26, 12);

async function harness(email = "totp-limit@example.com") {
  const storage = new InMemoryAuthStorage();
  const rateLimitStore = new InMemoryRateLimitStore();
  const auth = createOwnAuth({
    storage, rateLimitStore, tokenPepper: "totp-rate-limit-test",
    encryption: { current: { id: "current", key: new Uint8Array(32).fill(8) } },
    mfa: { maxAttempts: 4, challengeTtlMs: windowMs }
  });
  const signup = await auth.signUpEmailPassword({ email, password: "correct-horse" });
  const enrollment = await auth.beginTotpEnrollment({ sessionToken: signup.sessionToken });
  const valid = new Set([-30_000, 0, 30_000, 60_000].map((offset) => createTotpCode(enrollment.secret, start + offset)));
  const wrongCode = Array.from({ length: 10 }, (_, index) => String(index).padStart(6, "0"))
    .find((code) => !valid.has(code))!;
  return { auth, storage, rateLimitStore, signup, enrollment, wrongCode };
}

async function enabledHarness() {
  const setup = await harness();
  await setup.auth.confirmTotpEnrollment({
    sessionToken: setup.signup.sessionToken,
    factorId: setup.enrollment.factorId,
    code: createTotpCode(setup.enrollment.secret)
  });
  return setup;
}

describe("shared TOTP verification budget", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(start);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("does not reset the user's budget by starting a new enrollment", async () => {
    const { auth, signup, enrollment, wrongCode, storage } = await harness();
    for (let attempt = 0; attempt < 4; attempt++) {
      await expect(auth.confirmTotpEnrollment({
        sessionToken: signup.sessionToken, factorId: enrollment.factorId, code: wrongCode
      })).rejects.toMatchObject({ code: "mfa_code_invalid" });
    }
    const next = await auth.beginTotpEnrollment({ sessionToken: signup.sessionToken });
    await expect(auth.confirmTotpEnrollment({
      sessionToken: signup.sessionToken, factorId: next.factorId, code: createTotpCode(next.secret)
    })).rejects.toMatchObject({ code: "rate_limited", statusCode: 429 });
    expect(await storage.getActiveTotpFactorByUserId(signup.user.id)).toBeNull();
  });

  it("counts successful checks and permits verification after the existing window expires", async () => {
    const { auth, signup, enrollment, wrongCode } = await enabledHarness();
    vi.setSystemTime(start + 30_000);
    await auth.regenerateRecoveryCodes({ sessionToken: signup.sessionToken, code: createTotpCode(enrollment.secret) });
    // The successful enrollment and regeneration leave two checks in this window.
    for (let attempt = 0; attempt < 2; attempt++) {
      await expect(auth.disableTotp({ sessionToken: signup.sessionToken, code: wrongCode }))
        .rejects.toMatchObject({ code: "mfa_code_invalid" });
    }
    await expect(auth.regenerateRecoveryCodes({ sessionToken: signup.sessionToken, code: wrongCode }))
      .rejects.toMatchObject({ code: "rate_limited" });
    vi.setSystemTime(start + windowMs);
    await expect(auth.regenerateRecoveryCodes({
      sessionToken: signup.sessionToken, code: createTotpCode(enrollment.secret)
    })).resolves.toHaveLength(10);
  });

  it("fails before consuming a code or changing the factor when the store is unavailable", async () => {
    const { auth, storage, rateLimitStore, signup, enrollment } = await enabledHarness();
    const consume = vi.spyOn(storage, "useTotpTimestep");
    const update = vi.spyOn(storage, "updateTotpFactor");
    vi.spyOn(rateLimitStore, "hit").mockRejectedValue(new Error("Rate limit database unavailable"));
    vi.setSystemTime(start + 30_000);
    await expect(auth.disableTotp({
      sessionToken: signup.sessionToken, code: createTotpCode(enrollment.secret)
    })).rejects.toThrow("Rate limit database unavailable");
    expect(consume).not.toHaveBeenCalled();
    expect(update).not.toHaveBeenCalled();
    expect((await storage.getActiveTotpFactorByUserId(signup.user.id))?.status).toBe("active");
  });

  it("returns HTTP 429 across both settings routes before changing MFA", async () => {
    const { auth, signup, wrongCode, storage } = await enabledHarness();
    const handler = createOwnAuthHandler(auth);
    const paths = ["/api/auth/mfa/totp/disable", "/api/auth/mfa/recovery/regenerate"];
    for (let attempt = 0; attempt < 5; attempt++) {
      const response = await handler(jsonRequest(paths[attempt % 2]!, { code: wrongCode }, {
        authorization: `Bearer ${signup.sessionToken}`
      }));
      expect(response.status).toBe(attempt < 3 ? 401 : 429);
      if (attempt >= 3) expect(await response.json()).toMatchObject({ error: { code: "rate_limited" } });
    }
    expect((await storage.getActiveTotpFactorByUserId(signup.user.id))?.status).toBe("active");
  });

  it("keeps budgets independent for different users", async () => {
    const { auth, signup, wrongCode } = await enabledHarness();
    for (let attempt = 0; attempt < 3; attempt++) {
      await expect(auth.disableTotp({ sessionToken: signup.sessionToken, code: wrongCode }))
        .rejects.toMatchObject({ code: "mfa_code_invalid" });
    }
    const other = await auth.signUpEmailPassword({ email: "other-totp@example.com", password: "correct-horse" });
    const pending = await auth.beginTotpEnrollment({ sessionToken: other.sessionToken });
    await expect(auth.confirmTotpEnrollment({
      sessionToken: other.sessionToken, factorId: pending.factorId, code: createTotpCode(pending.secret)
    })).resolves.toMatchObject({ recoveryCodes: expect.any(Array) });
  });
});
