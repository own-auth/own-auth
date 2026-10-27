import { afterEach, expect, it, vi } from "vitest";
import { createOwnAuth, InMemoryAuthStorage } from "../src/index.js";

afterEach(() => vi.restoreAllMocks());

it("refuses a custom rate limit store without deletion before changing the account", async () => {
  const storage = new InMemoryAuthStorage();
  const auth = createOwnAuth({ storage, rateLimitStore: {
    async hit() { return { count: 1, resetAt: new Date(), allowed: true }; }, async reset() {}
  } });
  const signup = await auth.signUpEmailPassword({ email: "unsupported-rate@example.com", password: "correct-horse" });
  await expect(auth.eraseUser({ operationId: crypto.randomUUID(), confirmation: "erase", sessionToken: signup.sessionToken }))
    .rejects.toMatchObject({ code: "user_erasure_unsupported", details: { stores: ["rate_limits"] } });
  expect(await auth.getCurrentSession(signup.sessionToken)).not.toBeNull();
});

it("keeps a failed rate store pending and completes a later cleanup retry", async () => {
  vi.spyOn(console, "warn").mockImplementation(() => {});
  const storage = new InMemoryAuthStorage();
  const erase = vi.spyOn(storage.rateLimitStore, "eraseUser").mockRejectedValueOnce(new Error("private failure"));
  const auth = createOwnAuth({ storage });
  const signup = await auth.signUpEmailPassword({ email: "failed-rate@example.com", password: "correct-horse" });
  const operationId = crypto.randomUUID();
  expect(await auth.eraseUser({ operationId, confirmation: "erase", sessionToken: signup.sessionToken }))
    .toMatchObject({ status: "pending", pendingLocalStores: ["rate_limits"] });
  expect(await auth.resumeUserErasure({ operationId })).toMatchObject({ status: "complete" });
  expect(erase).toHaveBeenCalledTimes(2);
  await expect(storage.rateLimitStore.hit(`session:${signup.user.id}`, 60_000, 10, signup.user.id))
    .rejects.toMatchObject({ code: "invalid_credentials" });
});
