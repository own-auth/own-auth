import { createOwnAuth, MemoryEmailProvider } from "../../src/index.js";
import type { AtomicEmailOwnershipInput } from "../../src/auth-storage-atomic.js";
import type { AtomicAdapterCase, AtomicAdapterHarness } from "./atomic-adapter-cases.js";
import { assertConformanceEqual, assertSingleValueWinner } from "./conformance-assertions.js";
import { uniqueConformanceValue as unique } from "./conformance-values.js";

export const passwordResetAdapterCases: readonly AtomicAdapterCase[] = [
  {
    name: "invalidates a distinct unused reset link after a successful reset",
    async run(harness) {
      const { auth, email, sessions } = await fixture(harness);
      const first = (await auth[0].requestPasswordReset({ email })).token!;
      const second = (await auth[1].requestPasswordReset({ email })).token!;
      await auth[0].resetPassword({ token: first, newPassword: "replacement-password" });
      await rejectsAuth(auth[1].resetPassword({ token: second, newPassword: "stale-password" }));
      assertConformanceEqual(await auth[0].getCurrentSession(sessions[0]), null, "reset revokes the original session");
      const fresh = (await auth[1].requestPasswordReset({ email })).token!;
      await auth[1].resetPassword({ token: fresh, newPassword: "fresh-password" });
    }
  },
  {
    name: "invalidates existing reset authority after an authenticated password replacement",
    async run(harness) {
      const { auth, email, sessions } = await fixture(harness);
      const token = (await auth[0].requestPasswordReset({ email })).token!;
      await auth[0].changePassword({ sessionToken: sessions[0], currentPassword: "original-password", newPassword: "replacement-password" });
      await rejectsAuth(auth[1].resetPassword({ token, newPassword: "stale-password" }));
      const fresh = (await auth[1].requestPasswordReset({ email })).token!;
      await auth[1].resetPassword({ token: fresh, newPassword: "fresh-password" });
    }
  },
  {
    name: "allows only one of two distinct reset tokens to replace the password concurrently",
    async run(harness) {
      const { input, second } = await resetInputs(harness);
      const winner = assertSingleValueWinner(await Promise.all([
        harness.storage[0].claimEmailOwnershipAtomically(input),
        harness.storage[1].claimEmailOwnershipAtomically(second)
      ]), "distinct reset token race");
      assertConformanceEqual((await harness.storage[0].getUserById(input.sourceUserId!))?.passwordHash,
        winner.user.passwordHash, "only the winning reset password persists");
    }
  },
  {
    name: "allows one authenticated replacement from the same previous password",
    async run(harness) {
      const { signup } = await fixture(harness);
      const update = { userId: signup.user.id, expectedPasswordHash: signup.user.passwordHash,
        passwordHash: "first-hash", updatedAt: new Date(), purpose: "replacement" as const };
      const winner = assertSingleValueWinner(await Promise.all([
        harness.storage[0].updatePasswordAtomically(update),
        harness.storage[1].updatePasswordAtomically({ ...update, passwordHash: "second-hash" })
      ]), "authenticated replacement race");
      assertConformanceEqual((await harness.storage[0].getUserById(signup.user.id))?.passwordHash,
        winner.passwordHash, "stale authentication cannot overwrite the winner");
    }
  },
  {
    name: "serializes an authenticated password change against a reset already in progress",
    async run(harness) {
      const { input } = await resetInputs(harness);
      const user = (await harness.storage[0].getUserById(input.sourceUserId!))!;
      const results = await Promise.all([
        harness.storage[0].updatePasswordAtomically({ userId: user.id,
          expectedPasswordHash: user.passwordHash, passwordHash: "authenticated-change",
          updatedAt: new Date(), purpose: "replacement" }),
        harness.storage[1].claimEmailOwnershipAtomically(input)
      ]);
      assertConformanceEqual(results.filter((result) => result !== null).length, 1,
        "only one operation authorized by the previous password state succeeds");
    }
  },
  {
    name: "preserves reset links during a password rehash and rejects a stale later rehash",
    async run(harness) {
      const { input } = await resetInputs(harness);
      const user = (await harness.storage[0].getUserById(input.sourceUserId!))!;
      const rehash = { userId: user.id, expectedPasswordHash: user.passwordHash,
        passwordHash: "same-password-new-format", updatedAt: new Date(), purpose: "rehash" as const };
      await harness.storage[0].updatePasswordAtomically(rehash);
      const reset = await harness.storage[1].claimEmailOwnershipAtomically(input);
      assertConformanceEqual(reset?.user.passwordHash, input.passwordHash!, "reset survives a format upgrade");
      assertConformanceEqual(await harness.storage[0].updatePasswordAtomically(rehash), null,
        "an older sign in cannot restore its password after reset");
    }
  },
  {
    name: "rolls back reset version advancement when pending account replacement fails",
    async run(harness) {
      const { input } = await resetInputs(harness);
      await harness.storage[0].updateUser(input.sourceUserId!, { emailVerifiedAt: null });
      const collision = unique("account");
      await harness.storage[0].createAccount({ ...input.replacementAccount,
        id: collision, userId: input.sourceUserId!, provider: "google", providerAccountId: unique("google") });
      input.replacementAccount.id = collision;
      let failed = false;
      try { await harness.storage[0].claimEmailOwnershipAtomically(input); } catch { failed = true; }
      assertConformanceEqual(failed, true, "replacement constraint fails");
      const proof = input.proof;
      if (proof.kind !== "token") throw new Error("Expected reset token");
      assertConformanceEqual((await harness.storage[0].getTokenByHash(proof.tokenHash, "password_reset"))?.usedAt,
        null, "proof remains usable and its version is unchanged after rollback");
      assertConformanceEqual((await harness.storage[0].getUserById(input.sourceUserId!))?.email,
        input.email, "original user survives rollback");
      input.replacementAccount.id = unique("retry-account");
      assertConformanceEqual((await harness.storage[0].claimEmailOwnershipAtomically(input))?.created,
        true, "the same proof can be retried through the corrected operation");
    }
  },
  {
    name: "invalidates links even when a replacement has the same stored password hash",
    async run(harness) {
      const { input } = await resetInputs(harness);
      const user = (await harness.storage[0].getUserById(input.sourceUserId!))!;
      await harness.storage[0].updatePasswordAtomically({ userId: user.id,
        expectedPasswordHash: user.passwordHash, passwordHash: user.passwordHash!,
        updatedAt: new Date(), purpose: "replacement" });
      assertConformanceEqual(await harness.storage[1].claimEmailOwnershipAtomically(input), null,
        "reset invalidation does not depend on a changed hash or timestamp");
    }
  }
];

async function fixture({ storage, rateLimits }: AtomicAdapterHarness) {
  const auth = storage.map((adapter, index) => createOwnAuth({
    storage: adapter, rateLimitStore: rateLimits[index], tokenPepper: "reset-conformance",
    exposeRawTokens: true, emailProvider: new MemoryEmailProvider(),
    password: { hasher: {
      hash: async (password) => `fixture:${password}`,
      verify: async (password, hash) => hash === `fixture:${password}`,
      needsRehash: () => false
    } }
  }));
  const email = `${unique("reset")}@example.com`;
  const signup = await auth[0]!.signUpEmailPassword({ email, password: "original-password" });
  await storage[0].updateUser(signup.user.id, { emailVerifiedAt: new Date() });
  return { auth: [auth[0]!, auth[1]!] as const, email, signup, sessions: [signup.sessionToken] as const };
}

async function resetInputs(harness: AtomicAdapterHarness) {
  const { signup, email } = await fixture(harness);
  const now = new Date();
  const makeInput = async (): Promise<AtomicEmailOwnershipInput> => {
    const hash = unique("reset-proof");
    await harness.storage[0].createToken({ id: unique("token"), tokenHash: hash, userId: signup.user.id,
      type: "password_reset", email, phone: null, organisationId: null, createdAt: now, usedAt: null,
      expiresAt: new Date(now.getTime() + 60_000) });
    const passwordHash = unique("password-hash");
    const owner = { ...signup.user, id: unique("owner"), passwordHash, emailVerifiedAt: now };
    return { operationId: unique("reset"), sourceUserId: signup.user.id, email, verifiedAt: now,
      passwordHash, sessionTokenHash: null, replacementUser: owner,
      replacementAccount: { id: unique("account"), userId: owner.id, provider: "password",
        providerAccountId: email, providerEmail: email, providerPhone: null, createdAt: now, updatedAt: now },
      proof: { kind: "token", type: "password_reset", tokenHash: hash } };
  };
  return { input: await makeInput(), second: await makeInput() };
}

async function rejectsAuth(result: Promise<unknown>) {
  try { await result; } catch (error) {
    assertConformanceEqual((error as { code: string }).code, "invalid_token", "older reset authority is invalid");
    return;
  }
  throw new Error("An older reset link replaced the password");
}
