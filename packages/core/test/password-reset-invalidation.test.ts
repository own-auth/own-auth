import { describe, expect, it, vi } from "vitest";
import { createOwnAuth, InMemoryAuthStorage, MemoryEmailProvider } from "../src/index.js";
import { PostgresAuthStorage } from "../src/postgres/index.js";
import { D1AuthStorage } from "../src/d1/index.js";
import { RecordingDb } from "./postgres/recording-postgres.js";
import { RecordingD1 } from "./d1/recording-d1.js";

async function fixture() {
  const storage = new InMemoryAuthStorage();
  const hasher = {
    hash: vi.fn(async (password: string) => `fixture:${password}`),
    verify: async (password: string, hash: string) => hash === `fixture:${password}`,
    needsRehash: () => false
  };
  const auth = createOwnAuth({ storage, tokenPepper: "reset-version-test", exposeRawTokens: true,
    emailProvider: new MemoryEmailProvider(), password: { hasher } });
  const email = "reset-version@example.com";
  const signup = await auth.signUpEmailPassword({ email, password: "original-password" });
  await storage.updateUser(signup.user.id, { emailVerifiedAt: new Date() });
  const token = (await auth.requestPasswordReset({ email })).token!;
  return { auth, storage, hasher, signup, token, email };
}

describe("password reset invalidation", () => {
  it("rejects an older reset whose hashing began before an authenticated change completed", async () => {
    const { auth, hasher, signup, token } = await fixture();
    let resume!: () => void;
    let entered!: () => void;
    const hashing = new Promise<void>((resolve) => { entered = resolve; });
    const gate = new Promise<void>((resolve) => { resume = resolve; });
    hasher.hash.mockImplementation(async (password) => {
      if (password === "delayed-reset-password") { entered(); await gate; }
      return `fixture:${password}`;
    });
    const reset = auth.resetPassword({ token, newPassword: "delayed-reset-password" });
    const rejection = expect(reset).rejects.toMatchObject({ code: "invalid_token" });
    await hashing;
    await auth.changePassword({ sessionToken: signup.sessionToken,
      currentPassword: "original-password", newPassword: "authenticated-password" });
    resume();
    await rejection;
    expect((await auth.storage.getUserById(signup.user.id))?.passwordHash).toBe("fixture:authenticated-password");
  });

  it("preserves earlier reset authority when validation or hashing fails", async () => {
    const { auth, hasher, signup, token } = await fixture();
    await expect(auth.resetPassword({ token, newPassword: "short" })).rejects.toMatchObject({ code: "weak_password" });
    hasher.hash.mockRejectedValueOnce(new Error("Hashing unavailable"));
    await expect(auth.changePassword({ sessionToken: signup.sessionToken,
      currentPassword: "original-password", newPassword: "replacement-password" })).rejects.toThrow("Hashing unavailable");
    await expect(auth.resetPassword({ token, newPassword: "recovered-password" })).resolves.toMatchObject({ email: signup.user.email });
  });

  it("preserves the password and reset authority when the replacement store rejects the write", async () => {
    const { auth, storage, signup, token } = await fixture();
    vi.spyOn(storage, "updatePasswordAtomically").mockRejectedValueOnce(new Error("Storage unavailable"));
    await expect(auth.changePassword({ sessionToken: signup.sessionToken,
      currentPassword: "original-password", newPassword: "replacement-password" })).rejects.toThrow("Storage unavailable");
    expect((await storage.getUserById(signup.user.id))?.passwordHash).toBe(signup.user.passwordHash);
    await expect(auth.resetPassword({ token, newPassword: "recovered-password" })).resolves.toMatchObject({ id: signup.user.id });
  });

  it("preserves reset proof when the reset storage operation fails", async () => {
    const { auth, storage, signup, token } = await fixture();
    vi.spyOn(storage, "claimEmailOwnershipAtomically").mockRejectedValueOnce(new Error("Storage unavailable"));
    await expect(auth.resetPassword({ token, newPassword: "replacement-password" })).rejects.toThrow("Storage unavailable");
    expect((await storage.getUserById(signup.user.id))?.passwordHash).toBe(signup.user.passwordHash);
    await expect(auth.resetPassword({ token, newPassword: "recovered-password" })).resolves.toMatchObject({ id: signup.user.id });
  });

  it("propagates Postgres and D1 errors from the single password and reset version write", async () => {
    const postgres = new RecordingDb();
    vi.spyOn(postgres, "query").mockRejectedValue(new Error("Postgres write rejected"));
    const d1 = new RecordingD1();
    vi.spyOn(d1, "next").mockImplementation(() => { throw new Error("D1 write rejected"); });
    const update = { userId: "user", expectedPasswordHash: "previous", passwordHash: "new",
      updatedAt: new Date(), purpose: "replacement" as const };
    await expect(new PostgresAuthStorage(postgres).updatePasswordAtomically(update)).rejects.toThrow("Postgres write rejected");
    await expect(new D1AuthStorage(d1).updatePasswordAtomically(update)).rejects.toThrow("D1 write rejected");
    expect(d1.calls[0]?.sql).toContain("password_reset_version = password_reset_version + 1");
  });
});
