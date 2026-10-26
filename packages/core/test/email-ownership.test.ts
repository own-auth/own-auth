import { describe, expect, it, vi } from "vitest";
import {
  createOwnAuth,
  createOwnAuthHandler,
  InMemoryAuthStorage,
  MemoryEmailProvider
} from "../src/index.js";
import { createOwnAuthClient } from "../src/client.js";
import { createTotpCode, requireCompleteSignIn } from "./identity-test-helpers.js";
import { jsonRequest } from "./http-test-helpers.js";

function harness() {
  const storage = new InMemoryAuthStorage();
  const emailProvider = new MemoryEmailProvider();
  const auth = createOwnAuth({
    storage, emailProvider, tokenPepper: "email-ownership-test-pepper",
    encryption: { current: { id: "current", key: new Uint8Array(32).fill(6) } },
    oauth: { accountLinking: "verified_email" }
  });
  return { auth, storage, emailProvider, handler: createOwnAuthHandler(auth) };
}

describe("email ownership", () => {
  it("does not give a mailbox owner an attacker's password, MFA, passkeys, linked provider, or profile", async () => {
    const { auth, storage, emailProvider } = harness();
    const attacker = await auth.signUpEmailPassword({
      email: "mailbox-owner@example.com", password: "attacker-password", name: "Attacker supplied name",
      metadata: { role: "attacker supplied role" }
    });
    await auth.linkOAuthProvider({
      actorUserId: attacker.user.id, provider: "google", providerAccountId: "attacker-google",
      email: "attacker@example.com", emailVerified: true
    });
    const enrollment = await auth.beginTotpEnrollment({ sessionToken: attacker.sessionToken });
    await auth.confirmTotpEnrollment({
      sessionToken: attacker.sessionToken, factorId: enrollment.factorId, code: createTotpCode(enrollment.secret)
    });
    const now = new Date();
    await storage.createPasskeyCredential({
      id: "attacker-passkey", userId: attacker.user.id, credentialId: "attacker-credential",
      publicKey: new Uint8Array([1, 2, 3]), counter: 0, transports: [], deviceType: "multiDevice",
      backedUp: true, discoverable: true, name: "Attacker passkey", metadata: {},
      createdAt: now, updatedAt: now, lastUsedAt: null
    });
    await auth.requestMagicLink({ email: "mailbox-owner@example.com" });
    const token = emailProvider.messages.at(-1)!.token;
    const owner = requireCompleteSignIn(await auth.verifyMagicLink({ token }));

    expect(owner.user.id).not.toBe(attacker.user.id);
    expect(owner.user).toMatchObject({
      email: "mailbox-owner@example.com", emailVerifiedAt: expect.any(Date),
      passwordHash: null, phone: null, name: null, metadata: {}
    });
    expect(await storage.listPasskeyCredentialsByUserId(owner.user.id)).toEqual([]);
    expect(await storage.getActiveTotpFactorByUserId(owner.user.id)).toBeNull();
    expect(await auth.getCurrentSession(attacker.sessionToken)).toBeNull();
    expect((await storage.getUserById(attacker.user.id))?.email).toBeNull();
    expect((await storage.getAccountByProvider("google", "attacker-google"))?.userId).toBe(attacker.user.id);
    expect((await storage.getPasskeyCredentialById("attacker-passkey"))?.userId).toBe(attacker.user.id);
    await expect(auth.signInEmailPassword({
      email: "mailbox-owner@example.com", password: "attacker-password"
    })).rejects.toMatchObject({ code: "invalid_credentials" });
    await expect(auth.verifyMagicLink({ token })).rejects.toMatchObject({ code: "token_already_used" });
  });

  it.each(["magic_link", "email_verification", "password_reset"] as const)(
    "keeps an unverified signup when %s proves both the original session and the mailbox",
    async (method) => {
      const { auth, emailProvider } = harness();
      const original = await auth.signUpEmailPassword({ email: `${method}@example.com`, password: "original-password" });
      if (method === "magic_link") await auth.requestMagicLink({ email: original.user.email! });
      else if (method === "email_verification") await auth.requestEmailVerification({ email: original.user.email! });
      else await auth.requestPasswordReset({ email: original.user.email! });
      const proof = { token: emailProvider.messages.at(-1)!.token, sessionToken: original.sessionToken };
      const user = method === "magic_link"
        ? requireCompleteSignIn(await auth.verifyMagicLink(proof)).user
        : method === "email_verification" ? await auth.verifyEmail(proof)
        : await auth.resetPassword({ ...proof, newPassword: "replacement-password" });
      expect(user.id).toBe(original.user.id);
      expect(user.emailVerifiedAt).toBeInstanceOf(Date);
      const password = method === "password_reset" ? "replacement-password" : "original-password";
      expect(requireCompleteSignIn(await auth.signInEmailPassword({ email: original.user.email!, password })).user.id)
        .toBe(original.user.id);
    }
  );

  it.each(["email_verification", "password_reset"] as const)(
    "separates an unproved signup during %s instead of activating the earlier password",
    async (method) => {
      const { auth, emailProvider } = harness();
      const attacker = await auth.signUpEmailPassword({ email: `${method}@example.com`, password: "attacker-password" });
      if (method === "email_verification") await auth.requestEmailVerification({ email: attacker.user.email! });
      else await auth.requestPasswordReset({ email: attacker.user.email! });
      const token = emailProvider.messages.at(-1)!.token;
      const owner = method === "email_verification"
        ? await auth.verifyEmail({ token }) : await auth.resetPassword({ token, newPassword: "owner-password" });
      expect(owner.id).not.toBe(attacker.user.id);
      expect(owner.emailVerifiedAt).toBeInstanceOf(Date);
      expect(await auth.getCurrentSession(attacker.sessionToken)).toBeNull();
      await expect(auth.signInEmailPassword({ email: owner.email!, password: "attacker-password" }))
        .rejects.toMatchObject({ code: "invalid_credentials" });
      if (method === "password_reset") {
        expect(requireCompleteSignIn(await auth.signInEmailPassword({ email: owner.email!, password: "owner-password" })).user.id)
          .toBe(owner.id);
      }
    }
  );

  it("applies the same rule to automatic linking with a verified provider email", async () => {
    const { auth, storage } = harness();
    const attacker = await auth.signUpEmailPassword({ email: "provider-owner@example.com", password: "attacker-password" });
    const owner = requireCompleteSignIn(await auth.signInWithVerifiedExternalIdentity({
      provider: "google", providerAccountId: "real-owner-provider", email: attacker.user.email!, emailVerified: true
    }));
    expect(owner.user.id).not.toBe(attacker.user.id);
    expect(owner.user.passwordHash).toBeNull();
    expect((await storage.getAccountByProvider("google", "real-owner-provider"))?.userId).toBe(owner.user.id);
  });

  it("checks mailbox ownership when concurrent provisioning finds a linked provider account", async () => {
    const { auth, storage } = harness();
    let concurrentSignup: Awaited<ReturnType<typeof auth.signUpEmailPassword>> | undefined;
    vi.spyOn(storage, "createUserAndAccount").mockImplementationOnce(async (_user, account) => {
      concurrentSignup = await auth.signUpEmailPassword({ email: "provider-race@example.com", password: "attacker-password" });
      await storage.createAccount({ ...account, userId: concurrentSignup.user.id });
      throw new Error("Concurrent identity creation");
    });
    const result = requireCompleteSignIn(await auth.signInWithVerifiedExternalIdentity({
      provider: "google", providerAccountId: "concurrent-provider", email: "provider-race@example.com", emailVerified: true
    }));
    if (!concurrentSignup) throw new Error("Expected the concurrent account fixture");
    expect(result.user.id).not.toBe(concurrentSignup.user.id);
    expect(result.user.passwordHash).toBeNull();
    expect(await auth.getCurrentSession(concurrentSignup.sessionToken)).toBeNull();
    expect((await storage.getAccountByProvider("google", "concurrent-provider"))?.userId).toBe(result.user.id);
  });

  it("does not let a late original session write attach to the proved mailbox owner's identity", async () => {
    const { auth, storage, emailProvider } = harness();
    const attacker = await auth.signUpEmailPassword({ email: "late-session@example.com", password: "attacker-password" });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let reached!: () => void;
    const entered = new Promise<void>((resolve) => { reached = resolve; });
    const originalCreate = storage.createSession.bind(storage);
    const interception = vi.spyOn(storage, "createSession").mockImplementationOnce(async (session) => {
      reached();
      await gate;
      return originalCreate(session);
    });
    const pending = auth.signInEmailPassword({ email: attacker.user.email!, password: "attacker-password" });
    await entered;
    await auth.requestMagicLink({ email: attacker.user.email! });
    const owner = requireCompleteSignIn(await auth.verifyMagicLink({ token: emailProvider.messages.at(-1)!.token }));
    release();
    const oldSession = requireCompleteSignIn(await pending);
    interception.mockRestore();
    expect(oldSession.session.userId).toBe(attacker.user.id);
    expect(oldSession.session.userId).not.toBe(owner.user.id);
    expect((await auth.getCurrentSession(oldSession.sessionToken))?.user.email).toBeNull();
  });

  it("takes original account proof only from authenticated HTTP credentials", async () => {
    const { auth, handler, emailProvider } = harness();
    const original = await auth.signUpEmailPassword({ email: "http-owner@example.com", password: "original-password" });
    await auth.requestEmailVerification({ email: original.user.email! });
    const token = emailProvider.messages.at(-1)!.token;
    const forgedBody = await handler(jsonRequest("/api/auth/email-verification/verify", { token, sessionToken: original.sessionToken }));
    expect(forgedBody.status).toBe(400);
    const response = await handler(jsonRequest("/api/auth/email-verification/verify", { token }, {
      cookie: `own_auth_session=${original.sessionToken}`
    }));
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ user: { id: original.user.id } });
  });

  it("clears a cached browser session when verification returns a different account", async () => {
    const client = createOwnAuthClient({
      fetch: (async (input) => {
        const url = String(input);
        const user = { id: url.endsWith("/email-verification/verify") ? "proved-owner" : "original-user" };
        return Response.json(url.endsWith("/email-verification/verify") ? { user } : {
          status: "complete", user, session: { id: "original-session" }
        });
      }) as typeof fetch
    });
    await client.signUpEmailPassword({ email: "cached@example.com", password: "original-password" });
    await client.verifyEmail({ token: "mailbox-proof" });
    expect(client.getSessionSnapshot().data).toBeNull();
  });
});
