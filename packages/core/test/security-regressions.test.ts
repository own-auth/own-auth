import { describe, expect, it, vi } from "vitest";
import {
  ConsoleEmailProvider,
  ConsoleSmsProvider,
  createOwnAuth,
  InMemoryAuthStorage,
  MemoryEmailProvider,
  MemorySmsProvider
} from "../src/index.js";
import { assertSingleSettledWinner } from "./conformance/conformance-assertions.js";

function createHarness(
  options: Parameters<typeof createOwnAuth>[0] = {}
) {
  const storage = options.storage ?? new InMemoryAuthStorage();
  const emailProvider = new MemoryEmailProvider();
  const smsProvider = new MemorySmsProvider();
  const auth = createOwnAuth({
    storage,
    emailProvider,
    smsProvider,
    exposeRawTokens: true,
    baseUrl: "http://localhost:3000",
    ...options
  });

  return { auth, storage, emailProvider, smsProvider };
}

async function createOwnerWithOrg() {
  const harness = createHarness();
  const owner = await harness.auth.signUpEmailPassword({
    email: "owner@example.com",
    password: "correct-horse"
  });
  const organisation = await harness.auth.createOrganisation({
    name: "Example Co",
    ownerUserId: owner.user.id
  });

  return { ...harness, owner, ...organisation };
}

describe("OwnAuth security regressions", () => {
  it("normalizes user identifiers and rejects duplicate email or phone accounts", async () => {
    const { auth } = createHarness();

    const user = await auth.createUser({
      email: "USER@Example.COM ",
      phone: "+1 (555) 123-4567",
      password: "correct-horse"
    });

    expect(user.email).toBe("user@example.com");
    expect(user.phone).toBe("+15551234567");

    await expect(auth.createUser({ email: "user@example.com" })).rejects.toMatchObject({
      code: "email_already_exists"
    });
    await expect(auth.createUser({ phone: "+15551234567" })).rejects.toMatchObject({
      code: "phone_already_exists"
    });
  });

  it("rejects weak passwords before creating users", async () => {
    const { auth } = createHarness();

    await expect(
      auth.signUpEmailPassword({ email: "weak@example.com", password: "short" })
    ).rejects.toMatchObject({ code: "weak_password" });
    await expect(auth.storage.getUserByEmail("weak@example.com")).resolves.toBeNull();
  });

  it("blocks disabled users from signing in and invalidates their current sessions", async () => {
    const { auth, storage } = createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "disabled@example.com",
      password: "correct-horse"
    });

    await storage.updateUser(signup.user.id, {
      disabledAt: new Date(),
      updatedAt: new Date()
    });

    await expect(
      auth.signInEmailPassword({
        email: "disabled@example.com",
        password: "correct-horse"
      })
    ).rejects.toMatchObject({ code: "disabled_user" });
    await expect(auth.getCurrentSession(signup.sessionToken)).resolves.toBeNull();
  });

  it("rate limits repeated password sign-in failures", async () => {
    const { auth } = createHarness();
    await auth.signUpEmailPassword({
      email: "ratelimit@example.com",
      password: "correct-horse"
    });

    for (let attempt = 0; attempt < 10; attempt += 1) {
      await expect(
        auth.signInEmailPassword({
          email: "ratelimit@example.com",
          password: "wrong-password"
        })
      ).rejects.toMatchObject({ code: "invalid_credentials" });
    }

    await expect(
      auth.signInEmailPassword({
        email: "ratelimit@example.com",
        password: "correct-horse"
      })
    ).rejects.toMatchObject({ code: "rate_limited" });
  }, 20_000);

  it("rejects password changes with the wrong current password", async () => {
    const { auth } = createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "wrong-current@example.com",
      password: "correct-horse"
    });

    await expect(
      auth.changePassword({
        sessionToken: signup.sessionToken,
        currentPassword: "wrong-password",
        newPassword: "new-password"
      })
    ).rejects.toMatchObject({ code: "invalid_credentials" });

    const signin = await auth.signInEmailPassword({
      email: "wrong-current@example.com",
      password: "correct-horse"
    });
    expect(signin.user.id).toBe(signup.user.id);
  });

  it("rejects weak new passwords before updating the user password", async () => {
    const { auth } = createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "weak-change@example.com",
      password: "correct-horse"
    });

    await expect(
      auth.changePassword({
        sessionToken: signup.sessionToken,
        currentPassword: "correct-horse",
        newPassword: "short"
      })
    ).rejects.toMatchObject({ code: "weak_password" });

    const signin = await auth.signInEmailPassword({
      email: "weak-change@example.com",
      password: "correct-horse"
    });
    expect(signin.user.id).toBe(signup.user.id);
  });

  it("rejects new external provider links with unverified emails", async () => {
    const { auth } = createHarness();

    await expect(
      auth.signInWithVerifiedExternalIdentity({
        provider: "google",
        providerAccountId: "google-unverified-email",
        email: "unverified@example.com",
        emailVerified: false
      })
    ).rejects.toMatchObject({ code: "validation_error" });
    await expect(auth.storage.getUserByEmail("unverified@example.com")).resolves.toBeNull();
  });

  it("rejects unsupported external providers", async () => {
    const { auth } = createHarness();

    await expect(
      auth.signInWithVerifiedExternalIdentity({
        provider: "facebook" as "google",
        providerAccountId: "facebook-user-1"
      })
    ).rejects.toMatchObject({ code: "validation_error" });
  });

  it("blocks disabled users from external provider sign-in", async () => {
    const { auth, storage } = createHarness();
    const signin = await auth.signInWithVerifiedExternalIdentity({
      provider: "google",
      providerAccountId: "google-disabled-user",
      email: "disabled-external@example.com",
      emailVerified: true
    });

    await storage.updateUser(signin.user.id, {
      disabledAt: new Date(),
      updatedAt: new Date()
    });

    await expect(
      auth.signInWithVerifiedExternalIdentity({
        provider: "google",
        providerAccountId: "google-disabled-user"
      })
    ).rejects.toMatchObject({ code: "disabled_user" });
  });

  it("rejects expired absolute and idle sessions", async () => {
    const absolute = createHarness({ session: { ttlMs: -1, idleTtlMs: 60_000 } });
    const expiredAbsolute = await absolute.auth.signUpEmailPassword({
      email: "absolute@example.com",
      password: "correct-horse"
    });

    await expect(absolute.auth.getCurrentSession(expiredAbsolute.sessionToken)).resolves.toBeNull();

    const idle = createHarness({ session: { ttlMs: 60_000, idleTtlMs: -1 } });
    const expiredIdle = await idle.auth.signUpEmailPassword({
      email: "idle@example.com",
      password: "correct-horse"
    });

    await expect(idle.auth.getCurrentSession(expiredIdle.sessionToken)).resolves.toBeNull();
  });

  it("revokes every active session for a user", async () => {
    const { auth } = createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "sessions@example.com",
      password: "correct-horse"
    });
    const signin = await auth.signInEmailPassword({
      email: "sessions@example.com",
      password: "correct-horse"
    });

    await expect(
      auth.revokeAllSessions({ actorUserId: signup.user.id })
    ).resolves.toBe(2);
    await expect(auth.getCurrentSession(signup.sessionToken)).resolves.toBeNull();
    await expect(auth.getCurrentSession(signin.sessionToken)).resolves.toBeNull();
  });

  it("does not expose raw delivery tokens unless explicitly configured", async () => {
    const emailProvider = new MemoryEmailProvider();
    const auth = createOwnAuth({
      emailProvider,
      smsProvider: new MemorySmsProvider(),
      exposeRawTokens: false
    });

    const result = await auth.requestMagicLink({ email: "hidden-token@example.com" });

    expect(result.token).toBeUndefined();
    expect(result.url).toBeUndefined();
    expect(emailProvider.messages.at(-1)?.token).toBeTruthy();
  });

  it("does not log raw tokens or OTP codes from console providers", async () => {
    const originalInfo = console.info;
    const logs: unknown[] = [];
    console.info = (...args: unknown[]) => {
      logs.push(args);
    };

    try {
      await new ConsoleEmailProvider().send({
        to: "user@example.com",
        type: "magic_link",
        token: "raw-email-token",
        url: "https://app.example.com/auth?token=raw-email-token",
        expiresAt: new Date("2026-01-01T00:00:00.000Z")
      });
      await new ConsoleSmsProvider().send({
        to: "+15550000000",
        purpose: "phone_login",
        code: "999999",
        expiresAt: new Date("2026-01-01T00:00:00.000Z")
      });
    } finally {
      console.info = originalInfo;
    }

    expect(JSON.stringify(logs)).not.toContain("raw-email-token");
    expect(JSON.stringify(logs)).not.toContain("999999");
  });

  it("prevents magic-link open redirects but allows relative redirects", async () => {
    const { auth, emailProvider } = createHarness({
      redirectAllowlist: ["http://localhost:3000"]
    });

    await expect(
      auth.requestMagicLink({
        email: "redirect@example.com",
        redirectUrl: "https://evil.example/callback"
      })
    ).rejects.toMatchObject({ code: "redirect_not_allowed" });

    const result = await auth.requestMagicLink({
      email: "redirect@example.com",
      redirectUrl: "/dashboard"
    });

    expect(result.url).toContain("redirect_url=%2Fdashboard");
    expect(emailProvider.messages).toHaveLength(1);
  });

  it.each([
    ["HTTPS URL", "https://app.example.com/auth/callback", "https://app.example.com"],
    ["universal link", "https://app.example.com/auth/magic", "https://app.example.com/auth"],
    ["localhost URL", "http://localhost:3000/auth/callback", "http://localhost:3000"],
    ["loopback URL", "http://127.0.0.1:3000/auth/callback", "http://127.0.0.1:3000"],
    ["custom app scheme", "myapp://auth/magic", "myapp://auth"]
  ])("allows an allowlisted %s redirect", async (_label, redirectUrl, allowedUrl) => {
    const { auth } = createHarness({ redirectAllowlist: [allowedUrl] });

    await expect(
      auth.requestMagicLink({
        email: "redirect-allowed@example.com",
        redirectUrl
      })
    ).resolves.toMatchObject({ sent: true });
  });

  it.each([
    ["non-local HTTP URL", "http://app.example.com/auth", "http://app.example.com"],
    ["protocol-relative URL", "//evil.example/auth", "https://app.example.com"],
    ["lookalike host", "https://app.example.com.evil.test/auth", "https://app.example.com"],
    ["different custom scheme", "evilapp://auth/magic", "myapp://auth"],
    ["different custom host", "myapp://evil/magic", "myapp://auth"],
    ["unsafe script scheme", "javascript://auth/magic", "javascript://auth"],
    ["unsupported FTP URL", "ftp://app.example.com/auth", "ftp://app.example.com"],
    ["path outside the allowlist", "https://app.example.com/admin", "https://app.example.com/auth"]
  ])("rejects a %s redirect", async (_label, redirectUrl, allowedUrl) => {
    const { auth } = createHarness({ redirectAllowlist: [allowedUrl] });

    await expect(
      auth.requestMagicLink({ email: "redirect-rejected@example.com", redirectUrl })
    ).rejects.toMatchObject({ code: "redirect_not_allowed" });
  });

  it("does not create or email unknown users when magic-link signup is disabled", async () => {
    const { auth, emailProvider } = createHarness({ allowMagicLinkSignup: false });

    const result = await auth.requestMagicLink({ email: "unknown@example.com" });

    expect(result).toEqual({ sent: true, expiresAt: null });
    expect(emailProvider.messages).toHaveLength(0);
    await expect(auth.storage.getUserByEmail("unknown@example.com")).resolves.toBeNull();
  });

  it("rejects expired magic-link tokens", async () => {
    const { auth, emailProvider } = createHarness({
      tokenTtlMs: { magic_link: -1 }
    });

    await auth.requestMagicLink({ email: "expired-magic@example.com" });

    await expect(
      auth.verifyMagicLink({ token: emailProvider.messages.at(-1)?.token ?? "" })
    ).rejects.toMatchObject({ code: "expired_token" });
  });

  it("returns generic email-verification responses for unknown users", async () => {
    const { auth, emailProvider } = createHarness();

    await expect(
      auth.requestEmailVerification({ email: "missing@example.com" })
    ).resolves.toEqual({ sent: true, expiresAt: null });
    expect(emailProvider.messages).toHaveLength(0);
  });

  it("verifies email with a one-time token", async () => {
    const { auth, emailProvider } = createHarness();
    await auth.signUpEmailPassword({
      email: "verify@example.com",
      password: "correct-horse"
    });
    await auth.requestEmailVerification({ email: "verify@example.com" });

    const token = emailProvider.messages.at(-1)?.token ?? "";
    const user = await auth.verifyEmail({ token });

    expect(user.emailVerifiedAt).toBeInstanceOf(Date);
    await expect(auth.verifyEmail({ token })).rejects.toMatchObject({
      code: "token_already_used"
    });
  });

  it("allows only one concurrent magic-link verification", async () => {
    const { auth, emailProvider } = createHarness();
    await auth.requestMagicLink({ email: "magic-race@example.com" });
    const token = emailProvider.messages.at(-1)?.token ?? "";

    assertSingleSettledWinner(
      await Promise.allSettled([
        auth.verifyMagicLink({ token }),
        auth.verifyMagicLink({ token })
      ]),
      "token_already_used"
    );
  });

  it("allows only one concurrent email verification", async () => {
    const { auth, emailProvider } = createHarness();
    await auth.signUpEmailPassword({
      email: "verification-race@example.com",
      password: "correct-horse"
    });
    await auth.requestEmailVerification({ email: "verification-race@example.com" });
    const token = emailProvider.messages.at(-1)?.token ?? "";

    assertSingleSettledWinner(
      await Promise.allSettled([
        auth.verifyEmail({ token }),
        auth.verifyEmail({ token })
      ]),
      "token_already_used"
    );
  });

  it("returns generic password-reset responses for unknown users", async () => {
    const { auth, emailProvider } = createHarness();

    await expect(
      auth.requestPasswordReset({ email: "missing-reset@example.com" })
    ).resolves.toEqual({ sent: true, expiresAt: null });
    expect(emailProvider.messages).toHaveLength(0);
  });

  it("rejects expired password reset tokens", async () => {
    const { auth, emailProvider } = createHarness({
      tokenTtlMs: { password_reset: -1 }
    });
    await auth.signUpEmailPassword({
      email: "expired-reset@example.com",
      password: "correct-horse"
    });
    await auth.requestPasswordReset({ email: "expired-reset@example.com" });

    await expect(
      auth.resetPassword({
        token: emailProvider.messages.at(-1)?.token ?? "",
        newPassword: "new-password"
      })
    ).rejects.toMatchObject({ code: "expired_token" });
  });

  it("allows only one concurrent password reset", async () => {
    const { auth, emailProvider } = createHarness();
    await auth.signUpEmailPassword({
      email: "reset-race@example.com",
      password: "correct-horse"
    });
    await auth.requestPasswordReset({ email: "reset-race@example.com" });
    const token = emailProvider.messages.at(-1)?.token ?? "";

    assertSingleSettledWinner(
      await Promise.allSettled([
        auth.resetPassword({ token, newPassword: "new-password-one" }),
        auth.resetPassword({ token, newPassword: "new-password-two" })
      ]),
      "token_already_used"
    );
  });

  it("tracks SMS OTP attempts and blocks codes after the attempt limit", async () => {
    const { auth, smsProvider } = createHarness({ sms: { maxAttempts: 2 } });

    await auth.requestSmsOtp({ phone: "+15551230000" });
    const code = smsProvider.messages.at(-1)?.code ?? "";

    await expect(
      auth.verifySmsOtp({ phone: "+15551230000", code: "000000" })
    ).rejects.toMatchObject({ code: "invalid_otp" });
    await expect(
      auth.verifySmsOtp({ phone: "+15551230000", code: "111111" })
    ).rejects.toMatchObject({ code: "invalid_otp" });
    await expect(
      auth.verifySmsOtp({ phone: "+15551230000", code })
    ).rejects.toMatchObject({ code: "otp_attempts_exceeded" });
  });

  it("prevents SMS OTP reuse after a successful verification", async () => {
    const { auth, smsProvider } = createHarness();

    await auth.requestSmsOtp({ phone: "+15551230001" });
    const code = smsProvider.messages.at(-1)?.code ?? "";

    await auth.verifySmsOtp({ phone: "+15551230001", code });
    await expect(auth.verifySmsOtp({ phone: "+15551230001", code })).rejects.toMatchObject({
      code: "invalid_otp"
    });
  });

  it("allows only one concurrent SMS OTP verification", async () => {
    const { auth, smsProvider } = createHarness();
    const phone = "+15551230003";
    await auth.requestSmsOtp({ phone });
    const code = smsProvider.messages.at(-1)?.code ?? "";

    assertSingleSettledWinner(
      await Promise.allSettled([
        auth.verifySmsOtp({ phone, code }),
        auth.verifySmsOtp({ phone, code })
      ]),
      "invalid_otp"
    );
  });

  it("counts concurrent wrong SMS OTP attempts without dropping either hit", async () => {
    const { auth, smsProvider } = createHarness({ sms: { maxAttempts: 2 } });
    const phone = "+15551230004";
    await auth.requestSmsOtp({ phone });
    const validCode = smsProvider.messages.at(-1)?.code ?? "";
    const wrongCode = validCode === "000000" ? "111111" : "000000";

    const wrongAttempts = await Promise.allSettled([
      auth.verifySmsOtp({ phone, code: wrongCode }),
      auth.verifySmsOtp({ phone, code: wrongCode })
    ]);

    expect(wrongAttempts).toEqual([
      expect.objectContaining({ status: "rejected" }),
      expect.objectContaining({ status: "rejected" })
    ]);
    await expect(auth.verifySmsOtp({ phone, code: validCode })).rejects.toMatchObject({
      code: "otp_attempts_exceeded"
    });
  });

  it("verifies phone numbers without creating a login session for verification-only OTPs", async () => {
    const { auth, smsProvider } = createHarness();
    const user = await auth.createUser({ phone: "+15551230002" });

    await auth.requestSmsOtp({
      phone: "+15551230002",
      userId: user.id,
      purpose: "phone_verification"
    });
    const result = await auth.verifySmsOtp({
      phone: "+15551230002",
      code: smsProvider.messages.at(-1)?.code ?? "",
      purpose: "phone_verification"
    });

    expect(result.user.phoneVerifiedAt).toBeInstanceOf(Date);
    expect(result.session).toBeNull();
    expect(result.sessionToken).toBeNull();
  });

  it("rejects malformed, tampered, expired, and revoked API keys", async () => {
    const { auth, owner, organisation } = await createOwnerWithOrg();
    const created = await auth.createApiKey({
      name: "Worker",
      organisationId: organisation.id,
      actorUserId: owner.user.id,
      scopes: ["read users"],
      expiresAt: new Date(Date.now() + 60_000)
    });
    const tampered = `${created.rawKey.slice(0, -1)}x`;

    await expect(auth.verifyApiKey("not-a-key")).rejects.toMatchObject({
      code: "api_key_invalid"
    });
    await expect(auth.verifyApiKey(tampered)).rejects.toMatchObject({
      code: "api_key_invalid"
    });

    await auth.revokeApiKey({
      keyPrefix: created.apiKey.keyPrefix,
      actorUserId: owner.user.id
    });
    await expect(auth.verifyApiKey(created.rawKey)).rejects.toMatchObject({
      code: "api_key_revoked"
    });

    const expired = await auth.createApiKey({
      name: "Expired",
      organisationId: organisation.id,
      actorUserId: owner.user.id,
      expiresAt: new Date(Date.now() - 1)
    });
    await expect(auth.verifyApiKey(expired.rawKey)).rejects.toMatchObject({
      code: "api_key_expired"
    });
  });

  it("does not expose API key hashes through public methods", async () => {
    const { auth, owner, organisation } = await createOwnerWithOrg();
    const created = await auth.createApiKey({
      name: "Private hash",
      organisationId: organisation.id,
      actorUserId: owner.user.id
    });

    const [listed] = await auth.listApiKeys({
      organisationId: organisation.id,
      actorUserId: owner.user.id
    });
    const verified = await auth.verifyApiKey(created.rawKey);
    const revoked = await auth.revokeApiKey({
      keyPrefix: created.apiKey.keyPrefix,
      actorUserId: owner.user.id
    });
    const stored = await auth.storage.getApiKeyByPrefix(created.apiKey.keyPrefix);

    expect(created.apiKey).not.toHaveProperty("keyHash");
    expect(listed).not.toHaveProperty("keyHash");
    expect(verified.apiKey).not.toHaveProperty("keyHash");
    expect(revoked).not.toHaveProperty("keyHash");
    expect(stored?.keyHash).toBeTruthy();
  });

  it("supports wildcard API key scopes and records last-used time", async () => {
    const { auth, owner, organisation } = await createOwnerWithOrg();
    const created = await auth.createApiKey({
      name: "Wildcard",
      organisationId: organisation.id,
      actorUserId: owner.user.id,
      scopes: ["*"]
    });

    const verified = await auth.verifyApiKey(created.rawKey, [
      "read users",
      "manage organisation"
    ]);

    expect(verified.apiKey.lastUsedAt).toBeInstanceOf(Date);
    expect(verified.organisation?.id).toBe(organisation.id);
  });

  it.each(["missing", "disabled"] as const)(
    "rejects personal API keys when their user is %s without recording use",
    async (userState) => {
      const { auth, storage } = createHarness();
      const signup = await auth.signUpEmailPassword({
        email: `${userState}-api-key-user@example.com`,
        password: "correct-horse"
      });
      const created = await auth.createApiKey({
        name: "Personal key",
        actorUserId: signup.user.id
      });

      if (userState === "disabled") {
        await auth.disableUser({
          userId: signup.user.id,
          actorUserId: signup.user.id
        });
      } else {
        const getUserById = storage.getUserById.bind(storage);
        vi.spyOn(storage, "getUserById").mockImplementation(async (userId) =>
          userId === signup.user.id ? null : getUserById(userId));
      }
      const updateApiKey = vi.spyOn(storage, "updateApiKey");

      await expect(auth.verifyApiKey(created.rawKey)).rejects.toMatchObject({
        code: "api_key_revoked"
      });
      expect(updateApiKey).not.toHaveBeenCalled();
      await expect(storage.listAuditEvents({ apiKeyId: created.apiKey.id })).resolves.not.toEqual(
        expect.arrayContaining([expect.objectContaining({ eventType: "api_key.used" })])
      );
    }
  );

  it("keeps user-scoped resources bound to the acting user", async () => {
    const { auth } = createHarness();
    const first = await auth.signUpEmailPassword({
      email: "first-owner@example.com",
      password: "correct-horse"
    });
    const second = await auth.signUpEmailPassword({
      email: "second-owner@example.com",
      password: "correct-horse"
    });
    const firstOrganisation = await auth.createOrganisation({
      name: "First Organisation",
      ownerUserId: first.user.id
    });
    const secondOrganisation = await auth.createOrganisation({
      name: "Second Organisation",
      ownerUserId: second.user.id
    });
    const firstKey = await auth.createApiKey({
      name: "First user key",
      actorUserId: first.user.id
    });

    await expect(
      auth.listApiKeys({ actorUserId: first.user.id })
    ).resolves.toEqual([expect.objectContaining({ id: firstKey.apiKey.id })]);
    await expect(
      auth.listApiKeys({ actorUserId: second.user.id })
    ).resolves.toEqual([]);
    await expect(
      auth.revokeApiKey({
        keyPrefix: firstKey.apiKey.keyPrefix,
        actorUserId: second.user.id
      })
    ).rejects.toMatchObject({ code: "permission_denied" });
    await expect(
      auth.disableUser({
        userId: first.user.id,
        actorUserId: second.user.id
      })
    ).rejects.toMatchObject({ code: "permission_denied" });
    await expect(
      auth.listAuditEvents({
        actorUserId: second.user.id,
        userId: first.user.id
      })
    ).rejects.toMatchObject({ code: "permission_denied" });

    const secondSessions = await auth.listSessions({ actorUserId: second.user.id });
    expect(secondSessions.every((session) => session.userId === second.user.id)).toBe(true);
    await expect(
      auth.listOrganisations({ actorUserId: second.user.id })
    ).resolves.toEqual([expect.objectContaining({ id: secondOrganisation.organisation.id })]);
    await expect(
      auth.getOrganisation({
        organisationId: firstOrganisation.organisation.id,
        actorUserId: second.user.id
      })
    ).rejects.toMatchObject({ code: "organisation_not_found" });
  });

  it("creates unique organisation slugs", async () => {
    const { auth } = createHarness();
    const user = await auth.signUpEmailPassword({
      email: "slug-owner@example.com",
      password: "correct-horse"
    });

    const first = await auth.createOrganisation({
      name: "Example Co",
      ownerUserId: user.user.id
    });
    const second = await auth.createOrganisation({
      name: "Example Co",
      ownerUserId: user.user.id
    });

    expect(first.organisation.slug).toBe("example-co");
    expect(second.organisation.slug).toBe("example-co-2");
  });

  it("denies organisation actions for members without the required permission", async () => {
    const { auth, owner, organisation } = await createOwnerWithOrg();
    const memberUser = await auth.createUser({ email: "member@example.com" });
    const invite = await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: "member@example.com",
      role: "member"
    });
    await auth.acceptInvite({ token: invite.token ?? "", userId: memberUser.id });

    await expect(
      auth.createApiKey({
        name: "Member key",
        organisationId: organisation.id,
        actorUserId: memberUser.id
      })
    ).rejects.toMatchObject({ code: "permission_denied" });
    await expect(
      auth.updateOrganisation(organisation.id, {
        actorUserId: memberUser.id,
        name: "Renamed"
      })
    ).rejects.toMatchObject({ code: "permission_denied" });
    await expect(
      auth.inviteMember({
        organisationId: organisation.id,
        invitedByUserId: memberUser.id,
        email: "another-member@example.com"
      })
    ).rejects.toMatchObject({ code: "permission_denied" });
    await expect(
      auth.listInvitations({
        organisationId: organisation.id,
        actorUserId: memberUser.id
      })
    ).rejects.toMatchObject({ code: "permission_denied" });
    await expect(
      auth.listApiKeys({
        organisationId: organisation.id,
        actorUserId: memberUser.id
      })
    ).rejects.toMatchObject({ code: "permission_denied" });
    await expect(
      auth.listAuditEvents({
        organisationId: organisation.id,
        actorUserId: memberUser.id
      })
    ).rejects.toMatchObject({ code: "permission_denied" });
  });

  it("prevents demoting or removing the last owner", async () => {
    const { auth, owner, organisation } = await createOwnerWithOrg();

    await expect(
      auth.changeMemberRole({
        organisationId: organisation.id,
        userId: owner.user.id,
        actorUserId: owner.user.id,
        role: "admin"
      })
    ).rejects.toMatchObject({ code: "last_owner" });
    await expect(
      auth.removeMember({
        organisationId: organisation.id,
        userId: owner.user.id,
        actorUserId: owner.user.id
      })
    ).rejects.toMatchObject({ code: "last_owner" });
  });

  it("transfers ownership when the primary owner is removed", async () => {
    const { auth, owner, organisation } = await createOwnerWithOrg();
    const replacementUser = await auth.createUser({
      email: "replacement-owner@example.com"
    });
    const invite = await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: "replacement-owner@example.com",
      role: "member"
    });
    await auth.acceptInvite({ token: invite.token ?? "", userId: replacementUser.id });

    await auth.changeMemberRole({
      organisationId: organisation.id,
      userId: replacementUser.id,
      actorUserId: owner.user.id,
      role: "owner"
    });
    await auth.removeMember({
      organisationId: organisation.id,
      userId: owner.user.id,
      actorUserId: owner.user.id
    });

    await expect(
      auth.getOrganisation({
        organisationId: organisation.id,
        actorUserId: replacementUser.id
      })
    ).resolves.toMatchObject({ ownerUserId: replacementUser.id });
    await expect(
      auth.checkPermission(organisation.id, owner.user.id, "manage_organisation")
    ).resolves.toBe(false);
  });

  it("does not let an admin remove an owner", async () => {
    const { auth, owner, organisation } = await createOwnerWithOrg();
    const adminUser = await auth.createUser({ email: "admin-owner-check@example.com" });
    const invite = await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: "admin-owner-check@example.com",
      role: "admin"
    });
    await auth.acceptInvite({ token: invite.token ?? "", userId: adminUser.id });

    await expect(
      auth.removeMember({
        organisationId: organisation.id,
        userId: owner.user.id,
        actorUserId: adminUser.id
      })
    ).rejects.toMatchObject({ code: "permission_denied" });
  });

  it("allows only owners to issue owner invitations", async () => {
    const { auth, storage, owner, organisation } = await createOwnerWithOrg();
    const adminUser = await auth.createUser({ email: "owner-invite-admin@example.com" });
    const adminInvite = await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: adminUser.email ?? "",
      role: "admin"
    });
    await auth.acceptInvite({ token: adminInvite.token ?? "", userId: adminUser.id });
    const invitedOwnerEmail = "invited-owner@example.com";

    await expect(
      auth.inviteMember({
        organisationId: organisation.id,
        invitedByUserId: adminUser.id,
        email: invitedOwnerEmail,
        role: "owner"
      })
    ).rejects.toMatchObject({ code: "permission_denied" });
    await expect(
      storage.getPendingInvitationByOrganisationAndEmail(organisation.id, invitedOwnerEmail)
    ).resolves.toBeNull();

    await expect(
      auth.inviteMember({
        organisationId: organisation.id,
        invitedByUserId: owner.user.id,
        email: invitedOwnerEmail,
        role: "owner"
      })
    ).resolves.toMatchObject({ invitation: { role: "owner" } });
  });

  it("lets admins update organisation settings but not member roles", async () => {
    const { auth, owner, organisation } = await createOwnerWithOrg();
    const adminUser = await auth.createUser({ email: "role-admin@example.com" });
    const memberUser = await auth.createUser({ email: "role-member@example.com" });
    const adminInvite = await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: "role-admin@example.com",
      role: "admin"
    });
    await auth.acceptInvite({ token: adminInvite.token ?? "", userId: adminUser.id });
    const memberInvite = await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: "role-member@example.com",
      role: "member"
    });
    await auth.acceptInvite({ token: memberInvite.token ?? "", userId: memberUser.id });

    await expect(
      auth.updateOrganisation(organisation.id, {
        actorUserId: adminUser.id,
        name: "Admin Updated Co"
      })
    ).resolves.toMatchObject({ name: "Admin Updated Co" });

    await expect(
      auth.changeMemberRole({
        organisationId: organisation.id,
        userId: memberUser.id,
        actorUserId: adminUser.id,
        role: "admin"
      })
    ).rejects.toMatchObject({ code: "permission_denied" });
  });

  it("removes members and drops their permissions", async () => {
    const { auth, owner, organisation } = await createOwnerWithOrg();
    const adminUser = await auth.createUser({ email: "admin@example.com" });
    const invite = await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: "admin@example.com",
      role: "admin"
    });
    await auth.acceptInvite({ token: invite.token ?? "", userId: adminUser.id });

    await auth.removeMember({
      organisationId: organisation.id,
      userId: adminUser.id,
      actorUserId: owner.user.id
    });

    await expect(
      auth.checkPermission(organisation.id, adminUser.id, "manage_api_keys")
    ).resolves.toBe(false);
  });

  it("prevents invitation token reuse", async () => {
    const { auth, owner, organisation } = await createOwnerWithOrg();
    const invitedUser = await auth.createUser({ email: "invite-reuse@example.com" });
    const invite = await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: "invite-reuse@example.com"
    });

    await auth.acceptInvite({ token: invite.token ?? "", userId: invitedUser.id });
    await expect(
      auth.acceptInvite({ token: invite.token ?? "", userId: invitedUser.id })
    ).rejects.toMatchObject({ code: "token_already_used" });
  });

  it("allows only one concurrent invitation acceptance", async () => {
    const { auth, owner, organisation } = await createOwnerWithOrg();
    const invitedUser = await auth.createUser({ email: "invite-race@example.com" });
    const invite = await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: "invite-race@example.com"
    });
    const input = { token: invite.token ?? "", userId: invitedUser.id };

    assertSingleSettledWinner(
      await Promise.allSettled([
        auth.acceptInvite(input),
        auth.acceptInvite(input)
      ]),
      "token_already_used"
    );
  });

  it("does not consume an invitation when the wrong user tries to accept it", async () => {
    const { auth, owner, organisation } = await createOwnerWithOrg();
    const invitedUser = await auth.createUser({ email: "right-invite-user@example.com" });
    const wrongUser = await auth.createUser({ email: "wrong-invite-user@example.com" });
    const invite = await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: "right-invite-user@example.com"
    });

    await expect(
      auth.acceptInvite({ token: invite.token ?? "", userId: wrongUser.id })
    ).rejects.toMatchObject({ code: "permission_denied" });

    await expect(
      auth.acceptInvite({ token: invite.token ?? "", userId: invitedUser.id })
    ).resolves.toMatchObject({
      organisation: { id: organisation.id },
      member: { userId: invitedUser.id }
    });
  });

  it("rejects invitations for active organisation members", async () => {
    const { auth, owner, organisation } = await createOwnerWithOrg();

    await expect(
      auth.inviteMember({
        organisationId: organisation.id,
        invitedByUserId: owner.user.id,
        email: "owner@example.com"
      })
    ).rejects.toMatchObject({ code: "already_member" });
  });

  it("rejects duplicate pending invitations", async () => {
    const { auth, owner, organisation } = await createOwnerWithOrg();

    await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: "pending-invite@example.com"
    });

    await expect(
      auth.inviteMember({
        organisationId: organisation.id,
        invitedByUserId: owner.user.id,
        email: "PENDING-INVITE@example.com"
      })
    ).rejects.toMatchObject({ code: "invite_exists" });
  });

  it("rate limits invitation sends per organisation", async () => {
    const { auth, owner, organisation } = await createOwnerWithOrg();

    for (let index = 0; index < 10; index += 1) {
      await auth.inviteMember({
        organisationId: organisation.id,
        invitedByUserId: owner.user.id,
        email: `invite-${index}@example.com`
      });
    }

    await expect(
      auth.inviteMember({
        organisationId: organisation.id,
        invitedByUserId: owner.user.id,
        email: "invite-over-limit@example.com"
      })
    ).rejects.toMatchObject({ code: "rate_limited" });
  });

  it("marks expired pending invitations as expired", async () => {
    const { auth, storage, owner, organisation } = await createOwnerWithOrg();
    const invitedUser = await auth.createUser({ email: "expired-invite@example.com" });
    const invite = await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: "expired-invite@example.com"
    });

    await storage.updateInvitation(invite.invitation.id, {
      expiresAt: new Date(Date.now() - 1)
    });

    await expect(
      auth.acceptInvite({ token: invite.token ?? "", userId: invitedUser.id })
    ).rejects.toMatchObject({ code: "expired_token" });
    await expect(storage.getInvitationById(invite.invitation.id)).resolves.toMatchObject({
      status: "expired"
    });
  });

  it("filters audit events by user, organisation, and API key", async () => {
    const { auth, owner, organisation } = await createOwnerWithOrg();
    const apiKey = await auth.createApiKey({
      name: "Audited key",
      organisationId: organisation.id,
      actorUserId: owner.user.id
    });
    await auth.verifyApiKey(apiKey.rawKey);

    const userEvents = await auth.listAuditEvents({ actorUserId: owner.user.id });
    const orgEvents = await auth.listAuditEvents({
      organisationId: organisation.id,
      actorUserId: owner.user.id
    });
    const keyEvents = await auth.listAuditEvents({
      organisationId: organisation.id,
      apiKeyId: apiKey.apiKey.id,
      actorUserId: owner.user.id
    });

    expect(userEvents.map((event) => event.eventType)).toContain("user.signed_up");
    expect(orgEvents.map((event) => event.eventType)).toContain("organisation.created");
    expect(keyEvents.map((event) => event.eventType)).toEqual(
      expect.arrayContaining(["api_key.created", "api_key.used"])
    );
  });
});
