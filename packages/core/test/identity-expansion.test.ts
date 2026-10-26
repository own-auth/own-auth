import { describe, expect, it } from "vitest";
import {
  EncryptionKeyRing,
  InMemoryAuthStorage,
  MemoryEmailProvider,
  MemorySmsProvider,
  createOwnAuth,
  type Account,
  type OAuthProviderAdapter,
  type User
} from "../src/index.js";
import { deriveOAuthSecrets } from "../src/oauth-derivation.js";
import { createStoredWebhookEvent } from "../src/webhook-events.js";
import {
  createTotpCode,
  requireCompleteSignIn,
  requireMfaSignIn
} from "./identity-test-helpers.js";

const encryptionKey = new Uint8Array(32).fill(7);

function identityHarness() {
  const emailProvider = new MemoryEmailProvider();
  const smsProvider = new MemorySmsProvider();
  const auth = createOwnAuth({
    storage: new InMemoryAuthStorage(),
    emailProvider,
    smsProvider,
    exposeRawTokens: true,
    tokenPepper: "identity-expansion-test-pepper",
    encryption: { current: { id: "current", key: encryptionKey } },
    oauth: { adapters: [fakeGoogleProvider()] }
  });
  return { auth, emailProvider, smsProvider };
}

describe("identity expansion", () => {
  it("derives independent PKCE and nonce values without persisting either secret", async () => {
    const first = await deriveOAuthSecrets("state-value");
    const second = await deriveOAuthSecrets("state-value");

    expect(first).toEqual(second);
    expect(first.codeVerifier).not.toBe(first.nonce);
    expect(first.codeVerifier).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(first.nonce).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("decrypts previous-key records and authenticates record metadata", async () => {
    const previous = new EncryptionKeyRing({
      current: { id: "old", key: new Uint8Array(32).fill(1) }
    });
    const encrypted = await previous.encrypt("protected", "totp", {
      factorId: "factor-one",
      userId: "user-one"
    });
    const current = new EncryptionKeyRing({
      current: { id: "new", key: new Uint8Array(32).fill(2) },
      previous: [{ id: "old", key: new Uint8Array(32).fill(1) }]
    });

    await expect(current.decrypt(encrypted, "totp", {
      factorId: "factor-one",
      userId: "user-one"
    })).resolves.toEqual({ plaintext: "protected", needsRotation: true });
    await expect(current.decrypt(encrypted, "totp", {
      factorId: "factor-two",
      userId: "user-one"
    })).rejects.toMatchObject({ code: "encrypted_data_invalid" });

    const refreshCredential = await previous.encrypt("refresh-token", "oauth-refresh", {
      accountId: "account-one",
      provider: "google"
    });
    await expect(current.decrypt(refreshCredential, "oauth-refresh", {
      accountId: "account-one",
      provider: "google"
    })).resolves.toEqual({ plaintext: "refresh-token", needsRotation: true });
    await expect(current.decrypt(refreshCredential, "totp", {
      accountId: "account-one",
      provider: "google"
    })).rejects.toMatchObject({ code: "encrypted_data_invalid" });
  });

  it("fails closed when an encrypted record references an unavailable key", async () => {
    const encryption = new EncryptionKeyRing({
      current: { id: "current", key: encryptionKey }
    });

    await expect(encryption.decrypt({
      ciphertext: "unused",
      nonce: "unused",
      encryptionKeyId: "missing"
    }, "totp", {
      factorId: "factor-one",
      userId: "user-one"
    })).rejects.toMatchObject({ code: "encryption_key_unavailable" });
  });

  it("validates encryption key sizes and identifiers at startup", () => {
    expect(() => new EncryptionKeyRing({
      current: { id: " ", key: encryptionKey }
    })).toThrow("Encryption key IDs must be non-empty");
    expect(() => new EncryptionKeyRing({
      current: { id: "current", key: new Uint8Array(31) }
    })).toThrow("Encryption keys must contain exactly 32 bytes");
    expect(() => new EncryptionKeyRing({
      current: { id: "current", key: encryptionKey },
      previous: [{ id: "current", key: encryptionKey }]
    })).toThrow("Duplicate encryption key ID");
  });

  it("requires encryption before enabling provider offline access", () => {
    expect(() => createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "offline-access-configuration",
      oauth: { adapters: [refreshableGoogleProvider(() => undefined)] }
    })).toThrow("OAuth offline access requires encryption configuration");
  });

  it("rejects invalid MFA configuration before handling authentication", () => {
    expect(() => createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "invalid-mfa-config",
      mfa: { maxAttempts: 0 }
    })).toThrow("mfa.maxAttempts must be a positive integer");
  });

  it("allows only one pending TOTP enrollment to become active", async () => {
    const { auth } = identityHarness();
    const signup = requireCompleteSignIn(await auth.signUpEmailPassword({
      email: "totp-enrollment-race@example.com",
      password: "correct-horse"
    }));
    const [first, second] = await Promise.all([
      auth.beginTotpEnrollment({ sessionToken: signup.sessionToken }),
      auth.beginTotpEnrollment({ sessionToken: signup.sessionToken })
    ]);

    const results = await Promise.allSettled([
      auth.confirmTotpEnrollment({
        sessionToken: signup.sessionToken,
        factorId: first.factorId,
        code: createTotpCode(first.secret)
      }),
      auth.confirmTotpEnrollment({
        sessionToken: signup.sessionToken,
        factorId: second.factorId,
        code: createTotpCode(second.secret)
      })
    ]);

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toEqual([
      expect.objectContaining({
        reason: expect.objectContaining({ code: "mfa_code_invalid" })
      })
    ]);
  });

  it("keeps every first-factor flow sessionless until MFA succeeds", async () => {
    const { auth, emailProvider, smsProvider } = identityHarness();
    const signup = requireCompleteSignIn(await auth.signUpEmailPassword({
      email: "mfa@example.com",
      password: "correct-horse"
    }));
    const phone = "+14155550123";
    await auth.requestSmsOtp({
      phone,
      purpose: "phone_verification",
      userId: signup.user.id
    });
    await auth.verifySmsOtp({
      phone,
      purpose: "phone_verification",
      code: smsProvider.messages.at(-1)?.code ?? ""
    });
    await auth.linkOAuthProvider({
      actorUserId: signup.user.id,
      provider: "google",
      providerAccountId: "google-mfa-user",
      email: signup.user.email ?? undefined,
      emailVerified: true
    });
    const recoveryCodes = await enableTotp(auth, signup.sessionToken);
    expect(recoveryCodes).toHaveLength(10);
    expect(new Set(recoveryCodes).size).toBe(10);
    expect(recoveryCodes.every((code) => /^[A-HJ-NP-Z2-9]{6}-[A-HJ-NP-Z2-9]{6}$/.test(code)))
      .toBe(true);
    await auth.signOut(signup.sessionToken);
    const sessionsBefore = await auth.storage.listSessionsByUserId(signup.user.id);

    const password = await auth.signInEmailPassword({
      email: "mfa@example.com",
      password: "correct-horse"
    });
    expectMfa(password);

    await auth.requestMagicLink({ email: "mfa@example.com" });
    const magicToken = emailProvider.messages.at(-1)?.token ?? "";
    expectMfa(await auth.verifyMagicLink({
      token: magicToken
    }));

    await auth.requestSmsOtp({ phone });
    const smsCode = smsProvider.messages.at(-1)?.code ?? "";
    expectMfa(await auth.verifySmsOtp({
      phone,
      code: smsCode
    }));

    expectMfa(await auth.signInWithVerifiedExternalIdentity({
      provider: "google",
      providerAccountId: "google-mfa-user"
    }));

    const authorization = await auth.createOAuthAuthorizationUrl({ provider: "google" });
    const state = new URL(authorization.url).searchParams.get("state") ?? "";
    expectMfa(await auth.completeOAuthSignIn({
      provider: "google",
      browserBindingToken: authorization.browserBindingToken,
      callbackParameters: new URLSearchParams({ state, code: "provider-code" })
    }));

    const oneTap = await auth.prepareGoogleOneTap();
    expectMfa(await auth.signInWithGoogleOneTap({
      credential: "verified-google-credential",
      nonce: oneTap.nonce
    }));

    await expect(auth.storage.listSessionsByUserId(signup.user.id)).resolves.toHaveLength(
      sessionsBefore.length
    );

    const completed = await auth.completeMfaWithRecoveryCode({
      challengeToken: requireMfaSignIn(password).challengeToken,
      code: recoveryCodes[0] ?? ""
    });
    expect(completed.session.assuranceLevel).toBe("aal2");
    expect(completed.session.authenticationMethods).toEqual(["password", "recovery_code"]);
    const auditEvents = await auth.storage.listAuditEvents();
    const recoveryCodeEvent = auditEvents.find(
      (event) => event.eventType === "mfa.recovery_code_used"
    );
    expect(recoveryCodeEvent?.metadata).toEqual({ method: "recovery_code" });
    const storedWebhookEvent = recoveryCodeEvent
      ? createStoredWebhookEvent(recoveryCodeEvent)
      : null;
    expect(JSON.parse(storedWebhookEvent?.payload ?? "{}")).toMatchObject({
      type: "mfa.recovery_code_used",
      data: { details: { method: "recovery_code" } }
    });
    const auditJson = JSON.stringify(auditEvents);
    for (const secret of [magicToken, smsCode, state, oneTap.nonce, recoveryCodes[0] ?? ""]) {
      expect(auditJson).not.toContain(secret);
    }
  });

  it("invalidates recovery codes when TOTP is disabled", async () => {
    const { auth } = identityHarness();
    const signup = requireCompleteSignIn(await auth.signUpEmailPassword({
      email: "disable-totp@example.com",
      password: "correct-horse"
    }));
    const enrollment = await auth.beginTotpEnrollment({
      sessionToken: signup.sessionToken
    });
    const code = createTotpCode(enrollment.secret);
    const recoveryCodes = (await auth.confirmTotpEnrollment({
      sessionToken: signup.sessionToken,
      factorId: enrollment.factorId,
      code
    })).recoveryCodes;
    const pending = requireMfaSignIn(await auth.signInEmailPassword({
      email: "disable-totp@example.com",
      password: "correct-horse"
    }));

    await auth.disableTotp({
      sessionToken: signup.sessionToken,
      code: createTotpCode(enrollment.secret, Date.now() + 30_000)
    });

    await expect(auth.completeMfaWithRecoveryCode({
      challengeToken: pending.challengeToken,
      code: recoveryCodes[0] ?? ""
    })).rejects.toMatchObject({ code: "mfa_code_invalid" });
  });

  it("requires deliberate linking when a verified provider email already exists", async () => {
    const storage = new InMemoryAuthStorage();
    const auth = createOwnAuth({ storage, tokenPepper: "explicit-linking" });
    const signup = requireCompleteSignIn(await auth.signUpEmailPassword({
      email: "linked@example.com",
      password: "correct-horse"
    }));

    await expect(auth.signInWithVerifiedExternalIdentity({
      provider: "google",
      providerAccountId: "google-explicit-link",
      email: "linked@example.com",
      emailVerified: true
    })).rejects.toMatchObject({ code: "account_linking_required" });

    await auth.linkOAuthProvider({
      actorUserId: signup.user.id,
      provider: "google",
      providerAccountId: "google-explicit-link",
      email: "linked@example.com",
      emailVerified: true
    });
    await expect(auth.signInWithVerifiedExternalIdentity({
      provider: "google",
      providerAccountId: "google-explicit-link"
    })).resolves.toMatchObject({ status: "complete", user: { id: signup.user.id } });
  });

  it("applies account-linking policy when verified-email creation loses a race", async () => {
    const explicit = createOwnAuth({
      storage: new EmailCreationRaceStorage(),
      tokenPepper: "explicit-race"
    });
    await expect(explicit.signInWithVerifiedExternalIdentity({
      provider: "google",
      providerAccountId: "google-race-explicit",
      email: "race@example.com",
      emailVerified: true
    })).rejects.toMatchObject({ code: "account_linking_required" });

    const automatic = createOwnAuth({
      storage: new EmailCreationRaceStorage(),
      tokenPepper: "automatic-race",
      oauth: { accountLinking: "verified_email" }
    });
    await expect(automatic.signInWithVerifiedExternalIdentity({
      provider: "google",
      providerAccountId: "google-race-automatic",
      email: "race@example.com",
      emailVerified: true
    })).resolves.toMatchObject({
      status: "complete",
      user: { id: "usr_race_winner" }
    });
  });

  it("stores refresh credentials encrypted and refreshes them only on the server", async () => {
    let revokedToken: string | null = null;
    const provider = refreshableGoogleProvider((token) => {
      revokedToken = token;
    });
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "refresh-credential",
      encryption: { current: { id: "current", key: encryptionKey } },
      oauth: { adapters: [provider] }
    });
    const authorization = await auth.createOAuthAuthorizationUrl({ provider: "google" });
    const state = new URL(authorization.url).searchParams.get("state") ?? "";
    const signedIn = await auth.completeOAuthSignIn({
      provider: "google",
      browserBindingToken: authorization.browserBindingToken,
      callbackParameters: new URLSearchParams({ state, code: "provider-code" })
    });
    if (signedIn.status !== "complete") throw new Error("Expected completed OAuth sign-in");
    const account = (await auth.storage.listAccountsByUserId(signedIn.user.id))[0];
    const stored = await auth.storage.getOAuthCredentialByAccountId(account?.id ?? "");

    expect(stored?.ciphertext).not.toContain("refresh-one");
    await expect(auth.getExternalAccessToken({
      actorUserId: signedIn.user.id,
      provider: "google"
    })).resolves.toEqual({ accessToken: "access-two", scopes: ["calendar.read"] });

    await auth.revokeExternalProviderAccess({
      actorUserId: signedIn.user.id,
      provider: "google"
    });
    expect(revokedToken).toBe("refresh-two");
    await expect(
      auth.storage.getOAuthCredentialByAccountId(account?.id ?? "")
    ).resolves.toBeNull();
  });

  it("removes stored refresh credentials when the memory adapter unlinks an account", async () => {
    const storage = new InMemoryAuthStorage();
    const auth = createOwnAuth({ storage, tokenPepper: "memory-unlink" });
    const user = await auth.createUser({ email: "unlink@example.com" });
    const account = await storage.createAccount({
      id: "acct_memory_unlink",
      userId: user.id,
      provider: "google",
      providerAccountId: "google-memory-unlink",
      providerEmail: user.email,
      providerPhone: null,
      createdAt: new Date(),
      updatedAt: new Date()
    });
    await storage.upsertOAuthCredential({
      id: "oac_memory_unlink",
      accountId: account.id,
      provider: "google",
      ciphertext: "ciphertext",
      nonce: "nonce",
      encryptionKeyId: "current",
      scopes: [],
      createdAt: new Date(),
      updatedAt: new Date(),
      rotatedAt: null
    });

    await storage.deleteAccount(account.id);

    await expect(storage.getOAuthCredentialByAccountId(account.id)).resolves.toBeNull();
  });

});

async function enableTotp(
  auth: ReturnType<typeof createOwnAuth>,
  sessionToken: string
): Promise<string[]> {
  const enrollment = await auth.beginTotpEnrollment({ sessionToken });
  const code = createTotpCode(enrollment.secret);
  return (await auth.confirmTotpEnrollment({
    sessionToken,
    factorId: enrollment.factorId,
    code
  })).recoveryCodes;
}

function expectMfa(result: { status: string }): void {
  expect(result.status).toBe("mfa_required");
}

function fakeGoogleProvider(): OAuthProviderAdapter {
  const identity = {
    provider: "google" as const,
    providerAccountId: "google-mfa-user",
    email: "mfa@example.com",
    emailVerified: true,
    name: null,
    imageUrl: null
  };
  const provider: OAuthProviderAdapter = {
    provider: "google",
    redirectUri: "https://api.example.com/api/auth/oauth/google/callback",
    offlineAccess: false,
    async createAuthorizationUrl(input) {
      const url = new URL("https://accounts.example.test/authorize");
      url.searchParams.set("state", input.state);
      return url;
    },
    async exchangeCode() {
      return { identity, refreshToken: null, scopes: [] };
    },
    async verifyCredential() {
      if (this !== provider) throw new Error("OAuth provider receiver was not preserved");
      return identity;
    }
  };
  return provider;
}

function refreshableGoogleProvider(onRevoke: (token: string) => void): OAuthProviderAdapter {
  const provider: OAuthProviderAdapter = {
    provider: "google",
    redirectUri: "https://api.example.com/api/auth/oauth/google/callback",
    offlineAccess: true,
    async createAuthorizationUrl(input) {
      const url = new URL("https://accounts.example.test/authorize");
      url.searchParams.set("state", input.state);
      return url;
    },
    async exchangeCode() {
      return {
        identity: {
          provider: "google",
          providerAccountId: "offline-user",
          email: "offline@example.com",
          emailVerified: true,
          name: null,
          imageUrl: null
        },
        refreshToken: "refresh-one",
        scopes: ["profile"]
      };
    },
    async refresh() {
      if (this !== provider) throw new Error("OAuth provider receiver was not preserved");
      return {
        accessToken: "access-two",
        refreshToken: "refresh-two",
        scopes: ["calendar.read"]
      };
    },
    async revoke(token) {
      if (this !== provider) throw new Error("OAuth provider receiver was not preserved");
      onRevoke(token);
    }
  };
  return provider;
}

class EmailCreationRaceStorage extends InMemoryAuthStorage {
  private hideWinner = true;

  override async getUserByEmail(email: string): Promise<User | null> {
    if (this.hideWinner) {
      this.hideWinner = false;
      return null;
    }
    return super.getUserByEmail(email);
  }

  override async createUserAndAccount(user: User, _account: Account): Promise<Account> {
    await super.createUser({ ...user, id: "usr_race_winner" });
    throw new Error("simulated email uniqueness race");
  }
}
