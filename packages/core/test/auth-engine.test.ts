import { describe, expect, it } from "vitest";
import {
  createOwnAuth,
  InMemoryAuthStorage,
  MemoryEmailProvider,
  MemorySmsProvider
} from "../src/index.js";
import { PostgresAuthStorage, PostgresRateLimitStore } from "../src/postgres/index.js";
import { legacyScryptHash } from "./password-hash-fixtures.js";

function createTestAuth() {
  const emailProvider = new MemoryEmailProvider();
  const smsProvider = new MemorySmsProvider();
  const auth = createOwnAuth({
    emailProvider,
    smsProvider,
    exposeRawTokens: true,
    baseUrl: "http://localhost:3000"
  });

  return { auth, emailProvider, smsProvider };
}

describe("OwnAuth core", () => {
  it("signs up, signs in, validates, and revokes database-backed sessions", async () => {
    const { auth } = createTestAuth();

    const signup = await auth.signUpEmailPassword({
      email: "Tina@Example.com",
      password: "correct-horse"
    });

    expect(signup.user.email).toBe("tina@example.com");
    expect(signup.session.tokenHash).not.toContain(signup.sessionToken);

    const current = await auth.getCurrentSession(signup.sessionToken);
    expect(current?.user.id).toBe(signup.user.id);

    const signin = await auth.signInEmailPassword({
      email: "tina@example.com",
      password: "correct-horse"
    });
    expect(signin.session.tokenHash).not.toContain(signin.sessionToken);

    await auth.signOut(signup.sessionToken);
    await expect(auth.getCurrentSession(signup.sessionToken)).resolves.toBeNull();
  });

  it("upgrades a legacy scrypt password hash after a successful sign in", async () => {
    const { auth } = createTestAuth();
    const signup = await auth.signUpEmailPassword({
      email: "legacy@example.com",
      password: "old-password"
    });
    const legacyHash = legacyScryptHash("old-password");

    await auth.storage.updateUser(signup.user.id, {
      passwordHash: legacyHash,
      updatedAt: new Date()
    });

    await auth.signInEmailPassword({
      email: "legacy@example.com",
      password: "old-password"
    });

    const migratedUser = await auth.storage.getUserById(signup.user.id);
    expect(migratedUser?.passwordHash).toMatch(/^\$argon2id\$/);
    expect(migratedUser?.passwordHash).not.toBe(legacyHash);
  });

  it("keeps a legacy scrypt hash unchanged after a failed sign in", async () => {
    const { auth } = createTestAuth();
    const signup = await auth.signUpEmailPassword({
      email: "legacy-failed@example.com",
      password: "old-password"
    });
    const legacyHash = legacyScryptHash("old-password");

    await auth.storage.updateUser(signup.user.id, {
      passwordHash: legacyHash,
      updatedAt: new Date()
    });

    await expect(auth.signInEmailPassword({
      email: "legacy-failed@example.com",
      password: "wrong-password"
    })).rejects.toMatchObject({ code: "invalid_credentials" });

    const unchangedUser = await auth.storage.getUserById(signup.user.id);
    expect(unchangedUser?.passwordHash).toBe(legacyHash);
  });

  it("requires DATABASE_URL outside tests when no storage adapter is provided", () => {
    const previousNodeEnv = process.env.NODE_ENV;
    const previousDatabaseUrl = process.env.DATABASE_URL;

    try {
      process.env.NODE_ENV = "development";
      delete process.env.DATABASE_URL;

      expect(() => createOwnAuth()).toThrow("DATABASE_URL is required");
    } finally {
      process.env.NODE_ENV = previousNodeEnv;
      if (previousDatabaseUrl === undefined) {
        delete process.env.DATABASE_URL;
      } else {
        process.env.DATABASE_URL = previousDatabaseUrl;
      }
    }
  });

  it("requires OWN_AUTH_TOKEN_PEPPER in production", () => {
    const previousNodeEnv = process.env.NODE_ENV;
    const previousDatabaseUrl = process.env.DATABASE_URL;
    const previousTokenPepper = process.env.OWN_AUTH_TOKEN_PEPPER;

    try {
      process.env.NODE_ENV = "production";
      process.env.DATABASE_URL = "postgres://user:pass@localhost:5432/own_auth";
      delete process.env.OWN_AUTH_TOKEN_PEPPER;

      expect(() => createOwnAuth()).toThrow("OWN_AUTH_TOKEN_PEPPER is required in production.");
    } finally {
      process.env.NODE_ENV = previousNodeEnv;
      if (previousDatabaseUrl === undefined) {
        delete process.env.DATABASE_URL;
      } else {
        process.env.DATABASE_URL = previousDatabaseUrl;
      }
      if (previousTokenPepper === undefined) {
        delete process.env.OWN_AUTH_TOKEN_PEPPER;
      } else {
        process.env.OWN_AUTH_TOKEN_PEPPER = previousTokenPepper;
      }
    }
  });

  it("uses Postgres storage and rate limits from DATABASE_URL outside tests", () => {
    const previousNodeEnv = process.env.NODE_ENV;
    const previousDatabaseUrl = process.env.DATABASE_URL;

    try {
      process.env.NODE_ENV = "development";
      process.env.DATABASE_URL = "postgres://user:pass@localhost:5432/own_auth";

      const auth = createOwnAuth();

      expect(auth.storage).toBeInstanceOf(PostgresAuthStorage);
      expect(auth.rateLimitStore).toBeInstanceOf(PostgresRateLimitStore);
    } finally {
      process.env.NODE_ENV = previousNodeEnv;
      if (previousDatabaseUrl === undefined) {
        delete process.env.DATABASE_URL;
      } else {
        process.env.DATABASE_URL = previousDatabaseUrl;
      }
    }
  });

  it("allows explicit in-memory storage for tests", () => {
    const auth = createOwnAuth({ storage: new InMemoryAuthStorage() });

    expect(auth.storage).toBeInstanceOf(InMemoryAuthStorage);
  });

  it("uses one-time hashed magic link tokens", async () => {
    const { auth, emailProvider } = createTestAuth();

    await auth.requestMagicLink({ email: "new@example.com" });
    const message = emailProvider.messages.at(-1);

    expect(message?.token).toBeTruthy();

    const verified = await auth.verifyMagicLink({ token: message?.token ?? "" });
    expect(verified.user.email).toBe("new@example.com");
    expect(verified.user.emailVerifiedAt).toBeInstanceOf(Date);

    await expect(auth.verifyMagicLink({ token: message?.token ?? "" })).rejects.toMatchObject({
      code: "token_already_used"
    });
  });

  it("resets passwords with consumable tokens and revokes existing sessions", async () => {
    const { auth, emailProvider } = createTestAuth();
    const signup = await auth.signUpEmailPassword({
      email: "reset@example.com",
      password: "old-password"
    });

    await auth.requestPasswordReset({ email: "reset@example.com" });
    const resetMessage = emailProvider.messages.at(-1);
    await auth.resetPassword({
      token: resetMessage?.token ?? "",
      newPassword: "new-password"
    });

    await expect(auth.getCurrentSession(signup.sessionToken)).resolves.toBeNull();
    await expect(
      auth.signInEmailPassword({ email: "reset@example.com", password: "old-password" })
    ).rejects.toMatchObject({ code: "invalid_credentials" });

    const signin = await auth.signInEmailPassword({
      email: "reset@example.com",
      password: "new-password"
    });
    expect(signin.user.id).toBe(signup.user.id);
  });

  it("changes passwords with the current password and revokes other sessions", async () => {
    const { auth } = createTestAuth();
    const signup = await auth.signUpEmailPassword({
      email: "change@example.com",
      password: "old-password"
    });
    const otherSession = await auth.signInEmailPassword({
      email: "change@example.com",
      password: "old-password"
    });

    const changedUser = await auth.changePassword({
      sessionToken: signup.sessionToken,
      currentPassword: "old-password",
      newPassword: "new-password"
    });

    expect(changedUser.id).toBe(signup.user.id);
    const currentSession = await auth.getCurrentSession(signup.sessionToken);
    expect(currentSession?.user.id).toBe(signup.user.id);
    await expect(auth.getCurrentSession(otherSession.sessionToken)).resolves.toBeNull();
    await expect(
      auth.signInEmailPassword({ email: "change@example.com", password: "old-password" })
    ).rejects.toMatchObject({ code: "invalid_credentials" });

    const signin = await auth.signInEmailPassword({
      email: "change@example.com",
      password: "new-password"
    });
    expect(signin.user.id).toBe(signup.user.id);
  });

  it("signs in with a verified external provider identity", async () => {
    const { auth } = createTestAuth();

    const firstSignin = await auth.signInWithExternalProvider({
      provider: "google",
      providerAccountId: "google-user-1",
      email: "External@Example.com",
      emailVerified: true,
      name: "External User"
    });
    const secondSignin = await auth.signInWithExternalProvider({
      provider: "google",
      providerAccountId: "google-user-1"
    });

    expect(firstSignin.user.email).toBe("external@example.com");
    expect(firstSignin.user.emailVerifiedAt).toBeInstanceOf(Date);
    expect(secondSignin.user.id).toBe(firstSignin.user.id);
    await expect(auth.getCurrentSession(secondSignin.sessionToken)).resolves.toMatchObject({
      user: { id: firstSignin.user.id }
    });
  });

  it("links a verified external provider identity to an existing user email", async () => {
    const { auth } = createTestAuth();
    const signup = await auth.signUpEmailPassword({
      email: "linked@example.com",
      password: "correct-horse"
    });

    const signin = await auth.signInWithExternalProvider({
      provider: "apple",
      providerAccountId: "apple-user-1",
      email: "LINKED@example.com",
      emailVerified: true
    });

    expect(signin.user.id).toBe(signup.user.id);
    const account = await auth.storage.getAccountByProvider("apple", "apple-user-1");
    expect(account).toMatchObject({
      userId: signup.user.id,
      providerEmail: "linked@example.com"
    });
  });

  it("supports phone login through hashed SMS OTP codes", async () => {
    const { auth, smsProvider } = createTestAuth();

    await auth.requestSmsOtp({ phone: "+1 (555) 123-4567" });
    const message = smsProvider.messages.at(-1);
    const verified = await auth.verifySmsOtp({
      phone: "+15551234567",
      code: message?.code ?? ""
    });

    expect(verified.user.phone).toBe("+15551234567");
    expect(verified.user.phoneVerifiedAt).toBeInstanceOf(Date);
    expect(verified.sessionToken).toBeTruthy();
  });

  it("creates, verifies, scopes, and revokes API keys", async () => {
    const { auth } = createTestAuth();
    const owner = await auth.signUpEmailPassword({
      email: "owner@example.com",
      password: "correct-horse"
    });
    const { organisation } = await auth.createOrganisation({
      name: "Acme",
      ownerUserId: owner.user.id
    });
    const created = await auth.createApiKey({
      name: "CI",
      organisationId: organisation.id,
      actorUserId: owner.user.id,
      scopes: ["read users"]
    });

    expect(created.apiKey).not.toHaveProperty("keyHash");

    const verified = await auth.verifyApiKey(created.rawKey, ["read users"]);
    expect(verified.organisation?.id).toBe(organisation.id);

    await expect(auth.verifyApiKey(created.rawKey, ["manage users"])).rejects.toMatchObject({
      code: "insufficient_scope"
    });

    await auth.revokeApiKey({
      keyPrefix: created.apiKey.keyPrefix,
      actorUserId: owner.user.id
    });
    await expect(auth.verifyApiKey(created.rawKey)).rejects.toMatchObject({
      code: "api_key_revoked"
    });
  });

  it("disables and re-enables users", async () => {
    const { auth } = createTestAuth();
    const signup = await auth.signUpEmailPassword({
      email: "disable@example.com",
      password: "correct-horse"
    });

    const disabled = await auth.disableUser({
      userId: signup.user.id,
      actorUserId: signup.user.id
    });
    expect(disabled.disabledAt).toBeInstanceOf(Date);

    await expect(auth.getCurrentSession(signup.sessionToken)).resolves.toBeNull();
    await expect(
      auth.signInEmailPassword({ email: "disable@example.com", password: "correct-horse" })
    ).rejects.toMatchObject({ code: "disabled_user" });

    const enabled = await auth.enableUser({
      userId: signup.user.id,
      actorUserId: signup.user.id
    });
    expect(enabled.disabledAt).toBeNull();

    const signin = await auth.signInEmailPassword({
      email: "disable@example.com",
      password: "correct-horse"
    });
    expect(signin.user.id).toBe(signup.user.id);
  });

  it("revokes pending invitations", async () => {
    const { auth } = createTestAuth();
    const owner = await auth.signUpEmailPassword({
      email: "owner@example.com",
      password: "correct-horse"
    });
    const { organisation } = await auth.createOrganisation({
      name: "Revoke Org",
      ownerUserId: owner.user.id
    });
    const invitedUser = await auth.createUser({ email: "revokeme@example.com" });

    const invite = await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: "revokeme@example.com",
      role: "member"
    });

    const revoked = await auth.revokeInvitation({
      invitationId: invite.invitation.id,
      actorUserId: owner.user.id
    });
    expect(revoked.status).toBe("revoked");
    expect(revoked.revokedAt).toBeInstanceOf(Date);

    await expect(
      auth.acceptInvite({ token: invite.token ?? "", userId: invitedUser.id })
    ).rejects.toMatchObject({ code: "token_already_used" });
  });

  it("lists sessions, API keys, organisations, and invitations", async () => {
    const { auth } = createTestAuth();
    const owner = await auth.signUpEmailPassword({
      email: "lister@example.com",
      password: "correct-horse"
    });

    const sessions = await auth.listSessions({ actorUserId: owner.user.id });
    expect(sessions.length).toBe(1);
    expect(sessions[0].userId).toBe(owner.user.id);

    const { organisation } = await auth.createOrganisation({
      name: "List Org",
      ownerUserId: owner.user.id
    });

    const orgs = await auth.listOrganisations({ actorUserId: owner.user.id });
    expect(orgs.length).toBe(1);
    expect(orgs[0].id).toBe(organisation.id);

    await auth.createApiKey({
      name: "Key 1",
      organisationId: organisation.id,
      actorUserId: owner.user.id,
      scopes: ["read"]
    });
    await auth.createApiKey({
      name: "Key 2",
      organisationId: organisation.id,
      actorUserId: owner.user.id,
      scopes: ["write"]
    });

    const keys = await auth.listApiKeys({
      organisationId: organisation.id,
      actorUserId: owner.user.id
    });
    expect(keys.length).toBe(2);

    await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: "inv1@example.com",
      role: "member"
    });
    await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: "inv2@example.com",
      role: "admin"
    });

    const invitations = await auth.listInvitations({
      organisationId: organisation.id,
      actorUserId: owner.user.id
    });
    expect(invitations.length).toBe(2);
  });

  it("cleans audit logs older than a cutoff", async () => {
    const { auth } = createTestAuth();
    const signup = await auth.signUpEmailPassword({
      email: "audit-cleanup@example.com",
      password: "correct-horse"
    });
    const before = await auth.listAuditEvents({ actorUserId: signup.user.id });

    const deleted = await auth.cleanupAuditLogs({
      olderThan: new Date(Date.now() + 1_000)
    });

    expect(deleted).toBe(before.length);
    await expect(
      auth.listAuditEvents({ actorUserId: signup.user.id })
    ).resolves.toEqual([]);
    await expect(
      auth.cleanupAuditLogs({ olderThan: new Date("invalid") })
    ).rejects.toMatchObject({ code: "validation_error" });
  });

  it("handles organisation invites and role permissions", async () => {
    const { auth, emailProvider } = createTestAuth();
    const owner = await auth.signUpEmailPassword({
      email: "owner@example.com",
      password: "correct-horse"
    });
    const { organisation } = await auth.createOrganisation({
      name: "Example Co",
      ownerUserId: owner.user.id
    });
    const adminUser = await auth.createUser({ email: "admin@example.com" });

    const invite = await auth.inviteMember({
      organisationId: organisation.id,
      invitedByUserId: owner.user.id,
      email: "admin@example.com",
      role: "admin"
    });
    expect(invite.token).toBeTruthy();
    expect(emailProvider.messages.at(-1)?.type).toBe("organisation_invite");

    const accepted = await auth.acceptInvite({
      token: invite.token ?? "",
      userId: adminUser.id
    });
    expect(accepted.member.role).toBe("admin");

    await expect(
      auth.checkPermission(organisation.id, adminUser.id, "manage_api_keys")
    ).resolves.toBe(true);
  });
});
