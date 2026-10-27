import type { AtomicEmailOwnershipInput } from "../../src/auth-storage-atomic.js";
import type { AuthStorage } from "../../src/storage.js";
import type { User } from "../../src/types.js";
import type { ScimStorage } from "../../src/scim-storage.js";
import type { ScimUser } from "../../src/scim-types.js";
import type { AtomicAdapterCase } from "./atomic-adapter-cases.js";
import { assertConformanceEqual, assertSingleValueWinner } from "./conformance-assertions.js";
import { uniqueConformanceValue as unique } from "./conformance-values.js";

export const emailOwnershipAdapterCases: readonly AtomicAdapterCase[] = [
  ...([false, true] as const).map((removed): AtomicAdapterCase => ({
    name: removed
      ? "rejects a SAML mailbox claim after membership removal without changing ownership"
      : "allows an active SAML member to claim a mailbox despite removal from another organisation",
    async run({ storage, scim }) {
      const input = await pendingClaim(storage[0]);
      const matching = await provisionedClaim(storage[0], scim[0], input, input.email);
      const other = await provisionedClaim(storage[0], scim[0], input, `${unique("other")}@example.com`);
      await storage[0].updateOrganisationMember(other.membershipId, { status: "removed", removedAt: input.verifiedAt });
      if (removed) {
        await storage[0].updateOrganisationMember(matching.membershipId, { status: "removed", removedAt: input.verifiedAt });
      }
      input.proof = { kind: "provider", samlOrganisationId: matching.connectionId };
      const result = await storage[0].claimEmailOwnershipAtomically(input);
      assertConformanceEqual(result?.user.id ?? null, removed ? null : input.replacementUser.id, "SAML membership decision");
      assertConformanceEqual((await storage[1].getUserByEmail(input.email))?.id,
        removed ? input.sourceUserId : input.replacementUser.id, "mailbox owner");
      assertConformanceEqual((await storage[1].listSessionsByUserId(input.sourceUserId!))[0]?.revokedAt?.getTime() ?? null,
        removed ? null : input.verifiedAt.getTime(), "original session changes only after an allowed claim");
      assertConformanceEqual((await scim[1].getUserById(matching.id))?.userId,
        removed ? input.sourceUserId : input.replacementUser.id, "matching SCIM owner");
      assertConformanceEqual((await scim[1].getUserById(other.id))?.userId, input.sourceUserId, "unrelated SCIM owner");
    }
  })),
  ...([false, true] as const).map((rollback): AtomicAdapterCase => ({
    name: rollback
      ? "preserves SCIM ownership and resource versions when a mailbox claim rolls back"
      : "moves only matching SCIM records and memberships to the proved mailbox owner",
    async run({ storage, scim }) {
      const input = await pendingClaim(storage[0]);
      const matching = await provisionedClaim(storage[0], scim[0], input, input.email);
      const other = await provisionedClaim(storage[0], scim[0], input, `${unique("other")}@example.com`);
      const deleted = await provisionedClaim(storage[0], scim[0], input, input.email, true);
      if (rollback) {
        await forceReplacementConflict(storage[0], input);
      }
      let failed = false;
      let result;
      try { result = await storage[0].claimEmailOwnershipAtomically(input); } catch { failed = true; }
      assertConformanceEqual(failed, rollback, "mailbox claim failure");
      if (!rollback) {
        assertConformanceEqual(result?.user.id, input.replacementUser.id, "proved mailbox owner");
        assertConformanceEqual(result?.reassignedMemberships.length, 1, "only matching provisioned membership moves");
        assertConformanceEqual(result?.reassignedMemberships[0]?.id, matching.membershipId, "original membership ID returned");
      }
      for (const resource of [matching, other, deleted]) {
        const moved = !rollback && resource.id === matching.id;
        const stored = await scim[1].getUserById(resource.id);
        const expected = {
          ...resource,
          userId: moved ? input.replacementUser.id : input.sourceUserId!,
          version: resource.version + Number(moved),
          updatedAt: moved ? input.verifiedAt : resource.updatedAt
        };
        for (const key of Object.keys(expected) as (keyof ScimUser)[]) {
          const actualValue = stored?.[key];
          const expectedValue = expected[key];
          assertConformanceEqual(
            actualValue instanceof Date ? actualValue.getTime() : actualValue,
            expectedValue instanceof Date ? expectedValue.getTime() : expectedValue,
            `SCIM ${key}`
          );
        }
        const members = await storage[1].listOrganisationMembers(resource.connectionId);
        const member = members.find((candidate) => candidate.id === resource.membershipId);
        assertConformanceEqual(member?.userId, expected.userId, "matching membership ownership");
        assertConformanceEqual(member?.role, "member", "provisioned role preserved");
        assertConformanceEqual(member?.joinedAt?.getTime(), resource.createdAt.getTime(), "original join date preserved");
      }
    }
  })),
  {
    name: "separates a proved mailbox from an unproved password and revokes the original sessions",
    async run({ storage }) {
      const input = await pendingClaim(storage[0]);
      const result = await storage[0].claimEmailOwnershipAtomically(input);
      assertConformanceEqual(result?.created, true, "separate email owner created");
      assertConformanceEqual(result?.user.id, input.replacementUser.id, "proved mailbox owner ID");
      assertConformanceEqual(result?.user.passwordHash, null, "no inherited password");
      assertConformanceEqual((await storage[0].getUserById(input.sourceUserId!))?.email, null, "unproved email detached");
      assertConformanceEqual((await storage[0].getUserById(input.sourceUserId!))?.passwordHash,
        "unproved-password-hash", "original password stays on original record");
      assertConformanceEqual(result?.revokedSessions.length, 1, "original sessions revoked atomically");
      assertConformanceEqual(result?.revokedSessions[0]?.revokeReason, "email_ownership_changed", "revocation reason");
      assertConformanceEqual((await storage[0].getUserByEmail(input.email))?.id, result?.user.id, "unique mailbox owner");
      assertConformanceEqual((await storage[0].listAccountsByUserId(result!.user.id))[0]?.provider,
        "magic_link", "fresh mailbox authentication method");
    }
  },
  {
    name: "keeps the original account when the mailbox proof also carries its live session",
    async run({ storage }) {
      const input = await pendingClaim(storage[0]);
      input.sessionTokenHash = `session-${input.sourceUserId}`;
      const result = await storage[0].claimEmailOwnershipAtomically(input);
      assertConformanceEqual(result?.user.id, input.sourceUserId, "original actor and mailbox proved together");
      assertConformanceEqual(result?.created, false, "original account retained");
      assertConformanceEqual(result?.verified, true, "first email verification recorded");
      assertConformanceEqual(result?.user.passwordHash, "unproved-password-hash", "proved actor's password retained");
      assertConformanceEqual(result?.revokedSessions.length, 0, "matching live session retained");
    }
  },
  {
    name: "does not inherit credentials through an expired original session",
    async run({ storage }) {
      const input = await pendingClaim(storage[0]);
      input.sessionTokenHash = `session-${input.sourceUserId}`;
      const session = (await storage[0].listSessionsByUserId(input.sourceUserId!))[0]!;
      await storage[0].updateSession(session.id, { idleExpiresAt: new Date(input.verifiedAt.getTime() - 1) });
      const result = await storage[0].claimEmailOwnershipAtomically(input);
      assertConformanceEqual(result?.created, true, "expired session cannot prove original actor");
    }
  },
  {
    name: "allows only one connection to claim a mailbox with the same token",
    async run({ storage }) {
      const first = await pendingClaim(storage[0]);
      const second = replacementClaim(first);
      const results = await Promise.all([
        storage[0].claimEmailOwnershipAtomically(first),
        storage[1].claimEmailOwnershipAtomically(second)
      ]);
      const winner = assertSingleValueWinner(results, "atomic mailbox claim");
      assertConformanceEqual((await storage[0].getUserByEmail(first.email))?.id,
        winner.user.id, "winner owns the mailbox");
      assertConformanceEqual(await storage[0].getUserById(
        winner.user.id === first.replacementUser.id ? second.replacementUser.id : first.replacementUser.id
      ), null, "losing replacement was not inserted");
    }
  },
  {
    name: "rolls back email detachment and token consumption when replacement creation fails",
    async run({ storage }) {
      const input = await pendingClaim(storage[0]);
      await forceReplacementConflict(storage[0], input);
      let failed = false;
      try { await storage[0].claimEmailOwnershipAtomically(input); } catch { failed = true; }
      assertConformanceEqual(failed, true, "replacement constraint failure is returned");
      assertConformanceEqual((await storage[0].getUserById(input.sourceUserId!))?.email,
        input.email, "source contact survives rollback");
      assertConformanceEqual(await storage[0].getUserById(input.replacementUser.id), null, "replacement rolled back");
      assertConformanceEqual((await storage[0].listSessionsByUserId(input.sourceUserId!))[0]?.revokedAt,
        null, "source session survives rollback");
      if (input.proof.kind !== "token") throw new Error("Expected email token proof");
      assertConformanceEqual((await storage[0].getTokenByHash(input.proof.tokenHash, input.proof.type))?.usedAt,
        null, "proof remains usable after rollback");
    }
  },
  {
    name: "keeps a verified mailbox account stable without an original browser session",
    async run({ storage }) {
      const input = await pendingClaim(storage[0]);
      await storage[0].updateUser(input.sourceUserId!, { emailVerifiedAt: input.verifiedAt });
      const result = await storage[0].claimEmailOwnershipAtomically(input);
      assertConformanceEqual(result?.user.id, input.sourceUserId, "verified account identity is stable");
      assertConformanceEqual(result?.verified, false, "email verification is not recorded twice");
    }
  },
  {
    name: "does not let an attacker disabling an unproved signup reserve the mailbox",
    async run({ storage }) {
      const input = await pendingClaim(storage[0]);
      await storage[0].updateUser(input.sourceUserId!, { disabledAt: input.verifiedAt });
      const result = await storage[0].claimEmailOwnershipAtomically(input);
      assertConformanceEqual(result?.created, true, "disabled unproved signup cannot block mailbox owner");
      assertConformanceEqual(result?.user.disabledAt, null, "proved mailbox owner has a separate enabled record");
      assertConformanceEqual((await storage[0].getUserById(input.sourceUserId!))?.disabledAt?.getTime(),
        input.verifiedAt.getTime(), "original disabled record remains disabled");
    }
  }
];

async function forceReplacementConflict(storage: AuthStorage, input: AtomicEmailOwnershipInput): Promise<void> {
  const account = await storage.createAccount({
    ...input.replacementAccount, id: unique("collision"), userId: input.sourceUserId!,
    provider: "google", providerAccountId: unique("google")
  });
  input.replacementAccount.id = account.id;
}

async function pendingClaim(storage: AuthStorage): Promise<AtomicEmailOwnershipInput> {
  const now = new Date();
  const source = user(unique("unproved"), `${unique("mailbox")}@example.com`, now);
  source.passwordHash = "unproved-password-hash";
  await storage.createUser(source);
  await storage.createAccount({
    id: unique("password-account"), userId: source.id, provider: "password",
    providerAccountId: source.email!, providerEmail: source.email, providerPhone: null,
    createdAt: now, updatedAt: now
  });
  await storage.createSession({
    id: unique("session"), userId: source.id, tokenHash: `session-${source.id}`,
    createdAt: now, lastActiveAt: now, expiresAt: new Date(now.getTime() + 60_000),
    idleExpiresAt: new Date(now.getTime() + 60_000), revokedAt: null, revokeReason: null,
    ipAddress: null, userAgent: null, authenticationMethods: ["password"], assuranceLevel: "aal1", authenticatedAt: now
  });
  const owner = user(unique("owner"), source.email!, now);
  owner.emailVerifiedAt = now;
  const tokenHash = unique("email-proof");
  await storage.createToken({
    id: unique("proof"), tokenHash, type: "email_verification", userId: source.id,
    email: source.email, phone: null, organisationId: null, createdAt: now,
    expiresAt: new Date(now.getTime() + 60_000), usedAt: null
  });
  return {
    operationId: unique("claim"), sourceUserId: source.id, email: source.email!, verifiedAt: now,
    replacementUser: owner,
    replacementAccount: {
      id: unique("owner-account"), userId: owner.id, provider: "magic_link",
      providerAccountId: source.email!, providerEmail: source.email, providerPhone: null,
      createdAt: now, updatedAt: now
    },
    proof: { kind: "token", tokenHash, type: "email_verification" }, sessionTokenHash: null
  };
}

async function provisionedClaim(
  storage: AuthStorage,
  scim: ScimStorage,
  input: AtomicEmailOwnershipInput,
  email: string,
  deleted = false
): Promise<ScimUser> {
  const id = unique("provisioned");
  const at = new Date(input.verifiedAt.getTime() - 60_000);
  const owner = user(unique("organisation-owner"), `${unique("owner")}@example.com`, at);
  await storage.createUser(owner);
  await storage.createOrganisation({
    id, name: "Provisioned membership", slug: id, ownerUserId: owner.id,
    metadata: {}, createdAt: at, updatedAt: at, disabledAt: null
  });
  await scim.createConnection({
    id, organisationId: id, key: id, name: "Provisioning provider", defaultRole: "member",
    accountLinking: "email", samlConnectionId: null, disabledAt: null, createdAt: at, updatedAt: at
  });
  const resource: ScimUser = {
    id, connectionId: id, userId: input.sourceUserId!, membershipId: id, externalId: id,
    userName: email, normalizedUserName: email, email, normalizedEmail: email,
    displayName: "Original provisioned name", givenName: null, familyName: null,
    active: !deleted, version: 3, deletedAt: deleted ? at : null, createdAt: at, updatedAt: at
  };
  await scim.commitProvision({
    scimUser: resource,
    membership: {
      id, organisationId: id, userId: input.sourceUserId!, role: "member", status: "active",
      joinedAt: at, removedAt: null, createdAt: at, updatedAt: at
    },
    auditEvents: []
  });
  return resource;
}

function replacementClaim(input: AtomicEmailOwnershipInput): AtomicEmailOwnershipInput {
  const id = unique("other-owner");
  return {
    ...input, operationId: unique("other-claim"),
    replacementUser: { ...input.replacementUser, id },
    replacementAccount: { ...input.replacementAccount, id: unique("other-account"), userId: id }
  };
}

function user(id: string, email: string, at: Date): User {
  return {
    id, email, emailVerifiedAt: null, phone: null, phoneVerifiedAt: null, passwordHash: null,
    name: null, imageUrl: null, disabledAt: null, metadata: {}, createdAt: at, updatedAt: at, lastLoginAt: null
  };
}
