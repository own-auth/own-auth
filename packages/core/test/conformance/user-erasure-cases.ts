import { createOwnAuth, isSamlCapableStorage, type AuthStorage, type UserErasureCapableStorage, type RateLimitStore, type OwnAuthPluginDefinition } from "../../src/index.js";
import { assertConformance as assert, assertConformanceEqual as equal } from "./conformance-assertions.js";
import { eraseIdentityInventory } from "./user-erasure-identity-case.js";
import { eraseAuthorizationInventory } from "./user-erasure-authorization-case.js";
import { erasePluginAfterRestart } from "./user-erasure-plugin-case.js";
import { eraseCloudOutbox, eraseWebhookCopies } from "./user-erasure-delivery-cases.js";
import { userErasureResult } from "../../src/user-erasure.js";
import { samlConnection } from "../saml/saml-storage-fixtures.js";

export interface UserErasureHarness {
  storage: AuthStorage & UserErasureCapableStorage;
  rateLimits: RateLimitStore;
  reopen(): AuthStorage & UserErasureCapableStorage;
  close(): void | Promise<void>;
}

export const userErasureCases: readonly {
  name: string; run(harness: UserErasureHarness): Promise<void>;
}[] = [
  {
    name: "keeps local completion pending only while old anonymous identity requests remain authoritative",
    async run({ storage, rateLimits }) {
      const auth = engine(storage, rateLimits);
      const target = await auth.createUser({ email: `bounded-${crypto.randomUUID()}@example.com` });
      const owner = await auth.createUser({ email: `owner-${crypto.randomUUID()}@example.com` });
      const { organisation } = await auth.createOrganisation({ name: "Preserved identity provider", ownerUserId: owner.id });
      assert(isSamlCapableStorage(storage), "SAML capability");
      const connection = await storage.samlStorage.createConnection({ ...samlConnection(), id: crypto.randomUUID(), key: crypto.randomUUID(), organisationId: organisation.id });
      const now = Date.now();
      const deadline = new Date(now + 60_000);
      await storage.samlStorage.createTransaction({ id: crypto.randomUUID(), connectionId: connection.id, intent: "sign_in",
        relayStateHash: crypto.randomUUID(), requestIdHash: crypto.randomUUID(), destination: null, userId: null,
        expiresAt: deadline, consumedAt: new Date(now), createdAt: new Date(now) });
      const operationId = crypto.randomUUID();
      const record = await storage.userErasureStorage.eraseAtomically({ operationId, userId: target.id,
        expectedUpdatedAt: target.updatedAt, now, protectedUntil: now, pendingStores: [], cloudEvent: null, organisations: [] });
      equal(userErasureResult(record, now).local, "pending", "outstanding callback prevents premature completion");
      await rejects(() => storage.userErasureStorage.assertIdentityAllowed({ email: target.email }), "invalid_credentials");
      const completed = await storage.userErasureStorage.finish(operationId, deadline.getTime() + 1);
      assert(completed, "completed receipt exists");
      equal(completed.subject, null, "expired authority allows personal protection keys to be destroyed");
      equal(userErasureResult(completed, deadline.getTime() + 1).status, "complete", "no permanent local identity tombstone");
      await storage.samlStorage.cleanup(new Date(deadline.getTime() + 1));
    }
  },
  {
    name: "automatically preserves an organisation through another enabled owner",
    async run({ storage, rateLimits }) {
      const auth = engine(storage, rateLimits);
      const actor = await auth.createUser({ email: `owner-${crypto.randomUUID()}@example.com` });
      const target = await auth.createUser({ email: `target-${crypto.randomUUID()}@example.com` });
      const { organisation } = await auth.createOrganisation({ name: "Kept organisation", ownerUserId: target.id });
      await storage.createOrganisationMember({ id: crypto.randomUUID(), organisationId: organisation.id,
        userId: actor.id, role: "owner", status: "active", joinedAt: new Date(), removedAt: null, createdAt: new Date(), updatedAt: new Date() });
      equal((await auth.admin.eraseUser({ actorUserId: actor.id, userId: target.id, reason: "requested", operationId: crypto.randomUUID() })).status,
        "complete", "another owner permits safe deletion without an explicit transfer");
      equal((await storage.getOrganisationById(organisation.id))?.ownerUserId, actor.id, "existing owner keeps the organisation");
      equal((await storage.getOrganisationMember(organisation.id, actor.id))?.status, "active", "other owner's access preserved");
    }
  },
  {
    name: "rejects expired identity writes after the completed receipt loses its target",
    async run({ storage, rateLimits }) {
      const auth = engine(storage, rateLimits);
      const actor = await auth.createUser({ email: `actor-${crypto.randomUUID()}@example.com` });
      const target = await auth.createUser({ email: `target-${crypto.randomUUID()}@example.com` });
      await auth.admin.eraseUser({ actorUserId: actor.id, userId: target.id, reason: "requested", operationId: crypto.randomUUID() });
      const replacement = { ...target, id: crypto.randomUUID() };
      const account = { id: crypto.randomUUID(), userId: replacement.id, provider: "google" as const,
        providerAccountId: crypto.randomUUID(), providerEmail: target.email, providerPhone: null, createdAt: new Date(), updatedAt: new Date() };
      const expired = new Date(Date.now() - 1_000);
      const denied = async (work: () => Promise<unknown>) => {
        let rejected = false;
        try { await work(); } catch { rejected = true; }
        assert(rejected, "expired identity write rejected");
      };
      await denied(() => storage.createUserAndAccount(replacement, account, expired));
      assert(isSamlCapableStorage(storage), "SAML capability");
      await denied(() => storage.samlStorage.commitIdentity({ user: replacement, account, auditEvents: [], authorityExpiresAt: expired }));
      try {
        const result = await storage.claimEmailOwnershipAtomically({ operationId: crypto.randomUUID(), sourceUserId: null,
          email: target.email!, verifiedAt: new Date(), replacementUser: replacement, replacementAccount: account,
          proof: { kind: "provider", expiresAt: expired }, sessionTokenHash: null });
        equal(result, null, "expired email authority cannot create an identity");
      } catch {}
      equal(await storage.getUserById(replacement.id), null, "old callback cannot recreate the erased mailbox");
      const now = new Date();
      await denied(() => storage.createSession({ id: crypto.randomUUID(), userId: actor.id, tokenHash: crypto.randomUUID(),
        createdAt: now, lastActiveAt: now, expiresAt: new Date(now.getTime() + 60_000), idleExpiresAt: new Date(now.getTime() + 60_000),
        ipAddress: null, userAgent: null, revokedAt: null, revokeReason: null, authenticationMethods: ["google"], assuranceLevel: "aal1", authenticatedAt: now }, expired));
      const challengeId = crypto.randomUUID();
      await denied(() => storage.createMfaChallenge({ id: challengeId, userId: actor.id, tokenHash: crypto.randomUUID(),
        primaryMethod: "google", methods: ["totp"], attempts: 0, maxAttempts: 5, expiresAt: new Date(now.getTime() + 60_000),
        consumedAt: null, createdAt: now }, expired));
      equal(await storage.getMfaChallengeById(challengeId), null, "expired callback cannot start MFA for another identity");
    }
  },
  { name: "erases active and historical credentials and preserves another person's owned records", run: eraseIdentityInventory },
  { name: "erases authorization, device, SAML, and SCIM personal records and preserves shared configuration", run: eraseAuthorizationInventory },
  { name: "retries required plugin cleanup after adapter restart without the deleted login", run: erasePluginAfterRestart },
  { name: "removes delivered failed and claimed webhook copies without settlement resurrection", run: eraseWebhookCopies },
  { name: "commits Cloud deletion requests together and survives restart and duplicate acknowledgements", run: eraseCloudOutbox },
  {
    name: "erases through the core service and preserves unrelated users after adapter restart",
    async run({ storage, rateLimits, reopen }) {
      const auth = engine(storage, rateLimits);
      const actor = await auth.createUser({ email: `actor-${crypto.randomUUID()}@example.com` });
      const target = await auth.createUser({ email: `target-${crypto.randomUUID()}@example.com` });
      const other = await auth.createUser({ email: `other-${crypto.randomUUID()}@example.com` });
      await auth.storage.createAuditEvent({ id: "erasure-audit", eventType: "user.signed_up",
        actorUserId: target.id, targetUserId: target.id, organisationId: null, apiKeyId: null,
        ipAddress: "192.0.2.1", userAgent: "erasure test", metadata: {}, createdAt: new Date() });
      const operationId = crypto.randomUUID();
      const result = await auth.admin.eraseUser({ actorUserId: actor.id, userId: target.id, reason: "requested", operationId });
      equal(result.status, "complete", "erasure completes");
      const restarted = reopen();
      equal(await restarted.getUserById(target.id), null, "target remains deleted");
      equal((await restarted.listAccountsByUserId(target.id)).length, 0, "login accounts removed");
      equal((await restarted.listAuditEvents({ userId: target.id })).length, 0, "personal audit removed");
      equal((await restarted.getUserById(other.id))?.id, other.id, "other account preserved");
      const receipt = await restarted.userErasureStorage.get(operationId);
      equal(receipt?.subject, null, "completed receipt has no target");
      equal((await engine(restarted, rateLimits).getUserErasure({ operationId })).status, "complete", "status survives restart");
    }
  },
  {
    name: "returns an ownership conflict without partial deletion and accepts an authorized transfer",
    async run({ storage, rateLimits }) {
      const auth = engine(storage, rateLimits);
      const actor = await auth.createUser({ email: `actor-${crypto.randomUUID()}@example.com` });
      const target = await auth.createUser({ email: `target-${crypto.randomUUID()}@example.com` });
      const other = await auth.createUser({ email: `other-${crypto.randomUUID()}@example.com` });
      const { organisation } = await auth.createOrganisation({ name: "Kept organisation", ownerUserId: target.id });
      const member = await storage.createOrganisationMember({ id: crypto.randomUUID(), organisationId: organisation.id,
        userId: other.id, role: "member", status: "active", joinedAt: new Date(), removedAt: null,
        createdAt: new Date(), updatedAt: new Date() });
      const input = { actorUserId: actor.id, userId: target.id, reason: "requested", operationId: crypto.randomUUID() };
      await rejects(() => auth.admin.eraseUser(input), "user_erasure_ownership_required");
      assert(await storage.getUserById(target.id), "target survives ownership conflict");
      equal(await storage.userErasureStorage.get(input.operationId), null, "conflict records no deletion");
      await auth.admin.eraseUser({ ...input, organisations: [{ organisationId: organisation.id, action: "transfer", newOwnerUserId: other.id }] });
      equal((await storage.getOrganisationById(organisation.id))?.ownerUserId, other.id, "primary owner transferred");
      equal((await storage.getOrganisationMember(organisation.id, other.id))?.role, "owner", "eligible member promoted");
      equal((await storage.getOrganisationMember(organisation.id, other.id))?.id, member.id, "membership preserved");
    }
  },
  {
    name: "deletes explicitly confirmed sole owner organisations without deleting other members",
    async run({ storage, rateLimits }) {
      const auth = engine(storage, rateLimits);
      const actor = await auth.createUser({ email: `actor-${crypto.randomUUID()}@example.com` });
      const target = await auth.createUser({ email: `target-${crypto.randomUUID()}@example.com` });
      const other = await auth.createUser({ email: `other-${crypto.randomUUID()}@example.com` });
      const { organisation } = await auth.createOrganisation({ name: "Removed organisation", ownerUserId: target.id });
      const second = await auth.createOrganisation({ name: "Second removed organisation", ownerUserId: target.id });
      await storage.createOrganisationMember({ id: crypto.randomUUID(), organisationId: organisation.id, userId: other.id,
        role: "member", status: "active", joinedAt: new Date(), removedAt: null, createdAt: new Date(), updatedAt: new Date() });
      await auth.admin.eraseUser({ actorUserId: actor.id, userId: target.id, reason: "requested", operationId: crypto.randomUUID(),
        organisations: [organisation, second.organisation].map(({ id }) => ({
          organisationId: id, action: "delete", confirmation: "delete_organisation"
        })) });
      equal(await storage.getOrganisationById(organisation.id), null, "organisation removed");
      equal(await storage.getOrganisationById(second.organisation.id), null, "second organisation removed");
      equal((await storage.getUserById(other.id))?.id, other.id, "other member login preserved");
    }
  },
  {
    name: "joins concurrent erasure requests and rejects reuse of a completed operation for a new identity",
    async run({ storage, rateLimits, reopen }) {
      let cleanupAvailable = false;
      const plugins = [{ id: "pending-race", version: "1", userErasure: { personalData: true as const,
        async erase() { if (!cleanupAvailable) throw new Error("cleanup unavailable"); } } }];
      const auth = engine(storage, rateLimits, plugins);
      const actor = await auth.createUser({ email: `actor-${crypto.randomUUID()}@example.com` });
      const target = await auth.createUser({ email: `target-${crypto.randomUUID()}@example.com` });
      const inputs = [crypto.randomUUID(), crypto.randomUUID()].map((operationId) => ({ actorUserId: actor.id,
        userId: target.id, reason: "requested", operationId }));
      const results = await Promise.allSettled(inputs.map((input, index) =>
        engine(index ? reopen() : storage, rateLimits, plugins).admin.eraseUser(input)));
      equal(results.filter((result) => result.status === "fulfilled").length, 2, "both concurrent requests join pending deletion");
      const completed = results.find((result) => result.status === "fulfilled");
      if (!completed || completed.status !== "fulfilled") throw new Error("Missing erasure result");
      for (const result of results) if (result.status === "fulfilled") equal(result.value.operationId, completed.value.operationId, "concurrent operation IDs converge");
      cleanupAvailable = true;
      equal((await auth.resumeUserErasure({ operationId: completed.value.operationId })).status, "complete", "shared operation completes once cleanup recovers");
      const replacement = await auth.createUser({ email: target.email! });
      await rejects(() => auth.admin.eraseUser({ ...inputs[0]!, userId: replacement.id,
        operationId: completed.value.operationId }), "erasure_operation_closed");
      equal((await storage.getUserById(replacement.id))?.id, replacement.id, "new identity preserved");
    }
  },
  {
    name: "returns every unresolved organisation and rejects a transfer whose membership changes before deletion",
    async run({ storage, rateLimits, reopen }) {
      const auth = engine(storage, rateLimits);
      const actor = await auth.createUser({ email: `actor-${crypto.randomUUID()}@example.com` });
      const target = await auth.createUser({ email: `target-${crypto.randomUUID()}@example.com` });
      const first = await auth.createOrganisation({ name: "First owned organisation", ownerUserId: target.id });
      const second = await auth.createOrganisation({ name: "Second owned organisation", ownerUserId: target.id });
      const input = { actorUserId: actor.id, userId: target.id, operationId: crypto.randomUUID(), reason: "requested" };
      try { await auth.admin.eraseUser(input); throw new Error("Expected ownership decision"); }
      catch (error) {
        const details = (error as { details?: { organisationIds?: string[] } }).details;
        equal(JSON.stringify(details?.organisationIds?.sort()), JSON.stringify([first.organisation.id, second.organisation.id].sort()), "all ownership decisions returned");
      }
      const member = await storage.createOrganisationMember({ id: crypto.randomUUID(), organisationId: first.organisation.id,
        userId: actor.id, role: "member", status: "active", joinedAt: new Date(), removedAt: null, createdAt: new Date(), updatedAt: new Date() });
      const original = storage.userErasureStorage;
      const concurrent = new Proxy(storage, { get(targetStorage, property) {
        if (property === "userErasureStorage") return new Proxy(original, { get(targetErasure, name) {
          if (name === "eraseAtomically") return async (request: Parameters<typeof original.eraseAtomically>[0]) => {
            await reopen().updateOrganisationMember(member.id, { status: "removed", removedAt: new Date() });
            return original.eraseAtomically(request);
          };
          const value = Reflect.get(targetErasure, name);
          return typeof value === "function" ? value.bind(targetErasure) : value;
        } });
        const value = Reflect.get(targetStorage, property);
        return typeof value === "function" ? value.bind(targetStorage) : value;
      } });
      await rejects(() => engine(concurrent, rateLimits).admin.eraseUser({ ...input, organisations: [
        { organisationId: first.organisation.id, action: "transfer", newOwnerUserId: actor.id },
        { organisationId: second.organisation.id, action: "delete", confirmation: "delete_organisation" }
      ] }), "user_erasure_ownership_required");
      assert(await storage.getUserById(target.id), "target preserved after concurrent membership removal");
      assert(await storage.getOrganisationById(second.organisation.id), "explicit deletion rolls back with ownership conflict");
      equal(await storage.userErasureStorage.get(input.operationId), null, "no partial deletion receipt");
    }
  }
];

export function engine(storage: AuthStorage, rateLimits: RateLimitStore, plugins: readonly OwnAuthPluginDefinition[] = []) {
  return createOwnAuth({ storage, rateLimitStore: rateLimits,
    plugins, administration: { authorize: () => true }, tokenPepper: "erasure-conformance-pepper", baseUrl: "http://localhost" });
}

export async function rejects(work: () => Promise<unknown>, code: string): Promise<void> {
  try { await work(); } catch (error) {
    equal((error as { code?: string }).code, code, "error code"); return;
  }
  throw new Error(`Expected ${code}`);
}
