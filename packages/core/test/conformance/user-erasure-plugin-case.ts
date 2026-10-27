import { createOwnAuth } from "../../src/index.js";
import type { UserErasureHarness } from "./user-erasure-cases.js";
import { assertConformance as assert, assertConformanceEqual as equal } from "./conformance-assertions.js";

export async function erasePluginAfterRestart({ storage, rateLimits, reopen }: UserErasureHarness): Promise<void> {
  let available = false;
  const records = new Map<string, string>();
  const plugin = { id: "private-profile", version: "1", userErasure: { personalData: true as const,
    async erase(subject: { readonly userId: string }) {
      if (!available) throw new Error("Unavailable private store");
      records.delete(subject.userId);
    } } };
  const options = { rateLimitStore: rateLimits, tokenPepper: "restart-pepper", administration: { authorize: () => true } };
  const auth = createOwnAuth({ ...options, storage, plugins: [plugin] });
  const actor = await auth.createUser({ email: `actor-${crypto.randomUUID()}@example.com` });
  const target = await auth.createUser({ email: `target-${crypto.randomUUID()}@example.com` });
  records.set(target.id, "private profile");
  const input = { actorUserId: actor.id, userId: target.id, reason: "requested", operationId: crypto.randomUUID() };
  const pending = await auth.admin.eraseUser(input);
  equal(pending.local, "pending", "failed personal store keeps completion pending");
  equal(await storage.getUserById(target.id), null, "database deletion remains committed");
  assert(records.has(target.id), "failed store still has personal records");
  const restarted = reopen();
  const unconfigured = createOwnAuth({ ...options, storage: restarted });
  equal((await unconfigured.resumeUserErasure({ operationId: pending.operationId })).local, "pending", "missing plugin cannot silently complete cleanup");
  available = true;
  const recovered = createOwnAuth({ ...options, storage: restarted, plugins: [plugin] });
  const resumed = await recovered.admin.eraseUser({ ...input, operationId: crypto.randomUUID() });
  equal(resumed.operationId, pending.operationId, "named target retry joins its durable pending operation");
  equal(resumed.status, "complete", "restart retry completes required cleanup");
  equal(records.size, 0, "personal plugin data removed");
  equal((await restarted.userErasureStorage.get(pending.operationId))?.subject, null, "personal recovery keys removed");
}
