import { isWebhookCapableStorage } from "../../src/webhook-storage.js";
import { isCloudCapableStorage } from "../../src/cloud-storage.js";
import { createCloudEvent } from "../../src/cloud-events.js";
import { userErasureResult } from "../../src/user-erasure.js";
import type { UserErasureHarness } from "./user-erasure-cases.js";
import { engine } from "./user-erasure-cases.js";
import { assertConformance as assert, assertConformanceEqual as equal } from "./conformance-assertions.js";

export async function eraseWebhookCopies({ storage, rateLimits, reopen }: UserErasureHarness): Promise<void> {
  assert(isWebhookCapableStorage(storage), "webhook capability");
  const auth = engine(storage, rateLimits);
  const actor = await auth.createUser({ email: `actor-${crypto.randomUUID()}@example.com` });
  const target = await auth.createUser({ email: `target-${crypto.randomUUID()}@example.com` });
  const now = new Date();
  const ids: string[] = [];
  const unrelated = (await storage.webhookStorage.listWebhookDeliveries({})).map(({ delivery }) => delivery.id);
  for (let index = 0; index < 3; index++) {
    const eventId = crypto.randomUUID();
    const deliveryId = crypto.randomUUID();
    ids.push(deliveryId);
    await storage.webhookStorage.recordAuditEventWithWebhooks({ id: eventId, eventType: "user.signed_up",
      actorUserId: null, targetUserId: null, organisationId: null, apiKeyId: null, ipAddress: null, userAgent: null,
      metadata: { nested: { userId: target.id, email: target.email } }, createdAt: now },
    { id: eventId, type: "user.signed_up", version: 1, payload: JSON.stringify({ eventId, data: { nested: { userId: target.id } } }), createdAt: now },
    [{ id: deliveryId, endpointId: "external", url: "https://example.com/hooks", createdAt: now }]);
  }
  const leaseToken = crypto.randomUUID();
  const claims = await storage.webhookStorage.claimWebhookDeliveries({ now, leaseToken,
    leaseExpiresAt: new Date(now.getTime() + 60_000), limit: 10 });
  equal(claims.filter(({ delivery }) => ids.includes(delivery.id)).length, 3, "personal deliveries claimed");
  const settle = (deliveryId: string, status: "failed" | "delivered") => storage.webhookStorage.settleWebhookDelivery({
    deliveryId, leaseToken, expectedTotalAttempts: 0, status, nextAttemptAt: now,
    attempt: { id: crypto.randomUUID(), deliveryId, attemptNumber: 1, startedAt: now, finishedAt: now,
      outcome: status, statusCode: status === "delivered" ? 204 : 400, errorCode: null, nextRetryAt: null } });
  assert(await settle(ids[0]!, "delivered"), "delivered copy seeded");
  assert(await settle(ids[1]!, "failed"), "failed copy seeded");
  assert(await storage.userErasureStorage.authorizeWebhookSend(ids[2]!, leaseToken), "request authorized before deletion");
  await auth.admin.eraseUser({ actorUserId: actor.id, userId: target.id, reason: "requested", operationId: crypto.randomUUID() });
  const restarted = reopen();
  assert(isWebhookCapableStorage(restarted), "restart webhook capability");
  const retained = (await restarted.webhookStorage.listWebhookDeliveries({})).map(({ delivery }) => delivery.id);
  equal(retained.filter((id) => ids.includes(id)).length, 0, "delivered failed and claimed copies removed");
  assert(unrelated.every((id) => retained.includes(id)), "unrelated webhook records preserved");
  equal((await restarted.webhookStorage.listWebhookAttempts(ids)).length, 0, "personal attempt copies removed");
  equal(await restarted.userErasureStorage.authorizeWebhookSend(ids[2]!, leaseToken), false, "claimed work cannot start another send");
  equal(await settle(ids[2]!, "failed"), false, "in progress response cannot restore settlement");
  equal(await restarted.webhookStorage.retryWebhookDelivery(ids[1]!, now), null, "erased failed event cannot retry");
}

export async function eraseCloudOutbox({ storage, rateLimits, reopen }: UserErasureHarness): Promise<void> {
  assert(isCloudCapableStorage(storage), "Cloud capability");
  const auth = engine(storage, rateLimits);
  const target = await auth.createUser({ email: `cloud-${crypto.randomUUID()}@example.com` });
  const { organisation } = await auth.createOrganisation({ name: "Erased Cloud organisation", ownerUserId: target.id });
  const operationId = crypto.randomUUID();
  const now = Date.now();
  const deletion = createCloudEvent("app_erasure", { type: "user.deleted", data: { userId: target.id }, userId: target.id }, new Date(now));
  const record = await storage.userErasureStorage.eraseAtomically({ operationId, userId: target.id,
    expectedUpdatedAt: target.updatedAt, now, protectedUntil: now, pendingStores: [], cloudEvent: deletion,
    organisations: [{ organisationId: organisation.id, action: "delete", confirmation: "delete_organisation" }] });
  equal(record.pendingCloudEvents.length, 2, "user and organisation requests commit together");
  equal(await storage.cloudStorage.clearCloudOutbox(true), 0, "clearing the outbox preserves required erasure requests");
  equal(await storage.cloudStorage.purgeCloudOutboxForUser(target.id, target.email), 0, "legacy purge preserves required erasure requests");
  equal(await storage.getUserById(target.id), null, "local user deletion committed");
  equal(await storage.getOrganisationById(organisation.id), null, "local organisation deletion committed");
  const requests = await storage.cloudStorage.claimCloudOutbox(10, new Date(now), new Date(now + 30_000));
  equal(requests.length, 2, "durable priority requests survive until acknowledged");
  for (const request of requests) assert(request.priority, "all deletion requests use priority outbox");
  await storage.userErasureStorage.settleCloud(deletion.id);
  equal((await storage.userErasureStorage.get(operationId))?.cloudComplete, false, "user acknowledgement does not imply organisation completion");
  const restarted = reopen();
  const organisationEvent = requests.find((request) => request.event.type === "org.deleted")!;
  await restarted.userErasureStorage.settleCloud(organisationEvent.id);
  await restarted.userErasureStorage.settleCloud(deletion.id);
  const complete = await restarted.userErasureStorage.finish(operationId, now + 1);
  assert(complete, "durable receipt exists");
  equal(userErasureResult(complete).status, "complete", "duplicate acknowledgements converge on completion");
  equal(complete.subject, null, "local Cloud target reference removed");
  const late = createCloudEvent("app_erasure", { type: "user.updated", data: { userId: target.id, email: target.email, authMethods: [] }, userId: target.id });
  let rejected = false;
  try { await storage.cloudStorage.enqueueCloudEvent(late, { type: "user", id: target.id }, false); } catch { rejected = true; }
  assert(rejected, "late personal Cloud event cannot recreate local erased data");
  let commandRejected = false;
  try {
    await storage.cloudStorage.reserveCloudCommand({ idempotencyKey: crypto.randomUUID(), nonce: crypto.randomUUID(),
      action: "user.enable", payloadHash: "delayed-command", payload: { action: "user.enable", userId: target.id,
        initiatedBy: "dashboard:administrator", reason: "delayed" }, now: new Date(), leaseUntil: new Date(Date.now() + 30_000) });
  } catch { commandRejected = true; }
  assert(commandRejected, "late remote command cannot recreate a personal command record");
}
