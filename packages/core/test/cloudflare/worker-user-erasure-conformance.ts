import { createOwnAuth } from "../../dist/index.js";
import { createD1Persistence, type D1DatabaseLike } from "../../dist/d1/index.js";
import { userErasureCases } from "../conformance/user-erasure-cases.js";

export async function handleUserErasureQualification(database: D1DatabaseLike): Promise<Response> {
  await assertErasureRollback(database);
  for (const testCase of userErasureCases) {
    const { storage, rateLimitStore } = createD1Persistence(database);
    try {
      await testCase.run({ storage, rateLimits: rateLimitStore,
        reopen: () => createD1Persistence(database).storage, close() {} });
    } catch (error) {
      throw new Error(`D1 user erasure failed: ${testCase.name}`, { cause: error });
    }
  }
  const receipt = await database.prepare("select operation_id from own_auth_user_erasures where completed_at_ms is not null limit 1")
    .first<{ operation_id: string }>();
  if (!receipt) throw new Error("Missing completed erasure receipt");
  return Response.json({ cases: userErasureCases.length, operationId: receipt.operation_id });
}

async function assertErasureRollback(database: D1DatabaseLike): Promise<void> {
  const { storage } = createD1Persistence(database);
  const auth = createOwnAuth({ storage, administration: { authorize: () => true } });
  const actor = await auth.createUser({ email: `actor-${crypto.randomUUID()}@example.com` });
  const target = await auth.createUser({ email: `target-${crypto.randomUUID()}@example.com` });
  const input = { actorUserId: actor.id, userId: target.id, operationId: crypto.randomUUID(), reason: "requested" };
  const before = JSON.stringify(await storage.listAuditEvents());
  await database.prepare("create trigger fail_erasure before delete on own_auth_users begin select raise(abort, 'injected deletion failure'); end").run();
  let rejected = false;
  try { await auth.admin.eraseUser(input); } catch { rejected = true; }
  await database.prepare("drop trigger fail_erasure").run();
  if (!rejected || !await storage.getUserById(target.id) || await storage.userErasureStorage.get(input.operationId) ||
    JSON.stringify(await storage.listAuditEvents()) !== before) throw new Error("D1 erasure did not roll back atomically");
  if ((await auth.admin.eraseUser(input)).status !== "complete") throw new Error("D1 rollback retry did not complete");
}

export async function handleUserErasureRestart(request: Request, database: D1DatabaseLike): Promise<Response> {
  const { operationId } = await request.json() as { operationId: string };
  const { storage } = createD1Persistence(database);
  const result = await createOwnAuth({ storage }).getUserErasure({ operationId });
  return Response.json({ completedErasureSurvivesRestart: result.status === "complete" });
}
