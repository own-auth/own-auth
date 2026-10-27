import { describe, expect, it } from "vitest";
import { engine } from "../conformance/user-erasure-cases.js";
import { PostgresAuthStorage, PostgresRateLimitStore } from "../../src/postgres/index.js";
import { userErasureCases } from "../conformance/user-erasure-cases.js";
import { createPostgresTestDatabase, hasPostgresTestDatabase } from "./postgres-test-database.js";
import { createPostgresPersistence } from "../../src/postgres/postgres-persistence.js";

(hasPostgresTestDatabase ? describe : describe.skip)("Postgres user erasure", () => {
  it.each(["client", "pool"] as const)("rolls back failed deletion and safely retries through a %s", async (connection) => {
    const database = await createPostgresTestDatabase();
    const persistence = connection === "pool" ? createPostgresPersistence(database.connectionString) : null;
    try {
      const storage = persistence?.storage ?? new PostgresAuthStorage(database.client);
      const auth = engine(storage, persistence?.rateLimitStore ?? new PostgresRateLimitStore(database.client));
      const actor = await auth.createUser({ email: "rollback-actor@example.com" });
      const target = await auth.createUser({ email: "rollback-target@example.com" });
      const input = { actorUserId: actor.id, userId: target.id, operationId: crypto.randomUUID(), reason: "requested" };
      const audits = await storage.listAuditEvents();
      await database.client.query("create function fail_erasure() returns trigger language plpgsql as $$ begin raise exception 'injected deletion failure'; end $$");
      await database.client.query("create trigger fail_erasure before delete on own_auth_users for each row execute function fail_erasure()");
      await expect(auth.admin.eraseUser(input)).rejects.toThrow("injected deletion failure");
      expect(await storage.getUserById(target.id)).toEqual(target);
      expect(await storage.listAuditEvents()).toEqual(audits);
      expect(await storage.userErasureStorage.get(input.operationId)).toBeNull();
      await database.client.query("drop trigger fail_erasure on own_auth_users");
      expect(await auth.admin.eraseUser(input)).toMatchObject({ status: "complete" });
    } finally { await persistence?.close(); await database.close(); }
  });
  for (const testCase of userErasureCases) it(testCase.name, async () => {
    const database = await createPostgresTestDatabase();
    const [first, second] = await database.connectPair();
    try {
      await testCase.run({ storage: new PostgresAuthStorage(first), rateLimits: new PostgresRateLimitStore(first),
        reopen: () => new PostgresAuthStorage(second), close() {} });
    } finally { first.release(); second.release(); await database.close(); }
  });
});
