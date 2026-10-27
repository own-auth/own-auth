import { describe, expect, it, vi } from "vitest";
import { createCloudEvent } from "../src/cloud-events.js";
import { InMemoryAuthStorage, InMemoryRateLimitStore } from "../src/index.js";
import { userErasureCases, type UserErasureHarness } from "./conformance/user-erasure-cases.js";

const adapters: Record<string, () => Promise<UserErasureHarness>> = {
  async Memory() {
    const storage = new InMemoryAuthStorage();
    return { storage, rateLimits: new InMemoryRateLimitStore(), reopen: () => storage, close() {} };
  }
};
for (const [name, create] of Object.entries(adapters)) describe(`${name} user erasure`, () => {
  for (const testCase of userErasureCases) it(testCase.name, async () => {
    const harness = await create();
    try { await testCase.run(harness); } finally { await harness.close(); }
  });
});

it("rolls back memory deletion if committing the durable Cloud request fails", async () => {
  const storage = new InMemoryAuthStorage();
  const { createOwnAuth } = await import("../src/index.js");
  const auth = createOwnAuth({ storage });
  const target = await auth.createUser({ email: "rollback-memory@example.com" });
  const operationId = crypto.randomUUID();
  const now = Date.now();
  const failure = vi.spyOn(storage.cloudStorage.erasureOutbox, "set").mockImplementationOnce(() => { throw new Error("write failed"); });
  try {
    await expect(storage.userErasureStorage.eraseAtomically({ operationId, userId: target.id,
      expectedUpdatedAt: target.updatedAt, now, protectedUntil: now, pendingStores: [], organisations: [],
      cloudEvent: createCloudEvent("app_test", { type: "user.deleted", data: { userId: target.id }, userId: target.id }) })).rejects.toThrow("write failed");
    expect(await storage.getUserById(target.id)).toEqual(target);
    expect(await storage.userErasureStorage.get(operationId)).toBeNull();
    expect(await storage.cloudStorage.countCloudOutbox()).toBe(0);
  } finally { failure.mockRestore(); }
});
