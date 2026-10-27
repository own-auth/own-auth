import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createCloudEvent } from "../../src/cloud-events.js";
import { createOwnAuth } from "../../src/index.js";
import { PostgresAuthStorage } from "../../src/postgres/index.js";
import {
  createPostgresTestDatabase,
  hasPostgresTestDatabase,
  type PostgresTestDatabase
} from "./postgres-test-database.js";

const describeWithDatabase = hasPostgresTestDatabase ? describe : describe.skip;

describeWithDatabase("Postgres Cloud integration", () => {
  let database: PostgresTestDatabase;

  beforeAll(async () => {
    database = await createPostgresTestDatabase();
  });

  afterAll(async () => {
    await database?.close();
  });

  it("assigns unique entity versions across separate connections", async () => {
    const [first, second] = await database.connectPair();
    try {
      const stores = [
        new PostgresAuthStorage(first).cloudStorage,
        new PostgresAuthStorage(second).cloudStorage
      ] as const;
      const user = await createOwnAuth({ storage: new PostgresAuthStorage(first) }).createUser({ email: `versions-${crypto.randomUUID()}@example.com` });
      const entity = { type: "user", id: user.id } as const;
      const events = [0, 1].map(() => createCloudEvent("app_cloud", {
        type: "user.updated",
        data: { userId: entity.id, email: "user@example.com", authMethods: ["email"] },
        userId: entity.id,
        entity
      }));

      const stored = await Promise.all(events.map((event, index) =>
        stores[index as 0 | 1].enqueueCloudEvent(event, entity, false)
      ));

      expect(stored.every(Boolean)).toBe(true);
      expect(stored.map((item) => item?.entityVersion).sort()).toEqual([1, 2]);
    } finally {
      first.release();
      second.release();
    }
  });

  it("enforces outbox capacity atomically across separate connections", async () => {
    const [first, second] = await database.connectPair();
    try {
      const stores = [
        new PostgresAuthStorage(first).cloudStorage,
        new PostgresAuthStorage(second).cloudStorage
      ] as const;
      await stores[0].clearCloudOutbox(true);
      const user = await createOwnAuth({ storage: new PostgresAuthStorage(first) }).createUser({ email: `capacity-${crypto.randomUUID()}@example.com` });
      const entity = { type: "user", id: user.id } as const;
      const events = [0, 1].map(() => createCloudEvent("app_cloud", {
        type: "user.updated",
        data: { userId: entity.id, email: "user@example.com", authMethods: ["magic_link"] },
        userId: entity.id,
        entity
      }));

      const stored = await Promise.all(events.map((event, index) =>
        stores[index as 0 | 1].enqueueCloudEvent(event, entity, false, 1)
      ));

      expect(stored.filter(Boolean)).toHaveLength(1);
      expect(stored.find(Boolean)?.entityVersion).toBe(1);
      expect(await stores[0].countCloudOutbox(false)).toBe(1);
    } finally {
      first.release();
      second.release();
    }
  });

  it("selects one Cloud configuration value across separate connections", async () => {
    const [first, second] = await database.connectPair();
    try {
      const stores = [
        new PostgresAuthStorage(first).cloudStorage,
        new PostgresAuthStorage(second).cloudStorage
      ] as const;
      const key = `challenge_keys_${crypto.randomUUID()}`;

      const values = await Promise.all([
        stores[0].getOrCreateCloudConfig(key, "first"),
        stores[1].getOrCreateCloudConfig(key, "second")
      ]);

      expect(new Set(values).size).toBe(1);
      expect(await stores[0].getCloudConfig(key)).toBe(values[0]);
    } finally {
      first.release();
      second.release();
    }
  });

  it("backfills active organisation memberships", async () => {
    const storage = new PostgresAuthStorage(database.client);
    const auth = createOwnAuth({
      storage,
      tokenPepper: "postgres-cloud-backfill-token-pepper"
    });
    const signup = await auth.signUpEmailPassword({
      email: `cloud-${crypto.randomUUID()}@example.com`,
      password: "correct-horse"
    });
    const { organisation } = await auth.createOrganisation({
      name: "Cloud backfill",
      ownerUserId: signup.user.id
    });

    const snapshot = await storage.cloudStorage.listCloudSnapshot(null, 500);

    expect(snapshot.records).toContainEqual({
      type: "member",
      entityVersion: 1,
      data: expect.objectContaining({
        orgId: organisation.id,
        userId: signup.user.id,
        role: "owner"
      })
    });
  });

  it("backfills linked providers and enabled authentication factors", async () => {
    const storage = new PostgresAuthStorage(database.client);
    const userId = `usr_cloud_methods_${crypto.randomUUID()}`;
    const now = new Date();
    await database.client.query(
      `insert into own_auth_users
         (id, email, email_verified_at, phone, phone_verified_at, password_hash, name,
          metadata, disabled_at, created_at, updated_at, last_login_at)
       values ($1, $2, null, null, null, $3, null, '{}'::jsonb, null, $4, $4, null)`,
      [userId, `${userId}@example.com`, "hash", now]
    );
    await database.client.query(
      `insert into own_auth_accounts
         (id, user_id, provider, provider_account_id, created_at, updated_at)
       values ($1, $2, 'google', $3, $4, $4)`,
      [`acct_${crypto.randomUUID()}`, userId, `google_${crypto.randomUUID()}`, now]
    );
    await database.client.query(
      `insert into own_auth_mfa_factors
         (id, user_id, factor_type, status, ciphertext, nonce, encryption_key_id,
          created_at, updated_at)
       values ($1, $2, 'totp', 'active', 'ciphertext', 'nonce', 'key', $3, $3)`,
      [`mfa_${crypto.randomUUID()}`, userId, now]
    );
    await database.client.query(
      `insert into own_auth_passkeys
         (id, user_id, credential_id, public_key, counter, transports, device_type,
          backed_up, discoverable, name, metadata, created_at, updated_at)
       values ($1, $2, $3, $4, 0, array[]::text[], 'multiDevice', true, true,
          'Passkey', '{}'::jsonb, $5, $5)`,
      [`passkey_${crypto.randomUUID()}`, userId, `credential_${crypto.randomUUID()}`, Buffer.from("key"), now]
    );

    const snapshot = await storage.cloudStorage.listCloudSnapshot(null, 500);
    const user = snapshot.records.find((record) =>
      record.type === "user" && record.data.userId === userId
    );

    expect(user?.data.authMethods).toEqual([
      "google", "magic_link", "passkey", "password", "totp"
    ]);
  });
});
