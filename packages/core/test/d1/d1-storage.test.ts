import { describe, expect, it } from "vitest";
import { AuthError } from "../../src/errors.js";
import {
  D1AuthStorage,
  D1RateLimitStore,
  createD1Persistence,
  type D1BindableValue,
  type D1DatabaseLike,
  type D1PreparedStatementLike,
  type D1ResultLike
} from "../../src/d1/index.js";
import { D1WebhookStorage } from "../../src/d1/d1-webhook-storage.js";
import type { Account, AuditEvent, User } from "../../src/types.js";
import type { StoredWebhookEvent } from "../../src/webhook-types.js";

interface D1Call {
  sql: string;
  values: readonly D1BindableValue[];
}

class RecordingD1 implements D1DatabaseLike {
  readonly calls: D1Call[] = [];
  readonly responses: Array<D1ResultLike> = [];
  batchError: Error | null = null;

  prepare(sql: string): D1PreparedStatementLike {
    return new RecordingStatement(this, sql);
  }

  async batch<Row>(statements: D1PreparedStatementLike[]): Promise<D1ResultLike<Row>[]> {
    if (this.batchError) throw this.batchError;
    return statements.map((statement) => {
      const recorded = statement as RecordingStatement;
      this.calls.push({ sql: recorded.sql, values: recorded.values });
      return (this.responses.shift() ?? { success: true, results: [] }) as D1ResultLike<Row>;
    });
  }

  queue(rows: Record<string, unknown>[]): void {
    this.responses.push({ success: true, results: rows });
  }

  next<Row>(): D1ResultLike<Row> {
    return (this.responses.shift() ?? { success: true, results: [] }) as D1ResultLike<Row>;
  }
}

class RecordingStatement implements D1PreparedStatementLike {
  values: D1BindableValue[] = [];

  constructor(readonly database: RecordingD1, readonly sql: string) {}

  bind(...values: D1BindableValue[]): D1PreparedStatementLike {
    this.values = values;
    return this;
  }

  async first<Row>(): Promise<Row | null> {
    const result = this.record<Row>();
    return result.results?.[0] ?? null;
  }

  async all<Row>(): Promise<D1ResultLike<Row>> {
    return this.record<Row>();
  }

  async run<Row>(): Promise<D1ResultLike<Row>> {
    return this.record<Row>();
  }

  private record<Row>(): D1ResultLike<Row> {
    this.database.calls.push({ sql: this.sql, values: this.values });
    return this.database.next<Row>();
  }
}

describe("D1 persistence", () => {
  it("creates users with parameterized SQL and maps SQLite rows", async () => {
    const database = new RecordingD1();
    const storage = new D1AuthStorage(database);
    const user = userEntity();
    database.queue([userRow()]);

    const created = await storage.createUser(user);

    expect(created).toMatchObject({
      id: "usr_1",
      email: "alice@example.com",
      emailVerifiedAt: null,
      metadata: { plan: "pro" }
    });
    expect(database.calls[0]?.sql).toContain("insert into own_auth_users");
    expect(database.calls[0]?.sql).not.toContain("hash_1");
    expect(database.calls[0]?.values).toContain("hash_1");
    expect(database.calls[0]?.values).toContain('{"plan":"pro"}');
    expect(database.calls[0]?.values).toContain(user.createdAt.getTime());
  });

  it("lists users with literal prefix search, status, cursor, and limit bindings", async () => {
    const database = new RecordingD1();
    const storage = new D1AuthStorage(database);
    const createdAt = new Date("2026-07-15T12:00:00.000Z");
    database.queue([userRow()]);

    const users = await storage.listUsers({
      query: "Ali%",
      status: "disabled",
      cursor: { createdAt, id: "usr_cursor" },
      limit: 51
    });

    expect(users).toHaveLength(1);
    expect(database.calls[0]?.sql).toContain(
      "lower(substr(coalesce(email, ''), 1, length(?1)))"
    );
    expect(database.calls[0]?.sql).not.toContain("like");
    expect(database.calls[0]?.sql).toContain("disabled_at is not null");
    expect(database.calls[0]?.sql).toContain(
      "(created_at < ?2 or (created_at = ?2 and id < ?3))"
    );
    expect(database.calls[0]?.sql).toContain("order by created_at desc, id desc limit ?4");
    expect(database.calls[0]?.values).toEqual([
      "Ali%",
      createdAt.getTime(),
      "usr_cursor",
      51
    ]);
  });

  it("paginates audit events with a deterministic cursor", async () => {
    const database = new RecordingD1();
    const storage = new D1AuthStorage(database);
    const createdAt = new Date("2026-07-15T12:00:00.000Z");
    database.queue([auditEventRow()]);

    const events = await storage.listAuditEvents({
      userId: "usr_1",
      cursor: { createdAt, id: "evt_cursor" },
      limit: 51
    });

    expect(events).toHaveLength(1);
    expect(database.calls[0]?.sql).toContain(
      "(created_at < ?2 or (created_at = ?2 and id < ?3))"
    );
    expect(database.calls[0]?.sql).toContain("order by created_at desc, id desc limit ?4");
    expect(database.calls[0]?.values).toEqual([
      "usr_1",
      createdAt.getTime(),
      "evt_cursor",
      51
    ]);
  });

  it("consumes a token with one conditional update", async () => {
    const database = new RecordingD1();
    const storage = new D1AuthStorage(database);
    const consumedAt = new Date("2026-07-15T12:05:00.000Z");
    database.queue([tokenRow(consumedAt.getTime())]);

    const token = await storage.consumeToken("token_hash", "magic_link", consumedAt);

    expect(token?.usedAt).toEqual(consumedAt);
    expect(database.calls[0]?.sql).toContain("used_at is null");
    expect(database.calls[0]?.sql).toContain("expires_at > ?3");
    expect(database.calls[0]?.values).toEqual([
      "token_hash",
      "magic_link",
      consumedAt.getTime()
    ]);
  });

  it("keeps empty OAuth credential rotations conditional on the ciphertext", async () => {
    const database = new RecordingD1();
    const storage = new D1AuthStorage(database);
    database.queue([]);

    await expect(
      storage.rotateOAuthCredential("oac_1", "expected-ciphertext", {})
    ).resolves.toBeNull();

    expect(database.calls[0]?.sql).toContain("where id = ?1 and ciphertext = ?2");
    expect(database.calls[0]?.values).toEqual(["oac_1", "expected-ciphertext"]);
  });

  it("rotates authorization refresh tokens in one conditional D1 batch", async () => {
    const database = new RecordingD1();
    const storage = new D1AuthStorage(database).authorizationServerStorage;
    const now = new Date("2026-07-15T12:05:00.000Z");
    database.queue([{ grant_id: "ogrant_1" }]);
    database.queue([]);
    database.queue([]);

    await expect(storage.rotateAuthorizationRefreshToken({
      tokenHash: "refresh_hash_old",
      authorizationClientId: "ocli_1",
      replacementRefreshToken: authorizationRefreshToken(),
      accessToken: authorizationAccessToken(),
      rotatedAt: now
    })).resolves.toBe("rotated");

    expect(database.calls).toHaveLength(3);
    expect(database.calls[0]?.sql).toContain("consumed_at is null");
    expect(database.calls[0]?.sql).toContain("replaced_by_token_id is null");
    expect(database.calls[1]?.sql).toContain(
      "insert into own_auth_authorization_refresh_tokens"
    );
    expect(database.calls[2]?.sql).toContain(
      "insert into own_auth_authorization_access_tokens"
    );
  });

  it("revokes the D1 authorization grant family after refresh-token reuse", async () => {
    const database = new RecordingD1();
    const storage = new D1AuthStorage(database).authorizationServerStorage;
    database.queue([]);
    database.queue([]);
    database.queue([]);
    database.queue([{ id: "ogrant_1" }]);
    database.queue([]);
    database.queue([]);

    await expect(storage.rotateAuthorizationRefreshToken({
      tokenHash: "refresh_hash_old",
      authorizationClientId: "ocli_1",
      replacementRefreshToken: authorizationRefreshToken(),
      accessToken: authorizationAccessToken(),
      rotatedAt: new Date("2026-07-15T12:05:00.000Z")
    })).resolves.toBe("reused");

    expect(database.calls).toHaveLength(6);
    expect(database.calls[3]?.sql).toContain(
      "update own_auth_authorization_grants"
    );
    expect(database.calls[4]?.sql).toContain(
      "update own_auth_authorization_access_tokens"
    );
    expect(database.calls[5]?.sql).toContain(
      "update own_auth_authorization_refresh_tokens"
    );
    expect(database.calls[5]?.sql).not.toContain(
      "authorization_client_id = ?2\n           and revoked_at is null"
    );
  });

  it("maps D1 identity collisions to typed Own Auth errors", async () => {
    const database = new RecordingD1();
    const storage = new D1AuthStorage(database);
    database.batchError = new Error(
      "D1_ERROR: UNIQUE constraint failed: index 'own_auth_users_email_unique'"
    );

    await expect(storage.createUserAndAccount(userEntity(), accountEntity())).rejects.toMatchObject({
      code: "email_already_exists",
      statusCode: 409
    } satisfies Partial<AuthError>);
  });

  it("uses the same D1 binding for auth data and rate limits", async () => {
    const database = new RecordingD1();
    const persistence = createD1Persistence(database);
    database.queue([{ count: 1, reset_at: 1_786_291_260_000 }]);

    await persistence.rateLimitStore.hit("signin:alice@example.com", 60_000, 3);

    expect(persistence.storage).toBeInstanceOf(D1AuthStorage);
    expect(persistence.rateLimitStore).toBeInstanceOf(D1RateLimitStore);
    expect(database.calls[0]?.sql).toContain("own_auth_rate_limits");
    expect(database.calls[0]?.values[0]).toBe("signin:alice@example.com");
  });

  it("writes the audit event and webhook outbox in one D1 batch", async () => {
    const database = new RecordingD1();
    const storage = new D1WebhookStorage(database);

    await storage.recordAuditEventWithWebhooks(
      webhookAuditEvent(),
      storedWebhookEvent(),
      [{
        id: "whd_1",
        endpointId: "public-events",
        url: "https://hooks.example.com/own-auth",
        createdAt: new Date("2026-07-15T12:00:00.000Z")
      }]
    );

    expect(database.calls).toHaveLength(3);
    expect(database.calls[0]?.sql).toContain("insert into own_auth_audit_events");
    expect(database.calls[1]?.sql).toContain("insert into own_auth_webhook_events");
    expect(database.calls[2]?.sql).toContain("insert into own_auth_webhook_deliveries");
    expect(database.calls[2]?.values).toContain("https://hooks.example.com/own-auth");
  });

  it("settles webhook attempts under the claimed lease", async () => {
    const database = new RecordingD1();
    const storage = new D1WebhookStorage(database);
    const now = new Date("2026-07-15T12:00:00.000Z");
    database.queue([]);
    database.queue([{ id: "wha_1" }]);
    database.queue([]);

    await expect(storage.settleWebhookDelivery({
      deliveryId: "whd_1",
      leaseToken: "whl_1",
      expectedTotalAttempts: 0,
      attempt: {
        id: "wha_1",
        deliveryId: "whd_1",
        attemptNumber: 1,
        startedAt: now,
        finishedAt: now,
        outcome: "delivered",
        statusCode: 204,
        errorCode: null,
        nextRetryAt: null
      },
      status: "delivered",
      nextAttemptAt: now
    })).resolves.toBe(true);

    expect(database.calls).toHaveLength(3);
    expect(database.calls[1]?.sql).toContain("lease_token = ?12");
    expect(database.calls[1]?.values[11]).toBe("whl_1");
    expect(database.calls[2]?.sql).toContain("set lease_token = null");
  });
});

function userEntity(): User {
  const now = new Date("2026-07-15T12:00:00.000Z");
  return {
    id: "usr_1",
    email: "alice@example.com",
    emailVerifiedAt: null,
    phone: null,
    phoneVerifiedAt: null,
    passwordHash: "hash_1",
    name: "Alice",
    imageUrl: null,
    disabledAt: null,
    metadata: { plan: "pro" },
    createdAt: now,
    updatedAt: now,
    lastLoginAt: null
  };
}

function accountEntity(): Account {
  return {
    id: "acc_1",
    userId: "usr_1",
    provider: "password",
    providerAccountId: "alice@example.com",
    providerEmail: "alice@example.com",
    providerPhone: null,
    createdAt: new Date("2026-07-15T12:00:00.000Z"),
    updatedAt: new Date("2026-07-15T12:00:00.000Z")
  };
}

function userRow(): Record<string, unknown> {
  return {
    id: "usr_1",
    email: "alice@example.com",
    email_verified_at: null,
    phone: null,
    phone_verified_at: null,
    password_hash: "hash_1",
    name: "Alice",
    image_url: null,
    disabled_at: null,
    metadata: '{"plan":"pro"}',
    created_at: 1_752_580_800_000,
    updated_at: 1_752_580_800_000,
    last_login_at: null
  };
}

function tokenRow(usedAt: number): Record<string, unknown> {
  return {
    id: "tok_1",
    token_hash: "token_hash",
    type: "magic_link",
    user_id: "usr_1",
    email: "alice@example.com",
    phone: null,
    organisation_id: null,
    expires_at: usedAt + 60_000,
    used_at: usedAt,
    created_at: usedAt - 60_000
  };
}

function authorizationAccessToken() {
  return {
    id: "oat_1",
    tokenHash: "access_hash_1",
    prefix: "oa_at_1",
    grantId: "ogrant_1",
    authorizationClientId: "ocli_1",
    userId: "usr_1",
    scopes: ["openid", "offline_access"],
    expiresAt: new Date("2026-07-15T13:00:00.000Z"),
    revokedAt: null,
    createdAt: new Date("2026-07-15T12:05:00.000Z")
  };
}

function authorizationRefreshToken() {
  return {
    id: "ort_2",
    tokenHash: "refresh_hash_2",
    prefix: "oa_rt_2",
    grantId: "ogrant_1",
    authorizationClientId: "ocli_1",
    userId: "usr_1",
    scopes: ["openid", "offline_access"],
    generation: 1,
    replacedByTokenId: null,
    expiresAt: new Date("2026-08-15T12:05:00.000Z"),
    consumedAt: null,
    revokedAt: null,
    createdAt: new Date("2026-07-15T12:05:00.000Z")
  };
}

function auditEventRow(): Record<string, unknown> {
  return {
    id: "evt_1",
    event_type: "user.signed_in",
    actor_user_id: "usr_1",
    target_user_id: "usr_1",
    organisation_id: null,
    api_key_id: null,
    ip_address: null,
    user_agent: null,
    metadata: '{"method":"password"}',
    created_at: 1_752_580_800_000
  };
}

function webhookAuditEvent(): AuditEvent {
  return {
    id: "evt_1",
    eventType: "user.signed_up",
    actorUserId: "usr_1",
    targetUserId: "usr_1",
    organisationId: null,
    apiKeyId: null,
    ipAddress: null,
    userAgent: null,
    metadata: { provider: "password" },
    createdAt: new Date("2026-07-15T12:00:00.000Z")
  };
}

function storedWebhookEvent(): StoredWebhookEvent {
  return {
    id: "evt_1",
    type: "user.signed_up",
    version: 1,
    payload: '{"id":"evt_1","type":"user.signed_up"}',
    createdAt: new Date("2026-07-15T12:00:00.000Z")
  };
}
