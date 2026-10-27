import { describe, expect, it } from "vitest";
import { PostgresAuthStorage } from "../../src/postgres/index.js";
import { PostgresWebhookStorage } from "../../src/postgres/postgres-webhook-storage.js";
import type {
  ApiKey,
  AuditEvent,
  Session,
  User
} from "../../src/index.js";
import type { StoredWebhookEvent } from "../../src/webhook-types.js";
import { RecordingDb } from "./recording-postgres.js";

describe("PostgresAuthStorage", () => {
  it("creates users with parameterized SQL and maps snake-case rows", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    const user = userEntity();
    db.queueRows([userRow()]);

    const created = await storage.createUser(user);

    expect(created).toMatchObject({
      id: "usr_1",
      email: "tina@example.com",
      emailVerifiedAt: new Date("2026-01-01T00:00:00.000Z"),
      phoneVerifiedAt: null,
      metadata: { plan: "pro" }
    });
    expect(db.lastCall.sql).toContain("insert into own_auth_users");
    expect(db.lastCall.sql).toContain("password_hash");
    expect(db.lastCall.sql).not.toContain("hash_1");
    expect(db.lastCall.params).toContain("hash_1");
    expect(db.lastCall.params).toContain(JSON.stringify({ plan: "pro" }));
  });

  it("looks up users by normalized email without interpolating input", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    db.queueRows([userRow({ email: "case@example.com" })]);

    const user = await storage.getUserByEmail("Case@Example.com");

    expect(user?.email).toBe("case@example.com");
    expect(db.lastCall.sql).toContain("where lower(email) = lower($1)");
    expect(db.lastCall.sql).not.toContain("Case@Example.com");
    expect(db.lastCall.params).toEqual(["Case@Example.com"]);
  });

  it("lists users with literal prefix search, status, cursor, and limit parameters", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    const createdAt = new Date("2026-01-01T00:00:00.000Z");
    db.queueRows([userRow()]);

    const users = await storage.listUsers({
      query: "Ali%",
      status: "active",
      cursor: { createdAt, id: "usr_cursor" },
      limit: 51
    });

    expect(users).toHaveLength(1);
    expect(db.lastCall.sql).toContain("lower(substr(coalesce(email, ''), 1, char_length($1)))");
    expect(db.lastCall.sql).not.toContain("like");
    expect(db.lastCall.sql).toContain("disabled_at is null");
    expect(db.lastCall.sql).toContain(
      "(created_at < $2 or (created_at = $2 and id < $3))"
    );
    expect(db.lastCall.sql).toContain("order by created_at desc, id desc limit $4");
    expect(db.lastCall.params).toEqual(["Ali%", createdAt, "usr_cursor", 51]);
  });

  it("keeps empty OAuth credential rotations conditional on the ciphertext", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    db.queueRows([]);

    await expect(
      storage.rotateOAuthCredential("oac_1", "expected-ciphertext", {})
    ).resolves.toBeNull();

    expect(db.lastCall.sql).toContain("where id = $1 and ciphertext = $2");
    expect(db.lastCall.params).toEqual(["oac_1", "expected-ciphertext"]);
  });

  it("updates only provided session fields and maps nullable revoke metadata", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    const revokedAt = new Date("2026-02-01T12:00:00.000Z");
    db.queueRows([
      sessionRow({
        revoked_at: revokedAt,
        revoke_reason: "password_reset"
      })
    ]);

    const session = await storage.updateSession("ses_1", {
      revokedAt,
      revokeReason: "password_reset"
    });

    expect(session).toMatchObject({
      id: "ses_1",
      revokedAt,
      revokeReason: "password_reset"
    });
    expect(db.lastCall.sql).toContain("update own_auth_sessions set revoked_at = $1, revoke_reason = $2 where id = $3");
    expect(db.lastCall.sql).not.toContain("token_hash =");
    expect(db.lastCall.params).toEqual([revokedAt, "password_reset", "ses_1"]);
  });

  it("lists user sessions with a valid select query", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    db.queueRows([sessionRow()]);

    const sessions = await storage.listSessionsByUserId("usr_1");

    expect(sessions).toHaveLength(1);
    expect(sessions[0]?.id).toBe("ses_1");
    expect(db.lastCall.sql).toMatch(/^select id, user_id, token_hash,/);
    expect(db.lastCall.sql).toContain("from own_auth_sessions where user_id = $1");
    expect(db.lastCall.params).toEqual(["usr_1"]);
  });

  it("consumes a token with one conditional update", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    const consumedAt = new Date("2026-01-01T00:05:00.000Z");
    db.queueRows([tokenRow({ used_at: consumedAt })]);

    const token = await storage.consumeToken(
      "token_hash",
      "magic_link",
      consumedAt
    );

    expect(token?.usedAt).toEqual(consumedAt);
    expect(db.lastCall.sql).toContain("update own_auth_tokens");
    expect(db.lastCall.sql).toContain("used_at is null");
    expect(db.lastCall.sql).toContain("expires_at > $3");
    expect(db.lastCall.sql).toContain("returning password_reset_version, id, token_hash");
    expect(db.lastCall.sql).toContain("reset_owner.password_reset_version = own_auth_tokens.password_reset_version");
    expect(db.lastCall.params).toEqual(["token_hash", "magic_link", consumedAt]);
  });

  it("increments OTP attempts only while the credential is usable", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    const attemptedAt = new Date("2026-01-01T00:05:00.000Z");
    db.queueRows([smsOtpRow({ attempts: 1 })]);

    const otp = await storage.incrementSmsOtpAttempts("otp_1", attemptedAt);

    expect(otp?.attempts).toBe(1);
    expect(db.lastCall.sql).toContain("set attempts = attempts + 1");
    expect(db.lastCall.sql).toContain("consumed_at is null");
    expect(db.lastCall.sql).toContain("expires_at > $2");
    expect(db.lastCall.sql).toContain("attempts < max_attempts");
    expect(db.lastCall.params).toEqual(["otp_1", attemptedAt]);
  });

  it("consumes an OTP with one conditional update", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    const consumedAt = new Date("2026-01-01T00:05:00.000Z");
    db.queueRows([smsOtpRow({ attempts: 1, consumed_at: consumedAt })]);

    const otp = await storage.consumeSmsOtp("otp_1", consumedAt);

    expect(otp?.consumedAt).toEqual(consumedAt);
    expect(db.lastCall.sql).toContain("set consumed_at = $2");
    expect(db.lastCall.sql).toContain("attempts = attempts + 1");
    expect(db.lastCall.sql).toContain("consumed_at is null");
    expect(db.lastCall.sql).toContain("attempts < max_attempts");
    expect(db.lastCall.params).toEqual(["otp_1", consumedAt]);
  });

  it("builds valid select SQL for every list query", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    const listCalls: Array<{
      row: Record<string, unknown>;
      run: () => Promise<unknown>;
      sqlFragment: string;
    }> = [
      {
        row: sessionRow(),
        run: () => storage.listSessionsByUserId("usr_1"),
        sqlFragment: "from own_auth_sessions where user_id = $1"
      },
      {
        row: apiKeyRow(),
        run: () => storage.listApiKeysByOrganisationId("org_1"),
        sqlFragment: "from own_auth_api_keys where organisation_id = $1"
      },
      {
        row: apiKeyRow(),
        run: () => storage.listApiKeysByUserId("usr_1"),
        sqlFragment: "from own_auth_api_keys where user_id = $1"
      },
      {
        row: organisationRow(),
        run: () => storage.listOrganisationsByUserId("usr_1"),
        sqlFragment: "from own_auth_organisations where id in"
      },
      {
        row: organisationMemberRow(),
        run: () => storage.listOrganisationMembers("org_1"),
        sqlFragment: "from own_auth_organisation_members where organisation_id = $1"
      },
      {
        row: invitationRow(),
        run: () => storage.listInvitationsByOrganisationId("org_1"),
        sqlFragment: "from own_auth_invitations where organisation_id = $1"
      },
      {
        row: auditEventRow(),
        run: () => storage.listAuditEvents(),
        sqlFragment: "from own_auth_audit_events order by created_at desc"
      }
    ];

    for (const listCall of listCalls) {
      db.queueRows([listCall.row]);
      await listCall.run();
    }

    expect(db.calls).toHaveLength(listCalls.length);

    for (const [index, call] of db.calls.entries()) {
      const expected = listCalls[index];
      if (!expected) {
        throw new Error(`Missing expected SQL assertion for list query ${index}`);
      }

      expect(call.sql).toMatch(/^select /);
      expect(call.sql).toContain(expected.sqlFragment);
      expect(call.sql).not.toMatch(/^id, /);
    }
  });

  it("permanently deletes an organisation and its invitation tokens", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    db.queueRows([{ id: "org_1" }]);

    const deleted = await storage.deleteOrganisation("org_1");

    expect(deleted).toBe(true);
    expect(db.lastCall.sql).toContain(
      "delete from own_auth_tokens where organisation_id = $1"
    );
    expect(db.lastCall.sql).toContain(
      "delete from own_auth_organisations where id = $1 returning id"
    );
    expect(db.lastCall.params).toEqual(["org_1"]);
  });

  it("fetches pending invitations with case-insensitive email matching", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    db.queueRows([invitationRow()]);

    const invitation = await storage.getPendingInvitationByOrganisationAndEmail(
      "org_1",
      "INVITED@EXAMPLE.COM"
    );

    expect(invitation).toMatchObject({
      id: "inv_1",
      organisationId: "org_1",
      email: "invited@example.com",
      status: "pending"
    });
    expect(db.lastCall.sql).toContain("lower(email) = lower($2)");
    expect(db.lastCall.sql).toContain("status = 'pending'");
    expect(db.lastCall.params).toEqual(["org_1", "INVITED@EXAMPLE.COM"]);
  });

  it("fetches an invitation by its token record", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    db.queueRows([invitationRow()]);

    const invitation = await storage.getInvitationByTokenId("tok_1");

    expect(invitation).toMatchObject({ id: "inv_1", tokenId: "tok_1" });
    expect(db.lastCall.sql).toContain("from own_auth_invitations where token_id = $1");
    expect(db.lastCall.params).toEqual(["tok_1"]);
  });

  it("creates API keys with scopes, metadata, and no raw-key interpolation", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    const apiKey = apiKeyEntity();
    db.queueRows([apiKeyRow()]);

    const created = await storage.createApiKey(apiKey);

    expect(created).toMatchObject({
      id: "key_1",
      keyPrefix: "abc12345",
      keyHash: "stored_hash",
      scopes: ["read users"],
      metadata: { environment: "test" }
    });
    expect(db.lastCall.sql).toContain("insert into own_auth_api_keys");
    expect(db.lastCall.sql).not.toContain("stored_hash");
    expect(db.lastCall.params).toContain("stored_hash");
    expect(db.lastCall.params).toContain(JSON.stringify({ environment: "test" }));
  });

  it("builds audit filters with stable parameter ordering", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    db.queueRows([auditEventRow()]);

    const events = await storage.listAuditEvents({
      userId: "usr_1",
      organisationId: "org_1",
      apiKeyId: "key_1"
    });

    expect(events).toHaveLength(1);
    expect(db.lastCall.sql).toMatch(/^select id, event_type,/);
    expect(db.lastCall.sql).toContain("(actor_user_id = $1 or target_user_id = $1)");
    expect(db.lastCall.sql).toContain("organisation_id = $2");
    expect(db.lastCall.sql).toContain("api_key_id = $3");
    expect(db.lastCall.sql).toContain("order by created_at desc");
    expect(db.lastCall.params).toEqual(["usr_1", "org_1", "key_1"]);
  });

  it("paginates audit events with a deterministic cursor", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    const createdAt = new Date("2026-01-01T00:00:00.000Z");
    db.queueRows([auditEventRow()]);

    await storage.listAuditEvents({
      userId: "usr_1",
      cursor: { createdAt, id: "evt_cursor" },
      limit: 51
    });

    expect(db.lastCall.sql).toContain(
      "(created_at < $2 or (created_at = $2 and id < $3))"
    );
    expect(db.lastCall.sql).toContain("order by created_at desc, id desc limit $4");
    expect(db.lastCall.params).toEqual(["usr_1", createdAt, "evt_cursor", 51]);
  });

  it("deletes audit events before a cutoff with parameterized SQL", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db);
    const olderThan = new Date("2026-01-01T00:00:00.000Z");
    db.queueRows([{ id: "evt_1" }, { id: "evt_2" }]);

    const deleted = await storage.deleteAuditEventsBefore(olderThan);

    expect(deleted).toBe(2);
    expect(db.lastCall.sql).toBe(
      "delete from own_auth_audit_events where created_at < $1 returning id"
    );
    expect(db.lastCall.params).toEqual([olderThan]);
  });
});

describe("PostgresWebhookStorage", () => {
  it("writes the audit event and webhook outbox with one atomic statement", async () => {
    const db = new RecordingDb();
    const storage = new PostgresWebhookStorage(db);

    await storage.recordAuditEventWithWebhooks(
      webhookAuditEvent(),
      storedWebhookEvent(),
      [{
        id: "whd_1",
        endpointId: "public-events",
        url: "https://hooks.example.com/own-auth",
        createdAt: new Date("2026-01-01T00:00:00.000Z")
      }]
    );

    expect(db.calls).toHaveLength(1);
    expect(db.lastCall.sql).toContain("with inserted_audit as");
    expect(db.lastCall.sql).toContain("insert into own_auth_webhook_events");
    expect(db.lastCall.sql).toContain("insert into own_auth_webhook_deliveries");
    expect(db.lastCall.sql).toContain("jsonb_to_recordset");
    expect(JSON.stringify(db.lastCall.params)).toContain("https://hooks.example.com/own-auth");
  });

  it("claims due deliveries with row locks and settles attempts conditionally", async () => {
    const db = new RecordingDb();
    const storage = new PostgresWebhookStorage(db);
    const now = new Date("2026-01-01T00:00:00.000Z");
    db.queueRows([]);

    await storage.claimWebhookDeliveries({
      now,
      leaseToken: "lease_1",
      leaseExpiresAt: new Date(now.getTime() + 30_000),
      limit: 10
    });

    expect(db.lastCall.sql).toContain("for update skip locked");
    expect(db.lastCall.sql).toContain("lease_token = $3");

    db.queueRows([{ id: "wha_1" }]);
    await expect(storage.settleWebhookDelivery({
      deliveryId: "whd_1",
      leaseToken: "lease_1",
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

    expect(db.lastCall.sql).toContain("total_attempts = $3");
    expect(db.lastCall.sql).toContain("insert into own_auth_webhook_attempts");
  });
});

function userEntity(): User {
  return {
    id: "usr_1",
    email: "tina@example.com",
    emailVerifiedAt: new Date("2026-01-01T00:00:00.000Z"),
    phone: "+15551234567",
    phoneVerifiedAt: null,
    passwordHash: "hash_1",
    name: "Tina",
    imageUrl: null,
    disabledAt: null,
    metadata: { plan: "pro" },
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
    updatedAt: new Date("2026-01-01T00:00:00.000Z"),
    lastLoginAt: null
  };
}

function apiKeyEntity(): ApiKey {
  return {
    id: "key_1",
    keyPrefix: "abc12345",
    keyHash: "stored_hash",
    name: "Worker",
    userId: "usr_1",
    organisationId: "org_1",
    scopes: ["read users"],
    status: "active",
    expiresAt: null,
    lastUsedAt: null,
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
    revokedAt: null,
    revokedBy: null,
    metadata: { environment: "test" }
  };
}

function userRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "usr_1",
    email: "tina@example.com",
    email_verified_at: "2026-01-01T00:00:00.000Z",
    phone: "+15551234567",
    phone_verified_at: null,
    password_hash: "hash_1",
    name: "Tina",
    image_url: null,
    disabled_at: null,
    metadata: { plan: "pro" },
    created_at: "2026-01-01T00:00:00.000Z",
    updated_at: "2026-01-01T00:00:00.000Z",
    last_login_at: null,
    ...overrides
  };
}

function sessionRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "ses_1",
    user_id: "usr_1",
    token_hash: "session_hash",
    created_at: "2026-01-01T00:00:00.000Z",
    last_active_at: "2026-01-01T00:00:00.000Z",
    expires_at: "2026-02-01T00:00:00.000Z",
    idle_expires_at: "2026-01-08T00:00:00.000Z",
    ip_address: "127.0.0.1",
    user_agent: "vitest",
    revoked_at: null,
    revoke_reason: null,
    authentication_methods: ["legacy"],
    assurance_level: "aal1",
    authenticated_at: "2026-01-01T00:00:00.000Z",
    ...overrides
  };
}

function tokenRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "tok_1",
    token_hash: "token_hash",
    type: "magic_link",
    user_id: "usr_1",
    email: "tina@example.com",
    phone: null,
    organisation_id: null,
    expires_at: "2026-01-01T00:15:00.000Z",
    used_at: null,
    created_at: "2026-01-01T00:00:00.000Z",
    ...overrides
  };
}

function smsOtpRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "otp_1",
    phone: "+15551234567",
    user_id: "usr_1",
    code_hash: "code_hash",
    purpose: "phone_login",
    expires_at: "2026-01-01T00:10:00.000Z",
    attempts: 0,
    max_attempts: 3,
    consumed_at: null,
    created_at: "2026-01-01T00:00:00.000Z",
    last_sent_at: "2026-01-01T00:00:00.000Z",
    ...overrides
  };
}

function invitationRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "inv_1",
    token_id: "tok_1",
    organisation_id: "org_1",
    email: "invited@example.com",
    phone: null,
    role: "member",
    invited_by_user_id: "usr_1",
    status: "pending",
    expires_at: "2026-01-08T00:00:00.000Z",
    accepted_at: null,
    revoked_at: null,
    created_at: "2026-01-01T00:00:00.000Z",
    ...overrides
  };
}

function apiKeyRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "key_1",
    key_prefix: "abc12345",
    key_hash: "stored_hash",
    name: "Worker",
    user_id: "usr_1",
    organisation_id: "org_1",
    scopes: ["read users"],
    status: "active",
    expires_at: null,
    last_used_at: null,
    created_at: "2026-01-01T00:00:00.000Z",
    revoked_at: null,
    revoked_by: null,
    metadata: { environment: "test" },
    ...overrides
  };
}

function organisationRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "org_1",
    name: "Example Org",
    slug: "example-org",
    owner_user_id: "usr_1",
    metadata: {},
    created_at: "2026-01-01T00:00:00.000Z",
    updated_at: "2026-01-01T00:00:00.000Z",
    disabled_at: null,
    ...overrides
  };
}

function organisationMemberRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "mem_1",
    organisation_id: "org_1",
    user_id: "usr_1",
    role: "owner",
    status: "active",
    joined_at: "2026-01-01T00:00:00.000Z",
    removed_at: null,
    created_at: "2026-01-01T00:00:00.000Z",
    updated_at: "2026-01-01T00:00:00.000Z",
    ...overrides
  };
}

function auditEventRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "evt_1",
    event_type: "api_key.used",
    actor_user_id: "usr_1",
    target_user_id: "usr_1",
    organisation_id: "org_1",
    api_key_id: "key_1",
    ip_address: null,
    user_agent: null,
    metadata: { requiredScopes: ["read users"] },
    created_at: "2026-01-01T00:00:00.000Z",
    ...overrides
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
    createdAt: new Date("2026-01-01T00:00:00.000Z")
  };
}

function storedWebhookEvent(): StoredWebhookEvent {
  return {
    id: "evt_1",
    type: "user.signed_up",
    version: 1,
    payload: '{"id":"evt_1","type":"user.signed_up"}',
    createdAt: new Date("2026-01-01T00:00:00.000Z")
  };
}
