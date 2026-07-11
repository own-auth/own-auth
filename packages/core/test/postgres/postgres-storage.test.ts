import { describe, expect, it } from "vitest";
import { PostgresAuthStorage, type PostgresQueryable } from "../../src/postgres/index.js";
import type { ApiKey, Session, User } from "../../src/index.js";

interface QueryCall {
  sql: string;
  params: readonly unknown[];
}

class RecordingDb implements PostgresQueryable {
  readonly calls: QueryCall[] = [];
  private readonly queuedRows: Record<string, unknown>[][] = [];

  queueRows(rows: Record<string, unknown>[]): void {
    this.queuedRows.push(rows);
  }

  async query<Row = Record<string, unknown>>(
    sql: string,
    params: readonly unknown[] = []
  ): Promise<{ rows: Row[] }> {
    this.calls.push({ sql, params });
    return {
      rows: (this.queuedRows.shift() ?? []) as Row[]
    };
  }

  get lastCall(): QueryCall {
    const call = this.calls.at(-1);
    if (!call) {
      throw new Error("No query call was recorded");
    }

    return call;
  }
}

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
