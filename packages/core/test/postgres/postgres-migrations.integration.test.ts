import { describe, expect, it } from "vitest";
import { PostgresAuthStorage } from "../../src/postgres/index.js";
import {
  coreMigrationVersions
} from "../../src/core-migrations.js";
import {
  createPostgresTestDatabase,
  hasPostgresTestDatabase
} from "./postgres-test-database.js";

const describeWithDatabase = hasPostgresTestDatabase ? describe : describe.skip;

describeWithDatabase("core Postgres migrations", () => {
  it("invalidates legacy reset links while newly issued links capture the current password version", async () => {
    const now = new Date();
    const database = await createPostgresTestDatabase({
      async afterMigration(file, client) {
        if (file !== "018_cloud.sql") return;
        await client.query(`insert into own_auth_users (id, email, password_hash, created_at, updated_at)
          values ('legacy-reset-user', 'legacy-reset@example.com', 'original-hash', $1, $1)`, [now]);
        await client.query(`insert into own_auth_tokens
          (id, token_hash, type, user_id, email, expires_at, created_at)
          values ('legacy-reset-token', 'legacy-reset-proof', 'password_reset', 'legacy-reset-user',
            'legacy-reset@example.com', $1, $2)`, [new Date(now.getTime() + 60_000), now]);
      }
    });
    try {
      const storage = new PostgresAuthStorage(database.client);
      expect(await storage.getTokenByHash("legacy-reset-proof", "password_reset")).toBeNull();
      const issued = await storage.createToken({ id: "fresh-reset-token", tokenHash: "fresh-reset-proof",
        type: "password_reset", userId: "legacy-reset-user", email: "legacy-reset@example.com",
        phone: null, organisationId: null, expiresAt: new Date(now.getTime() + 60_000), usedAt: null, createdAt: now });
      expect(issued.passwordResetVersion).toBe(1);
      expect(await storage.getTokenByHash("fresh-reset-proof", "password_reset")).not.toBeNull();
      const retained = await database.client.query("select used_at from own_auth_tokens where id = 'legacy-reset-token'");
      expect(retained.rows[0]?.used_at).toBeNull();
    } finally { await database.close(); }
  });

  it("applies every core migration to a fresh database", async () => {
    const database = await createPostgresTestDatabase();

    try {
      const result = await database.client.query<{ version: string }>(
        "select version from own_auth_migrations order by version"
      );

      expect(result.rows.map(({ version }) => version)).toEqual(coreMigrationVersions);
    } finally {
      await database.close();
    }
  });

  it("upgrades sessions from the 0.2.0 schema with safe assurance defaults", async () => {
    const createdAt = new Date("2026-01-01T12:00:00.000Z");
    const database = await createPostgresTestDatabase({
      async afterMigration(file, client) {
        if (file !== "002_external_providers.sql") {
          return;
        }

        await client.query(
          `insert into own_auth_users (
            id, email, password_hash, created_at, updated_at
          ) values ($1, $2, $3, $4, $4)`,
          ["usr_legacy", "legacy@example.com", "legacy-hash", createdAt]
        );
        await client.query(
          `insert into own_auth_sessions (
            id, user_id, token_hash, created_at, last_active_at, expires_at, idle_expires_at
          ) values ($1, $2, $3, $4, $4, $5, $5)`,
          [
            "ses_legacy",
            "usr_legacy",
            "legacy-token-hash",
            createdAt,
            new Date("2026-02-01T12:00:00.000Z")
          ]
        );
      }
    });

    try {
      const result = await database.client.query<{
        assuranceLevel: string;
        authenticatedAt: Date;
        authenticationMethods: string[];
        createdAt: Date;
      }>(
        `select
          authentication_methods as "authenticationMethods",
          assurance_level as "assuranceLevel",
          authenticated_at as "authenticatedAt",
          created_at as "createdAt"
        from own_auth_sessions
        where id = $1`,
        ["ses_legacy"]
      );

      expect(result.rows[0]).toMatchObject({
        assuranceLevel: "aal1",
        authenticationMethods: ["legacy"]
      });
      expect(result.rows[0]?.authenticatedAt).toEqual(result.rows[0]?.createdAt);
    } finally {
      await database.close();
    }
  });

  it("deletes webhook attempts when their delivery is deleted", async () => {
    const database = await createPostgresTestDatabase();

    try {
      const now = new Date("2026-07-15T12:00:00.000Z");
      await database.client.query(
        `insert into own_auth_webhook_events (
           id, event_type, version, payload, created_at
         ) values ($1, $2, 1, $3, $4)`,
        ["evt_AAAAAAAAAAAAAAAAAAAAAA", "user.signed_up", "{}", now]
      );
      await database.client.query(
        `insert into own_auth_webhook_deliveries (
           id, event_id, endpoint_id, endpoint_url, status,
           next_attempt_at, created_at, updated_at
         ) values ($1, $2, $3, $4, 'delivered', $5, $5, $5)`,
        [
          "whd_1",
          "evt_AAAAAAAAAAAAAAAAAAAAAA",
          "public-events",
          "https://hooks.example.com/own-auth",
          now
        ]
      );
      await database.client.query(
        `insert into own_auth_webhook_attempts (
           id, delivery_id, attempt_number, started_at, finished_at,
           outcome, status_code
         ) values ($1, $2, 1, $3, $3, 'delivered', 204)`,
        ["wha_1", "whd_1", now]
      );

      await database.client.query(
        "delete from own_auth_webhook_deliveries where id = $1",
        ["whd_1"]
      );
      const attempts = await database.client.query<{ count: string }>(
        "select count(*) as count from own_auth_webhook_attempts where delivery_id = $1",
        ["whd_1"]
      );

      expect(Number(attempts.rows[0]?.count)).toBe(0);
    } finally {
      await database.close();
    }
  });

  it("preserves existing roles and accepts configured role identifiers", async () => {
    const now = new Date("2026-07-15T12:00:00.000Z");
    const database = await createPostgresTestDatabase({
      async afterMigration(file, client) {
        if (file !== "008_webhooks.sql") return;

        await client.query(
          `insert into own_auth_users (id, email, created_at, updated_at)
           values ($1, $2, $3, $3), ($4, $5, $3, $3)`,
          [
            "usr_role_owner",
            "role-owner@example.com",
            now,
            "usr_role_member",
            "role-member@example.com"
          ]
        );
        await client.query(
          `insert into own_auth_organisations (
             id, name, slug, owner_user_id, created_at, updated_at
           ) values ($1, $2, $3, $4, $5, $5)`,
          ["org_roles", "Role migration", "role-migration", "usr_role_owner", now]
        );
        await client.query(
          `insert into own_auth_organisation_members (
             id, organisation_id, user_id, role, status, joined_at, created_at, updated_at
           ) values ($1, $2, $3, 'admin', 'active', $4, $4, $4)`,
          ["mem_roles", "org_roles", "usr_role_member", now]
        );
        await client.query(
          `insert into own_auth_invitations (
             id, organisation_id, email, role, invited_by_user_id, status, expires_at, created_at
           ) values ($1, $2, $3, 'member', $4, 'pending', $5, $6)`,
          [
            "inv_roles",
            "org_roles",
            "future-member@example.com",
            "usr_role_owner",
            new Date("2026-08-01T12:00:00.000Z"),
            now
          ]
        );
      }
    });

    try {
      await expect(database.client.query(
        "select role from own_auth_organisation_members where id = $1",
        ["mem_roles"]
      )).resolves.toMatchObject({ rows: [{ role: "admin" }] });
      await database.client.query(
        "update own_auth_organisation_members set role = 'reviewer' where id = $1",
        ["mem_roles"]
      );
      await database.client.query(
        "update own_auth_invitations set role = 'content_editor' where id = $1",
        ["inv_roles"]
      );
      await expect(database.client.query(
        `select
           (select role from own_auth_organisation_members where id = $1) as member_role,
           (select role from own_auth_invitations where id = $2) as invitation_role`,
        ["mem_roles", "inv_roles"]
      )).resolves.toMatchObject({
        rows: [{ member_role: "reviewer", invitation_role: "content_editor" }]
      });
      await expect(database.client.query(
        "update own_auth_organisation_members set role = 'Invalid Role' where id = $1",
        ["mem_roles"]
      )).rejects.toThrow();
    } finally {
      await database.close();
    }
  });
});
