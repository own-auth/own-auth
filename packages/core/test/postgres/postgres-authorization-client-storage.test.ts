import { describe, expect, it } from "vitest";
import {
  deviceAuthorizationGrantType,
  type AuthorizationClient
} from "../../src/index.js";
import { PostgresAuthStorage } from "../../src/postgres/index.js";
import { RecordingDb } from "./recording-postgres.js";

describe("Postgres authorization client storage", () => {
  it("persists grant types when creating a confidential client", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db).authorizationServerStorage;
    const now = new Date("2026-07-18T12:00:00.000Z");
    const client: AuthorizationClient = {
      id: "ocli_1",
      clientId: "oa_client_cli",
      name: "CLI",
      clientType: "confidential",
      applicationType: "native",
      tokenEndpointAuthMethod: "client_secret_post",
      redirectUris: [],
      allowedScopes: ["openid"],
      grantTypes: [deviceAuthorizationGrantType],
      dpopBoundAccessTokens: false,
      status: "active",
      createdAt: now,
      updatedAt: now,
      revokedAt: null
    };
    db.queueRows([{
      id: client.id,
      client_id: client.clientId,
      name: client.name,
      client_type: client.clientType,
      application_type: client.applicationType,
      token_endpoint_auth_method: client.tokenEndpointAuthMethod,
      redirect_uris: client.redirectUris,
      allowed_scopes: client.allowedScopes,
      grant_types: client.grantTypes,
      dpop_bound_access_tokens: client.dpopBoundAccessTokens,
      status: client.status,
      created_at: client.createdAt,
      updated_at: client.updatedAt,
      revoked_at: client.revokedAt
    }]);

    await expect(storage.createAuthorizationClient(client, {
      id: "oclsec_1",
      authorizationClientId: client.id,
      prefix: "oa_cs_example",
      secretHash: "secret-hash",
      createdAt: now,
      expiresAt: null,
      revokedAt: null
    })).resolves.toMatchObject({ grantTypes: [deviceAuthorizationGrantType] });

    expect(db.lastCall.sql).toContain("grant_types, dpop_bound_access_tokens");
    expect(db.lastCall.params[8]).toEqual([deviceAuthorizationGrantType]);
    expect(db.lastCall.sql).toContain("values ($15,$16,$17,$18,$19,$20,$21)");
  });
});
