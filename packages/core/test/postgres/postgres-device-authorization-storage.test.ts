import { describe, expect, it } from "vitest";
import { PostgresAuthStorage } from "../../src/postgres/index.js";
import {
  deviceAccessToken,
  deviceAuthorization,
  deviceAuthorizationRow,
  deviceFixtureNow
} from "../helpers/device-authorization.js";
import { RecordingDb } from "./recording-postgres.js";

describe("Postgres device authorization storage", () => {
  it("maps device records while storing only code hashes", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db).authorizationServerStorage
      .deviceAuthorizationStorage;
    db.queueRows([deviceAuthorizationRow("postgres")]);

    await expect(storage.createDeviceAuthorization(deviceAuthorization())).resolves
      .toMatchObject({ deviceCodeHash: "device-code-hash", userCodeHash: "user-code-hash" });
    expect(db.lastCall.sql).toContain("insert into own_auth_device_authorizations");
    expect(db.lastCall.params).toContain("device-code-hash");
    expect(db.lastCall.params).toContain("user-code-hash");
    expect(JSON.stringify(db.lastCall)).not.toContain("oa_dc_");
  });

  it("consumes the device record and creates tokens in one statement", async () => {
    const db = new RecordingDb();
    const storage = new PostgresAuthStorage(db).authorizationServerStorage
      .deviceAuthorizationStorage;
    db.queueRows([{ id: "oda_1" }]);

    await expect(storage.consumeDeviceAuthorization({
      id: "oda_1",
      deviceCodeHash: "device-code-hash",
      authorizationClientId: "ocli_1",
      consumedAt: deviceFixtureNow,
      accessToken: deviceAccessToken(),
      refreshToken: null
    })).resolves.toBe(true);
    expect(db.calls).toHaveLength(1);
    expect(db.lastCall.sql).toContain("with consumed as");
    expect(db.lastCall.sql).toContain("select $5,$6,$7");
    expect(db.lastCall.sql).toContain("from consumed");
    expect(db.lastCall.sql).toContain("status = 'approved'");
  });
});
