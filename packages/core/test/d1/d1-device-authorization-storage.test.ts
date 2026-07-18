import { describe, expect, it, vi } from "vitest";
import { D1AuthStorage } from "../../src/d1/index.js";
import {
  deviceAccessToken,
  deviceAuthorization,
  deviceAuthorizationRow,
  deviceFixtureNow
} from "../helpers/device-authorization.js";
import { RecordingD1 } from "./recording-d1.js";

describe("D1 device authorization storage", () => {
  it("maps JSON arrays and stores only code hashes", async () => {
    const database = new RecordingD1();
    const storage = new D1AuthStorage(database).authorizationServerStorage
      .deviceAuthorizationStorage;
    database.queue([deviceAuthorizationRow("d1")]);

    await expect(storage.createDeviceAuthorization(deviceAuthorization())).resolves
      .toMatchObject({ deviceCodeHash: "device-code-hash", approvedScopes: [] });
    expect(database.calls[0]?.values).toContain("device-code-hash");
    expect(database.calls[0]?.values).toContain("user-code-hash");
    expect(JSON.stringify(database.calls[0])).not.toContain("oa_dc_");
  });

  it("uses one D1 batch to create the token and consume the device record", async () => {
    const database = new RecordingD1();
    const batch = vi.spyOn(database, "batch");
    const storage = new D1AuthStorage(database).authorizationServerStorage
      .deviceAuthorizationStorage;
    database.queue([]);
    database.queue([{ id: "oda_1" }]);

    await expect(storage.consumeDeviceAuthorization({
      id: "oda_1",
      deviceCodeHash: "device-code-hash",
      authorizationClientId: "ocli_1",
      consumedAt: deviceFixtureNow,
      accessToken: deviceAccessToken(),
      refreshToken: null
    })).resolves.toBe(true);
    expect(batch).toHaveBeenCalledTimes(1);
    expect(database.calls).toHaveLength(2);
    expect(database.calls[0]?.sql).toContain("status = 'approved'");
    expect(database.calls[1]?.sql).toContain("status = 'consumed'");
    expect(database.calls[1]?.sql).toContain("exists (");
  });
});
