import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createDeviceFlowClient,
  DeviceFlowClientError
} from "../src/device-authorization.js";

describe("device authorization client", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("rejects plaintext non-local authorization endpoints", () => {
    const options = {
      tokenEndpoint: "https://auth.example.com/oauth/token",
      clientId: "oa_client_example",
      fetch: vi.fn<typeof globalThis.fetch>()
    };

    expect(() => createDeviceFlowClient({
      ...options,
      deviceAuthorizationEndpoint: "http://auth.example.com/oauth/device/authorize"
    })).toThrow(
      "deviceAuthorizationEndpoint must be an HTTPS or local development URL without a query or fragment"
    );
    expect(() => createDeviceFlowClient({
      ...options,
      deviceAuthorizationEndpoint: "http://localhost:3000/oauth/device/authorize",
      tokenEndpoint: "http://localhost:3000/oauth/token"
    })).not.toThrow();
  });

  it("accepts an RFC response without verification_uri_complete", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () => Response.json({
      device_code: "oa_dc_example",
      user_code: "BCDF-GHJK",
      verification_uri: "https://auth.example.com/device",
      expires_in: 600,
      interval: 5
    }));
    const client = createDeviceFlowClient({
      deviceAuthorizationEndpoint: "https://auth.example.com/oauth/device/authorize",
      tokenEndpoint: "https://auth.example.com/oauth/token",
      clientId: "oa_client_example",
      fetch
    });

    const authorization = await client.start({ scope: ["openid"] });
    expect(authorization).toMatchObject({
      deviceCode: "oa_dc_example",
      userCode: "BCDF-GHJK",
      verificationUri: "https://auth.example.com/device",
      scopes: ["openid"]
    });
    expect(authorization.verificationUriComplete).toBeUndefined();
  });

  it("continues through pending and slow-down responses", async () => {
    vi.useFakeTimers();
    const responses = [
      Response.json({ error: "authorization_pending" }, { status: 400 }),
      Response.json({ error: "slow_down" }, { status: 400 }),
      Response.json({
        token_type: "bearer",
        access_token: "oa_at_example",
        expires_in: 300
      })
    ];
    const fetch = vi.fn<typeof globalThis.fetch>(async () => responses.shift()!);
    const client = createDeviceFlowClient({
      deviceAuthorizationEndpoint: "https://auth.example.com/oauth/device/authorize",
      tokenEndpoint: "https://auth.example.com/oauth/token",
      clientId: "oa_client_example",
      fetch
    });
    const result = client.poll({
      authorization: {
        deviceCode: "oa_dc_example",
        userCode: "BCDF-GHJK",
        verificationUri: "https://auth.example.com/device",
        scopes: ["openid"],
        expiresAt: new Date(Date.now() + 30_000),
        intervalSeconds: 1
      }
    });

    await vi.advanceTimersByTimeAsync(1_000);
    await vi.advanceTimersByTimeAsync(1_000);
    await vi.advanceTimersByTimeAsync(6_000);
    await expect(result).resolves.toMatchObject({
      accessToken: "oa_at_example",
      tokenType: "Bearer",
      scopes: ["openid"]
    });
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it("exposes only RFC device errors to callers", async () => {
    vi.useFakeTimers();
    const client = createDeviceFlowClient({
      deviceAuthorizationEndpoint: "https://auth.example.com/oauth/device/authorize",
      tokenEndpoint: "https://auth.example.com/oauth/token",
      clientId: "oa_client_example",
      fetch: async () => Response.json({ error: "access_denied" }, { status: 400 })
    });
    const result = client.poll({
      authorization: {
        deviceCode: "oa_dc_example",
        userCode: "BCDF-GHJK",
        verificationUri: "https://auth.example.com/device",
        scopes: ["openid"],
        expiresAt: new Date(Date.now() + 10_000),
        intervalSeconds: 1
      }
    });
    const rejection = expect(result).rejects.toEqual(expect.objectContaining({
      code: "access_denied"
    } satisfies Partial<DeviceFlowClientError>));

    await vi.advanceTimersByTimeAsync(1_000);
    await rejection;
  });
});
