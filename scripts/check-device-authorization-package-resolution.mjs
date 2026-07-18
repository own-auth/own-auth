import { pathToFileURL } from "node:url";
import {
  checkPackageResolution,
  repositoryRoot
} from "./package-resolution-check.mjs";

const guardUrl = pathToFileURL(
  `${repositoryRoot}/scripts/portable-subpath-import-guard.mjs`
).href;

await checkPackageResolution({
  fixturePrefix: "own-auth-device-authorization-resolution-",
  typeScriptSource: `import {
  createDeviceFlowClient,
  type DeviceFlowAuthorization,
  type DeviceFlowTokenResponse
} from "own-auth/device-authorization";

const client = createDeviceFlowClient({
  deviceAuthorizationEndpoint: "https://auth.example.com/oauth/device/authorize",
  tokenEndpoint: "https://auth.example.com/oauth/token",
  clientId: "oa_client_example"
});
declare const authorization: DeviceFlowAuthorization;
declare const tokens: DeviceFlowTokenResponse;
void client;
void authorization;
void tokens;
`,
  runtimeSource: `import { register } from "node:module";
register(${JSON.stringify(guardUrl)}, import.meta.url);
const { createDeviceFlowClient } = await import("own-auth/device-authorization");
const client = createDeviceFlowClient({
  deviceAuthorizationEndpoint: "https://auth.example.com/oauth/device/authorize",
  tokenEndpoint: "https://auth.example.com/oauth/token",
  clientId: "oa_client_example",
  fetch: async () => Response.json({
    device_code: "oa_dc_example",
    user_code: "BCDF-GHJK",
    verification_uri: "https://auth.example.com/device",
    expires_in: 600,
    interval: 5
  })
});
const started = await client.start({ scope: ["openid"] });
if (started.userCode !== "BCDF-GHJK") throw new Error("Unexpected user code");
`,
  successMessage:
    "own-auth/device-authorization resolves without loading core or database dependencies."
});
