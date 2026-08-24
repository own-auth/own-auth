import { pathToFileURL } from "node:url";
import {
  checkPackageResolution,
  repositoryRoot
} from "./package-resolution-check.mjs";

const guardUrl = pathToFileURL(
  `${repositoryRoot}/scripts/portable-subpath-import-guard.mjs`
).href;

await checkPackageResolution({
  fixturePrefix: "own-auth-cloud-resolution-",
typeScriptSource: `import {
  cloud,
  cloudEventContract,
  type CloudPluginOptions
} from "own-auth/cloud";
import { cloudClient, cloudNativeClient } from "own-auth/client";
import { solveCloudChallenge } from "own-auth/challenge-solver";

declare const options: CloudPluginOptions;
void cloud(options);
void cloudEventContract;
void cloudClient();
void cloudNativeClient();
void solveCloudChallenge;
`,
  runtimeSource: `import { register } from "node:module";
register(${JSON.stringify(guardUrl)}, import.meta.url);
const { cloud, cloudEventContract } = await import("own-auth/cloud");
const { cloudClient, cloudNativeClient } = await import("own-auth/client");
const { solveCloudChallenge } = await import("own-auth/challenge-solver");
const plugin = cloud({ key: "oac_sk_abcdefghijklmnopqrstuvwxyz012345" });
if (
  plugin.id !== "cloud" ||
  cloudEventContract.version !== 1 ||
  cloudClient().id !== "cloud" ||
  cloudNativeClient().id !== "cloud" ||
  typeof solveCloudChallenge !== "function"
) {
  throw new Error("own-auth/cloud exposed an invalid Cloud plugin");
}
`,
  successMessage: "own-auth/cloud resolves without loading database dependencies."
});
