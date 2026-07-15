import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { validateReleaseFiles } from "./release-policy.mjs";

const scriptPath = fileURLToPath(import.meta.url);
const rootDir = resolve(dirname(scriptPath), "..");
const packageDir = resolve(rootDir, "packages/core");
const packageName = "own-auth";
const verificationDefaults = {
  attempts: 30,
  delayMs: 2_000
};

export async function runReleaseCommand(args, runtime = createSystemRuntime()) {
  const [command, channel, ...extraArgs] = args;
  if (extraArgs.length > 0) {
    throw usageError();
  }

  if (command === "publish" && channel) {
    return publishRelease(channel, runtime);
  }
  if (command === "verify" && !channel) {
    return verifyCurrentRelease(runtime);
  }
  if (command === "tag" && !channel) {
    return tagCurrentRelease(runtime);
  }
  throw usageError();
}

export async function publishRelease(channel, runtime, verification = verificationDefaults) {
  const plan = loadReleasePlan(runtime, channel);
  const releaseCommit = assertMainReady(runtime);
  assertTagAbsent(runtime, plan.tagName);

  const registryBefore = readRegistryState(runtime);
  if (registryBefore.versions.includes(plan.version)) {
    throw new Error(
      `${packageName}@${plan.version} is already published. ` +
      "Use pnpm release:verify and pnpm release:tag only when recovering this release."
    );
  }

  run(runtime, "pnpm", ["run", "release:check"], {
    cwd: rootDir,
    stdio: "inherit"
  });
  run(runtime, "npm", [
    "publish",
    "--access",
    "public",
    "--auth-type=web",
    "--tag",
    plan.distTag
  ], {
    cwd: packageDir,
    stdio: "inherit"
  });

  await verifyPublication(plan, runtime, {
    ...verification,
    expectedLatest: plan.channel === "next"
      ? registryBefore.distTags.latest
      : undefined,
    verifyLatestUnchanged: plan.channel === "next"
  });
  ensureGitTag(plan, releaseCommit, runtime);
}

export async function verifyCurrentRelease(runtime, verification = verificationDefaults) {
  const plan = loadReleasePlan(runtime);
  await verifyPublication(plan, runtime, verification);
}

export async function tagCurrentRelease(runtime, verification = verificationDefaults) {
  const plan = loadReleasePlan(runtime);
  const releaseCommit = assertMainReady(runtime);
  await verifyPublication(plan, runtime, verification);
  ensureGitTag(plan, releaseCommit, runtime);
}

export function loadReleasePlan(runtime, channel) {
  const rootPackage = parseJson(
    runtime.readText(resolve(rootDir, "package.json")),
    "package.json"
  );
  const corePackage = parseJson(
    runtime.readText(resolve(packageDir, "package.json")),
    "packages/core/package.json"
  );

  return validateReleaseFiles({
    changelog: runtime.readText(resolve(rootDir, "CHANGELOG.md")),
    packageName: corePackage.name,
    packageVersion: corePackage.version,
    rootVersion: rootPackage.version
  }, channel);
}

export async function verifyPublication(plan, runtime, options = verificationDefaults) {
  let lastState;
  let lastError;

  for (let attempt = 0; attempt < options.attempts; attempt += 1) {
    try {
      lastState = readRegistryState(runtime);
      lastError = undefined;

      if (
        options.verifyLatestUnchanged &&
        lastState.distTags.latest !== options.expectedLatest
      ) {
        throw new Error(
          `Publishing ${plan.version} to next changed latest from ` +
          `${options.expectedLatest ?? "unset"} to ${lastState.distTags.latest ?? "unset"}`
        );
      }

      if (
        lastState.versions.includes(plan.version) &&
        lastState.distTags[plan.distTag] === plan.version
      ) {
        runtime.log(
          `Verified ${packageName}@${plan.version} on npm tag ${plan.distTag}.`
        );
        return;
      }
    } catch (error) {
      if (error instanceof Error && error.message.includes("changed latest")) {
        throw error;
      }
      lastError = error;
    }

    if (attempt + 1 < options.attempts) {
      await runtime.wait(options.delayMs);
    }
  }

  const observedTag = lastState?.distTags?.[plan.distTag] ?? "unset";
  const detail = lastError instanceof Error ? ` Last error: ${lastError.message}` : "";
  throw new Error(
    `npm did not expose ${packageName}@${plan.version} on ${plan.distTag}; ` +
    `observed ${observedTag}.${detail}`
  );
}

export function createSystemRuntime() {
  return {
    execute(command, args, options = {}) {
      const result = spawnSync(command, args, {
        cwd: options.cwd ?? rootDir,
        encoding: "utf8",
        stdio: options.stdio ?? "pipe"
      });
      if (result.error) {
        throw result.error;
      }
      return {
        status: result.status ?? 1,
        stderr: result.stderr ?? "",
        stdout: result.stdout ?? ""
      };
    },
    log(message) {
      console.log(message);
    },
    readText(path) {
      return readFileSync(path, "utf8");
    },
    wait(delayMs) {
      return new Promise((resolveWait) => setTimeout(resolveWait, delayMs));
    }
  };
}

function assertMainReady(runtime) {
  const status = output(runtime, "git", ["status", "--porcelain"]);
  if (status.trim()) {
    throw new Error("Release requires a clean working tree.");
  }

  const branch = output(runtime, "git", ["branch", "--show-current"]).trim();
  if (branch !== "main") {
    throw new Error(`Release requires the main branch; current branch is ${branch || "detached"}.`);
  }

  run(runtime, "git", ["fetch", "--quiet", "origin", "main"]);
  const head = output(runtime, "git", ["rev-parse", "HEAD"]).trim();
  const remoteHead = output(runtime, "git", ["rev-parse", "origin/main"]).trim();
  if (head !== remoteHead) {
    throw new Error("Release requires local main to match origin/main. Commit and push first.");
  }
  return head;
}

function assertTagAbsent(runtime, tagName) {
  if (localTagCommit(runtime, tagName)) {
    throw new Error(`Tag already exists locally: ${tagName}`);
  }
  if (remoteTagCommit(runtime, tagName)) {
    throw new Error(`Tag already exists on origin: ${tagName}`);
  }
}

function ensureGitTag(plan, releaseCommit, runtime) {
  const localCommit = localTagCommit(runtime, plan.tagName);
  const remoteCommit = remoteTagCommit(runtime, plan.tagName);

  assertTagCommit(plan.tagName, "local", localCommit, releaseCommit);
  assertTagCommit(plan.tagName, "origin", remoteCommit, releaseCommit);

  if (!localCommit && remoteCommit) {
    run(runtime, "git", ["fetch", "--quiet", "origin", "tag", plan.tagName]);
  } else if (!localCommit) {
    run(runtime, "git", [
      "tag",
      "-a",
      plan.tagName,
      releaseCommit,
      "-m",
      `${packageName} ${plan.tagName}`
    ]);
  }

  if (!remoteCommit) {
    run(runtime, "git", ["push", "origin", plan.tagName], { stdio: "inherit" });
  }
  runtime.log(`Verified Git tag ${plan.tagName} at ${releaseCommit}.`);
}

function assertTagCommit(tagName, location, actual, expected) {
  if (actual && actual !== expected) {
    throw new Error(
      `Tag ${tagName} on ${location} points to ${actual}, expected ${expected}`
    );
  }
}

function localTagCommit(runtime, tagName) {
  const result = execute(runtime, "git", [
    "rev-parse",
    "--verify",
    "--quiet",
    `refs/tags/${tagName}^{}`
  ], { allowFailure: true });

  if (result.status === 0) {
    return result.stdout.trim();
  }
  if (result.status === 1) {
    return null;
  }
  throw commandError("git", ["rev-parse", tagName], result);
}

function remoteTagCommit(runtime, tagName) {
  const result = execute(runtime, "git", [
    "ls-remote",
    "--tags",
    "origin",
    `refs/tags/${tagName}`,
    `refs/tags/${tagName}^{}`
  ]);
  const refs = result.stdout
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => {
      const [commit, ref] = line.split(/\s+/, 2);
      return { commit, ref };
    });
  return refs.find(({ ref }) => ref?.endsWith("^{}"))?.commit ??
    refs.find(({ ref }) => ref === `refs/tags/${tagName}`)?.commit ??
    null;
}

function readRegistryState(runtime) {
  const versions = parseJson(
    output(runtime, "npm", ["view", packageName, "versions", "--json"]),
    "npm versions"
  );
  const distTags = parseJson(
    output(runtime, "npm", ["view", packageName, "dist-tags", "--json"]),
    "npm dist-tags"
  );
  return {
    distTags,
    versions: Array.isArray(versions) ? versions : [versions]
  };
}

function parseJson(value, label) {
  try {
    return JSON.parse(value);
  } catch {
    throw new Error(`Could not parse ${label} as JSON.`);
  }
}

function output(runtime, command, args, options) {
  return execute(runtime, command, args, options).stdout;
}

function run(runtime, command, args, options) {
  execute(runtime, command, args, options);
}

function execute(runtime, command, args, options = {}) {
  const result = runtime.execute(command, args, options);
  if (result.status !== 0 && !options.allowFailure) {
    throw commandError(command, args, result);
  }
  return result;
}

function commandError(command, args, result) {
  const detail = result.stderr.trim() || result.stdout.trim();
  return new Error(
    `${command} ${args.join(" ")} failed with status ${result.status}` +
    (detail ? `: ${detail}` : "")
  );
}

function usageError() {
  return new Error([
    "Usage:",
    "  node scripts/release.mjs publish <stable|next>",
    "  node scripts/release.mjs verify",
    "  node scripts/release.mjs tag"
  ].join("\n"));
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    await runReleaseCommand(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
