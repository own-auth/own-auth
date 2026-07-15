import { describe, expect, it } from "vitest";
import {
  createReleasePlan,
  validateReleaseFiles
} from "./release-policy.mjs";
import {
  publishRelease,
  tagCurrentRelease,
  verifyCurrentRelease
} from "./release.mjs";

const releaseCommit = "1111111111111111111111111111111111111111";

describe("release policy", () => {
  it("maps stable versions to the latest npm tag", () => {
    expect(createReleasePlan("stable", "0.3.0")).toEqual({
      baseVersion: "0.3.0",
      channel: "stable",
      changelogHeading: "## 0.3.0",
      distTag: "latest",
      tagName: "v0.3.0",
      version: "0.3.0"
    });
  });

  it("maps next versions to the next npm tag and base changelog section", () => {
    expect(createReleasePlan("next", "0.4.0-next.2")).toMatchObject({
      baseVersion: "0.4.0",
      changelogHeading: "## 0.4.0",
      distTag: "next",
      tagName: "v0.4.0-next.2"
    });
  });

  it("rejects a version that does not match its channel", () => {
    expect(() => createReleasePlan("stable", "0.4.0-next.0"))
      .toThrow("stable releases require a version like 0.3.0");
    expect(() => createReleasePlan("next", "0.4.0"))
      .toThrow("next releases require a version like 0.4.0-next.0");
    expect(() => createReleasePlan("next", "0.4.0-beta.1"))
      .toThrow("next releases require a version like 0.4.0-next.0");
  });

  it("requires matching workspace versions and a changelog section", () => {
    expect(() => validateReleaseFiles({
      changelog: "## 0.3.0\n",
      packageName: "own-auth",
      packageVersion: "0.3.0",
      rootVersion: "0.2.0"
    }, "stable")).toThrow("Workspace version 0.2.0 does not match own-auth version 0.3.0");

    expect(() => validateReleaseFiles({
      changelog: "## 0.2.0\n",
      packageName: "own-auth",
      packageVersion: "0.3.0",
      rootVersion: "0.3.0"
    }, "stable")).toThrow("CHANGELOG.md is missing ## 0.3.0");
  });
});

describe("release orchestration", () => {
  it("publishes stable with browser auth, verifies latest, then tags", async () => {
    const runtime = createFakeRuntime();

    await publishRelease("stable", runtime, immediateVerification);

    expect(runtime.state.distTags.latest).toBe("0.3.0");
    expect(runtime.state.calls).toContainEqual(expect.objectContaining({
      args: [
        "publish",
        "--access",
        "public",
        "--auth-type=web",
        "--tag",
        "latest"
      ],
      command: "npm"
    }));
    expect(runtime.state.calls).toContainEqual(expect.objectContaining({
      args: ["run", "release:check"],
      command: "pnpm"
    }));
    expect(commandNames(runtime)).toEqual(expect.arrayContaining([
      "pnpm run",
      "npm publish",
      "git tag",
      "git push"
    ]));
    expect(commandIndex(runtime, "npm", "publish"))
      .toBeLessThan(commandIndex(runtime, "git", "tag"));
    expect(runtime.state.remoteTagCommit).toBe(releaseCommit);
  });

  it("publishes prereleases to next without changing latest", async () => {
    const runtime = createFakeRuntime({
      packageVersion: "0.4.0-next.0"
    });

    await publishRelease("next", runtime, immediateVerification);

    expect(runtime.state.distTags).toEqual({
      latest: "0.2.0",
      next: "0.4.0-next.0"
    });
    expect(runtime.state.calls).toContainEqual(expect.objectContaining({
      args: expect.arrayContaining(["--tag", "next"]),
      command: "npm"
    }));
  });

  it("does not treat registry failures as an unpublished version", async () => {
    const runtime = createFakeRuntime({ registryUnavailable: true });

    await expect(publishRelease("stable", runtime, immediateVerification))
      .rejects.toThrow("npm view own-auth versions --json failed");
    expect(commandIndex(runtime, "npm", "publish")).toBe(-1);
  });

  it("rejects versions that are already published before running checks", async () => {
    const runtime = createFakeRuntime({
      versions: ["0.2.0", "0.3.0"]
    });

    await expect(publishRelease("stable", runtime, immediateVerification))
      .rejects.toThrow("own-auth@0.3.0 is already published");
    expect(commandIndex(runtime, "pnpm", "run")).toBe(-1);
    expect(commandIndex(runtime, "npm", "publish")).toBe(-1);
  });

  it("rejects an existing release tag before publishing", async () => {
    const runtime = createFakeRuntime({ remoteTagCommit: releaseCommit });

    await expect(publishRelease("stable", runtime, immediateVerification))
      .rejects.toThrow("Tag already exists on origin: v0.3.0");
    expect(commandIndex(runtime, "npm", "publish")).toBe(-1);
  });

  it("does not create a tag when npm publish fails", async () => {
    const runtime = createFakeRuntime({ publishFails: true });

    await expect(publishRelease("stable", runtime, immediateVerification))
      .rejects.toThrow("npm publish");
    expect(commandIndex(runtime, "git", "tag")).toBe(-1);
    expect(commandIndex(runtime, "git", "push")).toBe(-1);
  });

  it("does not create a tag when registry verification fails", async () => {
    const runtime = createFakeRuntime({ publicationVisible: false });

    await expect(publishRelease("stable", runtime, immediateVerification))
      .rejects.toThrow("npm did not expose own-auth@0.3.0 on latest");
    expect(commandIndex(runtime, "git", "tag")).toBe(-1);
  });

  it("fails if a prerelease changes latest", async () => {
    const runtime = createFakeRuntime({
      changeLatestDuringNextPublish: true,
      packageVersion: "0.4.0-next.0"
    });

    await expect(publishRelease("next", runtime, immediateVerification))
      .rejects.toThrow("changed latest from 0.2.0 to 0.4.0-next.0");
    expect(commandIndex(runtime, "git", "tag")).toBe(-1);
  });

  it("recovers a failed tag push without creating or publishing again", async () => {
    const runtime = createFakeRuntime({
      distTags: { latest: "0.3.0" },
      localTagCommit: releaseCommit,
      versions: ["0.2.0", "0.3.0"]
    });

    await tagCurrentRelease(runtime, immediateVerification);
    await tagCurrentRelease(runtime, immediateVerification);

    expect(commandIndex(runtime, "npm", "publish")).toBe(-1);
    expect(commandNames(runtime).filter((name) => name === "git tag")).toHaveLength(0);
    expect(commandNames(runtime).filter((name) => name === "git push")).toHaveLength(1);
    expect(runtime.state.remoteTagCommit).toBe(releaseCommit);
  });

  it("refuses to replace a conflicting recovery tag", async () => {
    const runtime = createFakeRuntime({
      distTags: { latest: "0.3.0" },
      remoteTagCommit: "2222222222222222222222222222222222222222",
      versions: ["0.2.0", "0.3.0"]
    });

    await expect(tagCurrentRelease(runtime, immediateVerification))
      .rejects.toThrow("Tag v0.3.0 on origin points to");
    expect(commandIndex(runtime, "git", "push")).toBe(-1);
  });

  it("verifies an existing release without mutating npm or Git", async () => {
    const runtime = createFakeRuntime({
      distTags: { latest: "0.3.0" },
      versions: ["0.2.0", "0.3.0"]
    });

    await verifyCurrentRelease(runtime, immediateVerification);

    expect(commandIndex(runtime, "npm", "publish")).toBe(-1);
    expect(commandIndex(runtime, "git", "tag")).toBe(-1);
    expect(commandIndex(runtime, "git", "push")).toBe(-1);
  });

  it("requires a clean main branch that matches origin", async () => {
    const dirtyRuntime = createFakeRuntime({ dirty: true });
    await expect(publishRelease("stable", dirtyRuntime, immediateVerification))
      .rejects.toThrow("clean working tree");

    const behindRuntime = createFakeRuntime({ remoteCommit: "2222222222222222222222222222222222222222" });
    await expect(publishRelease("stable", behindRuntime, immediateVerification))
      .rejects.toThrow("local main to match origin/main");
  });
});

const immediateVerification = {
  attempts: 1,
  delayMs: 0
};

interface FakeRuntimeOptions {
  changeLatestDuringNextPublish?: boolean;
  dirty?: boolean;
  distTags?: Record<string, string>;
  localTagCommit?: string | null;
  packageVersion?: string;
  publicationVisible?: boolean;
  publishFails?: boolean;
  registryUnavailable?: boolean;
  remoteCommit?: string;
  remoteTagCommit?: string | null;
  versions?: string[];
}

function createFakeRuntime(options: FakeRuntimeOptions = {}) {
  const packageVersion = options.packageVersion ?? "0.3.0";
  const baseVersion = packageVersion.split("-", 1)[0];
  const state = {
    calls: [] as Array<{ args: string[]; command: string; options: Record<string, unknown> }>,
    distTags: { ...(options.distTags ?? { latest: "0.2.0" }) },
    localTagCommit: options.localTagCommit ?? null,
    logs: [] as string[],
    remoteTagCommit: options.remoteTagCommit ?? null,
    versions: [...(options.versions ?? ["0.2.0"])]
  };

  return {
    state,
    execute(command: string, args: string[], commandOptions: Record<string, unknown> = {}) {
      state.calls.push({ args: [...args], command, options: commandOptions });

      if (command === "git" && args[0] === "status") {
        return result(options.dirty ? " M package.json\n" : "");
      }
      if (command === "git" && args[0] === "branch") {
        return result("main\n");
      }
      if (command === "git" && args[0] === "fetch") {
        if (args.includes("tag")) state.localTagCommit = state.remoteTagCommit;
        return result();
      }
      if (command === "git" && args[0] === "rev-parse" && args[1] === "HEAD") {
        return result(`${releaseCommit}\n`);
      }
      if (command === "git" && args[0] === "rev-parse" && args[1] === "origin/main") {
        return result(`${options.remoteCommit ?? releaseCommit}\n`);
      }
      if (command === "git" && args[0] === "rev-parse") {
        return state.localTagCommit
          ? result(`${state.localTagCommit}\n`)
          : result("", 1);
      }
      if (command === "git" && args[0] === "ls-remote") {
        const tagRef = args.find((arg) => arg.startsWith("refs/tags/") && !arg.endsWith("^{}"));
        return state.remoteTagCommit && tagRef
          ? result(`${state.remoteTagCommit}\t${tagRef}\n`)
          : result();
      }
      if (command === "git" && args[0] === "tag") {
        state.localTagCommit = args[3] ?? null;
        return result();
      }
      if (command === "git" && args[0] === "push") {
        state.remoteTagCommit = state.localTagCommit;
        return result();
      }
      if (command === "pnpm" && args[0] === "run" && args[1] === "release:check") {
        return result();
      }
      if (command === "npm" && args[0] === "view") {
        if (options.registryUnavailable) return result("", 1, "network unavailable");
        return args[2] === "versions"
          ? result(`${JSON.stringify(state.versions)}\n`)
          : result(`${JSON.stringify(state.distTags)}\n`);
      }
      if (command === "npm" && args[0] === "publish") {
        if (options.publishFails) return result("", 1, "publish rejected");
        if (options.publicationVisible !== false) {
          state.versions.push(packageVersion);
          const distTag = args[args.indexOf("--tag") + 1];
          if (distTag) state.distTags[distTag] = packageVersion;
          if (options.changeLatestDuringNextPublish) {
            state.distTags.latest = packageVersion;
          }
        }
        return result();
      }
      throw new Error(`Unexpected command: ${command} ${args.join(" ")}`);
    },
    log(message: string) {
      state.logs.push(message);
    },
    readText(path: string) {
      if (path.endsWith("/packages/core/package.json")) {
        return JSON.stringify({ name: "own-auth", version: packageVersion });
      }
      if (path.endsWith("/package.json")) {
        return JSON.stringify({ version: packageVersion });
      }
      if (path.endsWith("/CHANGELOG.md")) {
        return `# Changelog\n\n## ${baseVersion}\n`;
      }
      throw new Error(`Unexpected file read: ${path}`);
    },
    wait() {
      return Promise.resolve();
    }
  };
}

function result(stdout = "", status = 0, stderr = "") {
  return { status, stderr, stdout };
}

function commandIndex(runtime: ReturnType<typeof createFakeRuntime>, command: string, firstArg: string) {
  return runtime.state.calls.findIndex(
    (call) => call.command === command && call.args[0] === firstArg
  );
}

function commandNames(runtime: ReturnType<typeof createFakeRuntime>) {
  return runtime.state.calls.map((call) => `${call.command} ${call.args[0]}`);
}
