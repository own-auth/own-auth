import { spawn, type ChildProcess } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { RateLimitStore } from "../packages/core/src/rate-limit.js";
import type { AuthStorage } from "../packages/core/src/storage.js";
import type { AuthorizationServerStorage } from "../packages/core/src/authorization-server-storage.js";
import {
  atomicAdapterCases,
  type AtomicAdapterHarness
} from "../packages/core/test/conformance/atomic-adapter-cases.js";
import {
  authConcurrencyCases,
  type AuthConcurrencyHarness
} from "../packages/core/test/conformance/auth-concurrency-cases.js";
import {
  type PersistenceConformanceAuth,
  type PersistenceConformanceArtifacts
} from "../packages/core/test/conformance/persistence-conformance-contract.js";
import { runPersistenceConformance } from "../packages/core/test/conformance/persistence-conformance.js";
import { assertCustomAuthorizationD1Migration } from "./d1-custom-authorization-migration-check.js";
import {
  decodeConformanceValue,
  encodeConformanceValue,
  isRecord,
  type ConformanceRpcError,
  type ConformanceRpcRequest
} from "../packages/core/test/cloudflare/conformance-protocol.js";
import {
  assertAuthorizationRefreshRace
} from "./authorization-server-conformance.js";

const root = new URL("..", import.meta.url);
const config = "packages/core/test/cloudflare/wrangler.jsonc";
const database = "own-auth-worker-compatibility";
const port = 18_787;
const persistenceDirectory = await mkdtemp(join(tmpdir(), "own-auth-d1-"));
let worker: ChildProcess | undefined;
const workerOutput: string[] = [];

try {
  await assertCustomAuthorizationD1Migration({
    persistenceDirectory,
    runWrangler,
    runWranglerCapture
  });
  await applyMigrations();
  await applyMigrations();
  worker = await startWorker();

  const origin = `http://127.0.0.1:${port}`;
  await assertWebhookVerifier(origin);
  await assertChecks(await postAction(`${origin}/conformance/schema`), "D1 schema");
  await assertChecks(await postAction(`${origin}/conformance/webhook-flow`), "D1 webhook flow");
  await assertAuthorizationRefreshRace(
    createRemoteProxy<AuthStorage>(origin, "storage"),
    createRemoteProxy<AuthorizationServerStorage>(origin, "authorization-storage")
  );

  for (const testCase of atomicAdapterCases) {
    await runCase("D1 atomic adapter conformance", testCase.name, () =>
      testCase.run(createRemoteAtomicHarness(origin))
    );
  }

  for (const testCase of authConcurrencyCases) {
    await runCase("D1 auth concurrency conformance", testCase.name, () =>
      testCase.run(createRemoteAuthHarness(origin, testCase.sms?.maxAttempts))
    );
  }

  const artifacts = await runCase("D1 persistence conformance", "complete auth lifecycle", () =>
    runPersistenceConformance({
      auth: createRemoteProxy<PersistenceConformanceAuth>(origin, "auth"),
      inspect: (targets) => inspectPersistence(origin, targets)
    })
  );
  await assertChecks(await postAction(`${origin}/conformance/close`), "D1 close lifecycle");

  await stopWorker(worker);
  worker = undefined;
  await applyMigrations();
  worker = await startWorker();

  const auth = createRemoteProxy<PersistenceConformanceAuth>(origin, "auth");
  const persisted = await auth.requireCurrentSession(artifacts.continuity.sessionToken);
  if (persisted.user.email !== artifacts.continuity.email) {
    throw new Error("D1 data did not survive a repeated migration run and Worker restart");
  }
  await assertChecks(await postAction(`${origin}/conformance/schema`), "restarted D1 schema");

  console.log(
    `Cloudflare D1 passed ${atomicAdapterCases.length} atomic cases, ` +
    `${authConcurrencyCases.length} auth races, webhook, lifecycle, migration, secret, and close checks.`
  );
} catch (error) {
  if (workerOutput.length > 0) console.error(workerOutput.join(""));
  throw error;
} finally {
  await stopWorker(worker);
  await rm(persistenceDirectory, { recursive: true, force: true });
}

function createRemoteAtomicHarness(origin: string): AtomicAdapterHarness {
  return {
    storage: [
      createRemoteProxy<AuthStorage>(origin, "storage"),
      createRemoteProxy<AuthStorage>(origin, "storage")
    ],
    rateLimits: [
      createRemoteProxy<RateLimitStore>(origin, "rate-limit"),
      createRemoteProxy<RateLimitStore>(origin, "rate-limit")
    ],
    close() {}
  };
}

function createRemoteAuthHarness(
  origin: string,
  smsMaxAttempts?: number
): AuthConcurrencyHarness {
  const options = smsMaxAttempts ? { smsMaxAttempts } : undefined;
  return {
    // Every method call is a separate HTTP request and therefore a separate Worker invocation.
    auth: [
      createRemoteProxy(origin, "auth", options),
      createRemoteProxy(origin, "auth", options)
    ],
    storage: [
      createRemoteProxy<AuthStorage>(origin, "storage"),
      createRemoteProxy<AuthStorage>(origin, "storage")
    ]
  };
}

function createRemoteProxy<T extends object>(
  origin: string,
  resource: "auth" | "storage" | "rate-limit" | "authorization-storage",
  options?: ConformanceRpcRequest["options"]
): T {
  return new Proxy({}, {
    get(_target, property) {
      if (property === "then" || typeof property !== "string") return undefined;
      return (...args: unknown[]) => postRpc(
        `${origin}/conformance/${resource}`,
        { method: property, args, options }
      );
    }
  }) as T;
}

async function inspectPersistence(
  origin: string,
  artifacts: PersistenceConformanceArtifacts
): Promise<Record<string, boolean>> {
  const result = await postEncoded(`${origin}/conformance/inspect`, artifacts);
  if (!isRecord(result)) throw new Error("D1 inspection returned an invalid result");
  return result as Record<string, boolean>;
}

async function runCase<Value>(
  group: string,
  name: string,
  run: () => Promise<Value>
): Promise<Value> {
  try {
    return await run();
  } catch (error) {
    throw new Error(`${group} failed: ${name}`, { cause: error });
  }
}

async function assertChecks(value: unknown, label: string): Promise<void> {
  if (!isRecord(value)) throw new Error(`${label} returned an invalid result`);
  for (const [check, passed] of Object.entries(value)) {
    if (passed !== true) throw new Error(`${label} failed: ${check}`);
  }
}

async function assertWebhookVerifier(origin: string): Promise<void> {
  const event = {
    id: "evt_AAAAAAAAAAAAAAAAAAAAAA",
    type: "user.signed_up",
    version: 1,
    createdAt: new Date().toISOString(),
    data: {
      actorUserId: "usr_1",
      targetUserId: "usr_1",
      organisationId: null,
      apiKeyId: null,
      details: { provider: "password" }
    }
  };
  const body = JSON.stringify(event);
  const timestamp = Math.floor(Date.now() / 1_000).toString();
  const signature = createHmac(
    "sha256",
    "cloudflare-webhook-verifier-secret-32-bytes"
  ).update(`v1.${event.id}.${timestamp}.${body}`).digest("base64url");
  const response = await fetch(`${origin}/conformance/webhook-verifier`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-own-auth-webhook-id": event.id,
      "x-own-auth-webhook-timestamp": timestamp,
      "x-own-auth-webhook-signature": `v1=${signature}`
    },
    body
  });
  if (!response.ok) {
    throw new Error(`Cloudflare webhook verifier returned ${response.status}`);
  }
  const verified = await response.json() as { id?: string; type?: string };
  if (verified.id !== event.id || verified.type !== event.type) {
    throw new Error("Cloudflare webhook verifier returned the wrong event");
  }
}

async function applyMigrations(): Promise<void> {
  await runWrangler([
    "d1",
    "migrations",
    "apply",
    database,
    "--local",
    "--config",
    config,
    "--persist-to",
    persistenceDirectory
  ]);
}

async function startWorker(): Promise<ChildProcess> {
  const child = spawnWrangler([
    "dev",
    "--config",
    config,
    "--ip",
    "127.0.0.1",
    "--port",
    String(port),
    "--persist-to",
    persistenceDirectory
  ], workerOutput);
  await waitForWorker(`http://127.0.0.1:${port}`, child, workerOutput);
  return child;
}

function spawnWrangler(args: string[], output: string[] = []): ChildProcess {
  const child = spawn("pnpm", ["dlx", "wrangler@4.110.0", ...args], {
    cwd: root,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"]
  });
  child.stdout?.on("data", (chunk) => output.push(chunk.toString()));
  child.stderr?.on("data", (chunk) => output.push(chunk.toString()));
  return child;
}

async function runWrangler(args: string[]): Promise<void> {
  const output: string[] = [];
  const child = spawnWrangler(args, output);
  const exitCode = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", resolve);
  });
  if (exitCode !== 0) {
    throw new Error(`Wrangler exited with code ${exitCode}.\n${output.join("")}`);
  }
}

async function runWranglerCapture(args: string[]): Promise<string> {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const child = spawn("pnpm", ["dlx", "wrangler@4.110.0", ...args], {
    cwd: root,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"]
  });
  child.stdout?.on("data", (chunk) => stdout.push(chunk.toString()));
  child.stderr?.on("data", (chunk) => stderr.push(chunk.toString()));
  const exitCode = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", resolve);
  });
  if (exitCode !== 0) {
    throw new Error(`Wrangler exited with code ${exitCode}.\n${stderr.join("")}`);
  }
  return stdout.join("");
}

async function stopWorker(child?: ChildProcess): Promise<void> {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  if (!await waitForExit(child, 5_000)) {
    child.kill("SIGKILL");
    await waitForExit(child, 5_000);
  }
}

function waitForExit(child: ChildProcess, timeoutMs: number): Promise<boolean> {
  if (child.exitCode !== null) return Promise.resolve(true);
  return new Promise((resolve) => {
    const onExit = () => finish(true);
    const timeout = setTimeout(() => finish(child.exitCode !== null), timeoutMs);
    const finish = (exited: boolean) => {
      clearTimeout(timeout);
      child.off("exit", onExit);
      resolve(exited);
    };
    child.once("exit", onExit);
    if (child.exitCode !== null) finish(true);
  });
}

async function waitForWorker(
  origin: string,
  child: ChildProcess,
  output: string[]
): Promise<void> {
  const deadline = Date.now() + 90_000;
  let lastError: unknown;

  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`Cloudflare Worker exited with code ${child.exitCode}.\n${output.join("")}`);
    }
    try {
      const response = await fetch(`${origin}/missing`);
      if (response.status === 404) return;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  throw new Error("Cloudflare Worker did not become ready within 90 seconds", {
    cause: lastError
  });
}

async function postRpc(url: string, body: ConformanceRpcRequest): Promise<unknown> {
  return postEncoded(url, body);
}

async function postAction(url: string): Promise<unknown> {
  return postEncoded(url, {});
}

async function postEncoded(url: string, body: unknown): Promise<unknown> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(encodeConformanceValue(body))
  });
  const result = decodeConformanceValue(await response.json());
  if (!response.ok) {
    const error = isRecord(result) && isRecord(result.error)
      ? result.error as unknown as ConformanceRpcError["error"]
      : null;
    throw {
      name: "RemoteConformanceError",
      message: typeof error?.message === "string"
        ? error.message
        : `Conformance request returned ${response.status}`,
      code: typeof error?.code === "string" ? error.code : undefined
    };
  }
  return result;
}
