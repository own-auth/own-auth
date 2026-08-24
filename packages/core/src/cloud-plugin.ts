import { cloneAndDeepFreeze } from "./immutable-config.js";
import { defineOwnAuthPlugin } from "./plugin-definition.js";
import type {
  CloudClientManifest,
  CloudClientOptions,
  CloudPluginDefinition,
  CloudPluginOptions
} from "./cloud-types.js";

const cloudKeyPattern = /^oac_sk_[A-Za-z0-9_-]{16,}$/;
const webhookPathPattern = /^\/[A-Za-z0-9/_-]*[A-Za-z0-9_-]$/;
const keyIdPattern = /^[A-Za-z0-9._-]{1,64}$/;

export function cloud(options: CloudPluginOptions): CloudPluginDefinition {
  const normalized = normalizeCloudOptions(options);
  return defineOwnAuthPlugin({
    id: "cloud",
    version: "1.0.0",
    __ownAuthCloud: normalized
  });
}

export function cloudClient(options: CloudClientOptions = {}): CloudClientManifest {
  return cloneAndDeepFreeze({
    id: "cloud",
    methods: {},
    __ownAuthCloudClient: normalizeCloudClientOptions(options)
  });
}

export function cloudNativeClient(options: CloudClientOptions = {}): CloudClientManifest {
  return cloudClient(options);
}

export function findCloudPlugin(
  plugins: readonly { id: string }[] = []
): CloudPluginDefinition | null {
  const candidates = plugins.filter((plugin) => plugin.id === "cloud");
  if (candidates.length === 0) return null;
  if (candidates.length > 1) throw new Error("Only one Own Auth Cloud plugin may be configured");
  const candidate = candidates[0] as Partial<CloudPluginDefinition>;
  if (!candidate.__ownAuthCloud) {
    throw new Error("Use cloud() from own-auth/cloud to configure the Cloud plugin");
  }
  return candidate as CloudPluginDefinition;
}

export function isCloudClientManifest(value: unknown): value is CloudClientManifest {
  return Boolean(
    value && typeof value === "object" &&
    (value as Partial<CloudClientManifest>).id === "cloud" &&
    (value as Partial<CloudClientManifest>).__ownAuthCloudClient
  );
}

function normalizeCloudOptions(options: CloudPluginOptions): Readonly<CloudPluginOptions> {
  if (!options || typeof options !== "object") {
    throw new Error("cloud() requires configuration");
  }
  if (!cloudKeyPattern.test(options.key)) {
    throw new Error("Own Auth Cloud key must start with oac_sk_ and contain a secret value");
  }
  const endpoint = new URL(options.endpoint ?? "https://api.own-auth.com");
  if (endpoint.protocol !== "https:" && !isLoopback(endpoint)) {
    throw new Error("Own Auth Cloud endpoint must use HTTPS unless it is local");
  }
  const webhookPath = options.webhookPath ?? "/api/auth/cloud-webhook";
  if (!webhookPathPattern.test(webhookPath) || webhookPath.includes("//")) {
    throw new Error("Own Auth Cloud webhookPath must be an absolute URL path");
  }
  const challengeSecret = options.challengeSecret ?? (
    globalThis as { process?: { env?: Record<string, string | undefined> } }
  ).process?.env?.OWN_AUTH_CHALLENGE_SECRET;
  for (const [name, secret] of [
    ["webhookSigningSecret", options.webhookSigningSecret],
    ["webhookPreviousSigningSecret", options.webhookPreviousSigningSecret],
    ["challengeSecret", challengeSecret]
  ] as const) {
    if (secret !== undefined && new TextEncoder().encode(secret).length < 32) {
      throw new Error(`${name} must contain at least 32 bytes`);
    }
  }
  if (options.webhookPreviousSigningSecret && !options.webhookSigningSecret) {
    throw new Error("webhookPreviousSigningSecret requires webhookSigningSecret");
  }
  if (options.webhookPreviousSigningSecret && !options.webhookPreviousValidUntil) {
    throw new Error("webhookPreviousSigningSecret requires webhookPreviousValidUntil");
  }
  if (options.webhookPreviousValidUntil && !options.webhookPreviousSigningSecret) {
    throw new Error("webhookPreviousValidUntil requires webhookPreviousSigningSecret");
  }
  const webhookPreviousValidUntil = options.webhookPreviousValidUntil
    ? new Date(options.webhookPreviousValidUntil)
    : undefined;
  if (webhookPreviousValidUntil && Number.isNaN(webhookPreviousValidUntil.getTime())) {
    throw new Error("webhookPreviousValidUntil must be a valid date");
  }
  const webhookKeyId = options.webhookKeyId ?? "current";
  const webhookPreviousKeyId = options.webhookPreviousKeyId ?? "previous";
  if (!keyIdPattern.test(webhookKeyId) || !keyIdPattern.test(webhookPreviousKeyId)) {
    throw new Error("Cloud webhook key IDs must contain 1 to 64 safe characters");
  }
  if (options.webhookPreviousSigningSecret && webhookKeyId === webhookPreviousKeyId) {
    throw new Error("Current and previous Cloud webhook key IDs must differ");
  }
  const minimumDifficulty = options.security?.botDetection?.minimumDifficulty;
  if (
    minimumDifficulty !== undefined &&
    (!Number.isInteger(minimumDifficulty) || minimumDifficulty < 1 || minimumDifficulty > 20)
  ) {
    throw new Error("Cloud challenge difficulty must be between 1 and 20");
  }
  const flushMode = options.flushMode ?? "request";
  if (flushMode === "background" && !options.schedule) {
    throw new Error("Cloud background flushing requires a schedule(task) function");
  }
  if (flushMode !== "background" && options.schedule) {
    throw new Error("Cloud schedule(task) is only used with flushMode background");
  }
  return cloneAndDeepFreeze({
    ...options,
    endpoint: endpoint.toString().replace(/\/$/, ""),
    challengeSecret,
    webhookKeyId,
    webhookPreviousKeyId,
    webhookPreviousValidUntil: webhookPreviousValidUntil?.toISOString(),
    webhookPath,
    flushMode
  });
}

function normalizeCloudClientOptions(
  options: CloudClientOptions
): Required<CloudClientOptions> {
  const maximumSolveMs = options.maximumSolveMs ?? 5_000;
  if (!Number.isInteger(maximumSolveMs) || maximumSolveMs < 1 || maximumSolveMs > 30_000) {
    throw new Error("Cloud challenge solve timeout must be between 1 and 30000 milliseconds");
  }
  return {
    autoSolveChallenge: options.autoSolveChallenge ?? true,
    maximumSolveMs
  };
}

function isLoopback(url: URL): boolean {
  return url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1");
}
