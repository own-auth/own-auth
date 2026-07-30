import {
  OwnAuthClientError,
  requestJson
} from "./client-error.js";
import type { OwnAuthPluginClientManifest } from "./plugin-types.js";

export interface OwnAuthPluginClient {
  call<Output = unknown>(method: string, input?: unknown): Promise<Output>;
}

export async function callOwnAuthPluginMethod<Output>(options: {
  baseURL: string;
  fetch: typeof globalThis.fetch;
  fingerprint?: string;
  headers: Headers;
  input?: unknown;
  manifest?: OwnAuthPluginClientManifest;
  methodName: string;
  pluginId: string;
}): Promise<Output> {
  const method = options.manifest?.methods[options.methodName];
  if (!method) {
    throw new Error(
      `Unknown Own Auth plugin client method: ${options.pluginId}.${options.methodName}`
    );
  }

  const url = new URL(`${options.baseURL}${method.path}`, browserOrLocalBase());
  const init: RequestInit = {
    method: method.method,
    credentials: "include",
    headers: options.headers
  };
  if (method.method === "GET") {
    addQueryInput(url, options.input);
  } else if (options.input !== undefined) {
    options.headers.set("content-type", "application/json");
    init.body = JSON.stringify(options.input);
  }

  const { body, response } = await requestJson(
    options.fetch,
    toRequestUrl(url, options.baseURL),
    init
  );

  const serverFingerprint = response.headers.get("x-own-auth-plugin-fingerprint");
  if (options.fingerprint && options.fingerprint !== serverFingerprint) {
    throw new OwnAuthClientError(
      "internal_error",
      "The Own Auth plugin client is out of date and must be regenerated",
      409
    );
  }
  return body as Output;
}

function addQueryInput(url: URL, input: unknown): void {
  if (!input || typeof input !== "object" || Array.isArray(input)) return;
  for (const [name, value] of Object.entries(input as Record<string, unknown>)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (const item of value) url.searchParams.append(name, String(item));
    } else {
      url.searchParams.set(name, String(value));
    }
  }
}

function browserOrLocalBase(): string {
  return (globalThis as { location?: { origin?: string } }).location?.origin
    ?? "http://own-auth.local";
}

function toRequestUrl(url: URL, configuredBaseUrl: string): string {
  return /^https?:\/\//i.test(configuredBaseUrl)
    ? url.toString()
    : `${url.pathname}${url.search}`;
}
