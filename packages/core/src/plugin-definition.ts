import { normalizeTrustedWebOrigin } from "./url-security.js";
import { cloneAndDeepFreeze } from "./immutable-config.js";
import { isSupportedJsonSchema } from "./http/validation.js";
import type {
  OwnAuthConfig,
  OwnAuthPluginClientManifest,
  OwnAuthPluginDefinition,
  OwnAuthPluginEndpoint
} from "./plugin-types.js";

const pluginIdentifierPattern = /^[a-z][a-z0-9-]{0,63}$/;
const identifierPattern = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const memberPattern = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;

export class OwnAuthPluginError extends Error {
  readonly code: `plugin.${string}`;
  readonly statusCode: number;
  readonly safeMessage: string;

  constructor(pluginId: string, error: string, message: string, statusCode = 400) {
    super(message);
    this.name = "OwnAuthPluginError";
    this.code = `plugin.${pluginId}.${error}`;
    this.statusCode = statusCode;
    this.safeMessage = message;
  }
}

export function defineOwnAuthPlugin<const Plugin extends OwnAuthPluginDefinition>(
  plugin: Plugin
): Plugin {
  validatePlugin(plugin);
  return cloneAndDeepFreeze(plugin);
}

export function defineOwnAuthConfig<const Config extends OwnAuthConfig>(config: Config): Config {
  validatePluginSet(config.plugins ?? []);
  return cloneAndDeepFreeze(config);
}

export function createRuntimeOwnAuthPluginSet(
  plugins: readonly OwnAuthPluginDefinition[]
): readonly OwnAuthPluginDefinition[] {
  validatePluginSet(plugins);
  return cloneAndDeepFreeze(plugins);
}

export function createOwnAuthPluginClientManifest(
  plugin: OwnAuthPluginDefinition
): OwnAuthPluginClientManifest {
  validatePlugin(plugin);
  const endpoints = new Map((plugin.endpoints ?? []).map((endpoint) => [endpoint.id, endpoint]));
  const methods: Record<string, { method: "GET" | "POST"; path: string }> = {};
  for (const [name, clientMethod] of Object.entries(plugin.clientMethods ?? {})) {
    const endpoint = endpoints.get(clientMethod.endpoint);
    if (!endpoint) throw new Error(`Plugin ${plugin.id} client method ${name} has no endpoint`);
    methods[name] = {
      method: endpoint.method,
      path: pluginEndpointPath(plugin.id, endpoint)
    };
  }
  return cloneAndDeepFreeze({ id: plugin.id, methods });
}

export function validatePluginSet(plugins: readonly OwnAuthPluginDefinition[]): void {
  const ids = new Set<string>();
  for (const plugin of plugins) {
    validatePlugin(plugin);
    if (ids.has(plugin.id)) throw new Error(`Duplicate Own Auth plugin ID: ${plugin.id}`);
    ids.add(plugin.id);
  }
}

export function validatePlugin(plugin: OwnAuthPluginDefinition): void {
  if (!plugin || typeof plugin !== "object") {
    throw new Error("Own Auth plugins must be objects");
  }
  if (typeof plugin.id !== "string" || !pluginIdentifierPattern.test(plugin.id)) {
    throw new Error(`Invalid plugin ID: ${String(plugin.id)}`);
  }
  if (typeof plugin.version !== "string" || !plugin.version.trim() || plugin.version.length > 128) {
    throw new Error(`Plugin ${plugin.id} must have a non-empty version`);
  }
  if (plugin.userErasure !== undefined && (
    !plugin.userErasure || typeof plugin.userErasure.personalData !== "boolean" ||
    (plugin.userErasure.personalData && typeof plugin.userErasure.erase !== "function")
  )) {
    throw new Error(`Plugin ${plugin.id} must declare valid user erasure support`);
  }
  assertUniqueMembers(plugin, "server method", Object.keys(plugin.serverMethods ?? {}));
  assertUniqueMembers(plugin, "client method", Object.keys(plugin.clientMethods ?? {}));
  assertUniqueIdentifiers(plugin, "error", plugin.errors ?? []);
  assertUniqueIdentifiers(plugin, "audit event", plugin.auditEvents ?? []);
  assertUniqueIdentifiers(plugin, "migration", (plugin.migrations ?? []).map(({ id }) => id));
  assertUniqueIdentifiers(plugin, "rate limit", (plugin.rateLimits ?? []).map(({ id }) => id));
  assertUniqueMembers(plugin, "before hook", (plugin.beforeHooks ?? []).map(({ id }) => id));
  assertUniqueMembers(plugin, "after hook", (plugin.afterHooks ?? []).map(({ id }) => id));
  validateEndpoints(plugin);
  validateRateLimits(plugin);
  validateMigrations(plugin);
  validateTrustedOrigins(plugin);
  validateClientMethods(plugin);
}

export function pluginEndpointPath(
  pluginId: string,
  endpoint: Pick<OwnAuthPluginEndpoint, "id" | "path">
): string {
  return `/plugins/${pluginId}${endpoint.path ?? `/${endpoint.id}`}`;
}

function validateEndpoints(plugin: OwnAuthPluginDefinition): void {
  const ids = new Set<string>();
  const paths = new Set<string>();
  const rateLimits = new Set((plugin.rateLimits ?? []).map(({ id }) => id));
  for (const endpoint of plugin.endpoints ?? []) {
    if (!endpoint || typeof endpoint !== "object") {
      throw new Error(`Plugin ${plugin.id} endpoints must be objects`);
    }
    assertIdentifier(endpoint.id, `plugin ${plugin.id} endpoint ID`);
    if (ids.has(endpoint.id)) throw new Error(`Duplicate endpoint ${plugin.id}.${endpoint.id}`);
    ids.add(endpoint.id);
    if (endpoint.method !== "GET" && endpoint.method !== "POST") {
      throw new Error(`Plugin endpoint ${plugin.id}.${endpoint.id} has an invalid method`);
    }
    if (
      endpoint.session !== undefined &&
      endpoint.session !== "none" &&
      endpoint.session !== "optional" &&
      endpoint.session !== "required"
    ) {
      throw new Error(`Plugin endpoint ${plugin.id}.${endpoint.id} has an invalid session requirement`);
    }
    if (typeof endpoint.handler !== "function") {
      throw new Error(`Plugin endpoint ${plugin.id}.${endpoint.id} needs a handler`);
    }
    if (endpoint.input !== undefined && !isSupportedJsonSchema(endpoint.input)) {
      throw new Error(`Plugin endpoint ${plugin.id}.${endpoint.id} has an unsupported input schema`);
    }
    if (!isSupportedJsonSchema(endpoint.output)) {
      throw new Error(`Plugin endpoint ${plugin.id}.${endpoint.id} has an unsupported output schema`);
    }
    const path = endpoint.path ?? `/${endpoint.id}`;
    if (typeof path !== "string") {
      throw new Error(`Plugin ${plugin.id} endpoint ${endpoint.id} has an invalid path`);
    }
    if (!/^\/[A-Za-z0-9/_-]*[A-Za-z0-9_-]$/.test(path) || path.includes("//")) {
      throw new Error(`Plugin ${plugin.id} endpoint ${endpoint.id} has an invalid path`);
    }
    const route = `${endpoint.method} ${path}`;
    if (paths.has(route)) throw new Error(`Duplicate plugin route ${plugin.id} ${route}`);
    paths.add(route);
    if (typeof endpoint.summary !== "string" || !endpoint.summary.trim()) {
      throw new Error(`Plugin endpoint ${plugin.id}.${endpoint.id} needs a summary`);
    }
    if (endpoint.rateLimit && !rateLimits.has(endpoint.rateLimit)) {
      throw new Error(`Plugin endpoint ${plugin.id}.${endpoint.id} references an unknown rate limit`);
    }
    for (const error of endpoint.errors ?? []) {
      if (!(plugin.errors ?? []).includes(error)) {
        throw new Error(`Plugin endpoint ${plugin.id}.${endpoint.id} references undeclared error ${error}`);
      }
    }
  }
}

function validateRateLimits(plugin: OwnAuthPluginDefinition): void {
  for (const rateLimit of plugin.rateLimits ?? []) {
    if (!Number.isInteger(rateLimit.limit) || rateLimit.limit < 1) {
      throw new Error(`Plugin ${plugin.id} rate limit ${rateLimit.id} needs a positive limit`);
    }
    if (!Number.isInteger(rateLimit.windowMs) || rateLimit.windowMs < 1) {
      throw new Error(`Plugin ${plugin.id} rate limit ${rateLimit.id} needs a positive window`);
    }
  }
}

function validateMigrations(plugin: OwnAuthPluginDefinition): void {
  for (const migration of plugin.migrations ?? []) {
    const hasSql = Object.values(migration.sql).some((sql) => sql?.trim());
    if (!hasSql) {
      throw new Error(`Plugin ${plugin.id} migration ${migration.id} has no SQL`);
    }
  }
}

function validateTrustedOrigins(plugin: OwnAuthPluginDefinition): void {
  for (const origin of plugin.trustedOrigins ?? []) {
    if (!normalizeTrustedWebOrigin(origin)) {
      throw new Error(`Plugin ${plugin.id} has an invalid trusted origin: ${origin}`);
    }
  }
}

function validateClientMethods(plugin: OwnAuthPluginDefinition): void {
  const endpoints = new Set((plugin.endpoints ?? []).map(({ id }) => id));
  for (const [name, method] of Object.entries(plugin.clientMethods ?? {})) {
    if (!method || typeof method !== "object" || typeof method.endpoint !== "string") {
      throw new Error(`Plugin ${plugin.id} client method ${name} is invalid`);
    }
    if (!endpoints.has(method.endpoint)) {
      throw new Error(`Plugin ${plugin.id} client method ${name} references an unknown endpoint`);
    }
  }
}

function assertUniqueIdentifiers(
  plugin: OwnAuthPluginDefinition,
  label: string,
  values: readonly string[]
): void {
  const seen = new Set<string>();
  for (const value of values) {
    assertIdentifier(value, `plugin ${plugin.id} ${label}`);
    if (seen.has(value)) throw new Error(`Duplicate ${label} ${plugin.id}.${value}`);
    seen.add(value);
  }
}

function assertUniqueMembers(
  plugin: OwnAuthPluginDefinition,
  label: string,
  values: readonly string[]
): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (!memberPattern.test(value)) throw new Error(`Invalid ${label} ${plugin.id}.${value}`);
    if (seen.has(value)) throw new Error(`Duplicate ${label} ${plugin.id}.${value}`);
    seen.add(value);
  }
}

function assertIdentifier(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !identifierPattern.test(value)) {
    throw new Error(`Invalid ${label}: ${String(value)}`);
  }
}
