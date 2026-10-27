import type { OwnAuth } from "./auth-engine.js";
import { createId } from "./crypto.js";
import { AuthError, isAuthError } from "./errors.js";
import { enforceRateLimit, type RateLimitStore } from "./rate-limit.js";
import type { AuthStorage } from "./storage.js";
import type { CurrentSession, JsonRecord, RequestContext } from "./types.js";
import {
  createRuntimeOwnAuthPluginSet,
  OwnAuthPluginError,
  pluginEndpointPath
} from "./plugin-definition.js";
import type {
  CallOwnAuthPluginMethodOptions,
  OwnAuthPluginContext,
  OwnAuthPluginDefinition,
  OwnAuthPluginEndpoint,
  OwnAuthPluginRuntimeOptions
} from "./plugin-types.js";
import { createOwnAuthPluginContractFingerprint } from "./plugin-contract.js";
import { matchesJsonSchema } from "./http/validation.js";

const maximumBeforeHookTimeoutMs = 5_000;

export interface RegisteredPluginEndpoint {
  readonly plugin: OwnAuthPluginDefinition;
  readonly endpoint: OwnAuthPluginEndpoint;
  readonly path: string;
}

export class OwnAuthPluginRuntime {
  private readonly plugins: ReadonlyMap<string, OwnAuthPluginDefinition>;
  private readonly endpoints: readonly RegisteredPluginEndpoint[];
  private readonly contractFingerprint: string;
  private readonly hookTimeoutMs: number;

  constructor(
    plugins: readonly OwnAuthPluginDefinition[],
    private readonly storage: AuthStorage,
    private readonly rateLimitStore: RateLimitStore,
    private readonly getAuth: () => OwnAuth<string, string>,
    private readonly options: OwnAuthPluginRuntimeOptions = {}
  ) {
    const runtimePlugins = createRuntimeOwnAuthPluginSet(plugins);
    this.validateStorageRequirements(runtimePlugins);
    this.plugins = new Map(runtimePlugins.map((plugin) => [plugin.id, plugin]));
    this.endpoints = Object.freeze(runtimePlugins.flatMap((plugin) =>
      (plugin.endpoints ?? []).map((endpoint) => ({
        plugin,
        endpoint,
        path: pluginEndpointPath(plugin.id, endpoint)
      })).map((registered) => Object.freeze(registered))
    ));
    this.contractFingerprint = createOwnAuthPluginContractFingerprint(runtimePlugins);
    this.hookTimeoutMs = options.beforeHookTimeoutMs ?? maximumBeforeHookTimeoutMs;
    if (
      !Number.isInteger(this.hookTimeoutMs) ||
      this.hookTimeoutMs < 1 ||
      this.hookTimeoutMs > maximumBeforeHookTimeoutMs
    ) {
      throw new Error("Plugin before-hook timeout must be between 1 and 5000 milliseconds");
    }
  }

  get definitions(): readonly OwnAuthPluginDefinition[] {
    return Object.freeze([...this.plugins.values()]);
  }

  get fingerprint(): string {
    return this.contractFingerprint;
  }

  findEndpoint(path: string, method: string): RegisteredPluginEndpoint | null {
    return this.endpoints.find(
      (candidate) => candidate.path === path && candidate.endpoint.method === method
    ) ?? null;
  }

  methodsForPath(path: string): string[] {
    return this.endpoints
      .filter((candidate) => candidate.path === path)
      .map((candidate) => candidate.endpoint.method);
  }

  async executeEndpoint(
    registered: RegisteredPluginEndpoint,
    input: unknown,
    sessionToken: string | null,
    request: RequestContext
  ): Promise<unknown> {
    const session = await this.resolveSession(sessionToken, registered.endpoint.session ?? "none");
    const operation = `plugin.${registered.plugin.id}.${registered.endpoint.id}`;
    return this.runWithHooks(operation, input, request, async (signal) => {
      const context = this.context(registered.plugin, input, request, session, signal);
      await this.enforceEndpointRateLimit(registered, context);
      const result = await registered.endpoint.handler(context);
      if (!matchesJsonSchema(result, registered.endpoint.output)) {
        throw new Error(`Plugin ${registered.plugin.id} returned an invalid endpoint response`);
      }
      return result;
    });
  }

  async callServerMethod(
    pluginId: string,
    methodName: string,
    input: unknown,
    options: CallOwnAuthPluginMethodOptions = {}
  ): Promise<unknown> {
    const plugin = this.requirePlugin(pluginId);
    const method = plugin.serverMethods?.[methodName];
    if (!method) throw new Error(`Unknown Own Auth plugin server method: ${pluginId}.${methodName}`);
    const session = options.sessionToken
      ? await this.getAuth().getCurrentSession(options.sessionToken)
      : null;
    const request = options.request ?? {};
    return this.runWithHooks(`plugin.${pluginId}.server.${methodName}`, input, request, (signal) =>
      method(this.context(plugin, input, request, session, signal))
    );
  }

  runCoreOperation<Result>(
    operation: string,
    input: unknown,
    request: RequestContext,
    work: () => Promise<Result>
  ): Promise<Result> {
    return this.runWithHooks(operation, input, request, () => work());
  }

  private async runWithHooks<Result>(
    operation: string,
    input: unknown,
    request: RequestContext,
    work: (signal: AbortSignal) => Promise<Result> | Result
  ): Promise<Result> {
    const immutableInput = immutableClone(input);
    for (const plugin of this.plugins.values()) {
      for (const hook of plugin.beforeHooks ?? []) {
        if (!matchesOperation(hook.operations, operation)) continue;
        const result = await this.runBeforeHook(plugin, hook, operation, immutableInput, request);
        if (result === false || (result && result.allow === false)) {
          const error = result && typeof result === "object" ? result.error : undefined;
          const message = result && typeof result === "object" && result.message
            ? result.message
            : "Authentication operation denied by a plugin";
          if (error && (plugin.errors ?? []).includes(error)) {
            throw new OwnAuthPluginError(plugin.id, error, message, 403);
          }
          throw new AuthError("plugin_denied", message, 403);
        }
      }
    }

    const result = await work(new AbortController().signal);
    const safeInput = immutableClone(sanitizeForHook(input));
    const safeResult = immutableClone(sanitizeForHook(result));
    for (const plugin of this.plugins.values()) {
      for (const hook of plugin.afterHooks ?? []) {
        if (!matchesOperation(hook.operations, operation)) continue;
        try {
          await this.runTimed(plugin.id, hook.id, (signal) => hook.run({
            pluginId: plugin.id,
            operation,
            input: safeInput,
            result: safeResult,
            request: immutableClone(request),
            signal
          }));
        } catch (error) {
          await this.reportAfterHookError(error, plugin.id, hook.id, operation);
        }
      }
    }
    return result;
  }

  private runBeforeHook(
    plugin: OwnAuthPluginDefinition,
    hook: NonNullable<OwnAuthPluginDefinition["beforeHooks"]>[number],
    operation: string,
    input: unknown,
    request: RequestContext
  ) {
    return this.runTimed(plugin.id, hook.id, (signal) => hook.run({
      pluginId: plugin.id,
      operation,
      input,
      request: immutableClone(request),
      signal
    })).catch((error: unknown) => {
      if (error instanceof OwnAuthPluginError || isAuthError(error)) throw error;
      throw new AuthError(
        error instanceof PluginHookTimeoutError ? "plugin_hook_timeout" : "plugin_denied",
        error instanceof PluginHookTimeoutError
          ? "Authentication plugin timed out"
          : "Authentication operation denied by a plugin",
        error instanceof PluginHookTimeoutError ? 504 : 403
      );
    });
  }

  private async runTimed<Result>(
    pluginId: string,
    hookId: string,
    run: (signal: AbortSignal) => Result | Promise<Result>
  ): Promise<Result> {
    const controller = new AbortController();
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<never>((_resolve, reject) => {
      timeout = setTimeout(() => {
        controller.abort();
        reject(new PluginHookTimeoutError(pluginId, hookId));
      }, this.hookTimeoutMs);
    });
    try {
      return await Promise.race([Promise.resolve().then(() => run(controller.signal)), timeoutPromise]);
    } finally {
      if (timeout) clearTimeout(timeout);
    }
  }

  private context(
    plugin: OwnAuthPluginDefinition,
    input: unknown,
    request: RequestContext,
    session: CurrentSession | null,
    signal: AbortSignal
  ): OwnAuthPluginContext {
    return {
      auth: this.getAuth(),
      input: immutableClone(input),
      request: immutableClone(request),
      session,
      signal,
      audit: (event, metadata) => this.audit(plugin, event, session, request, metadata),
      deny: (error, message, statusCode) => {
        if (!(plugin.errors ?? []).includes(error)) {
          throw new Error(`Plugin ${plugin.id} used undeclared error ${error}`);
        }
        throw new OwnAuthPluginError(plugin.id, error, message, statusCode);
      }
    };
  }

  private async enforceEndpointRateLimit(
    registered: RegisteredPluginEndpoint,
    context: OwnAuthPluginContext
  ): Promise<void> {
    if (!registered.endpoint.rateLimit) return;
    const definition = registered.plugin.rateLimits?.find(
      ({ id }) => id === registered.endpoint.rateLimit
    );
    if (!definition) throw new Error("Validated plugin rate limit is missing");
    const key = definition.key === "ip"
      ? context.request.ipAddress ?? null
      : definition.key === "user"
        ? context.session?.user.id ?? null
        : await definition.key(context);
    if (!key) return;
    await enforceRateLimit(this.rateLimitStore, {
      key: `plugin:${registered.plugin.id}:${definition.id}:${key}`,
      limit: definition.limit,
      windowMs: definition.windowMs,
      ownerUserId: definition.key === "ip" ? undefined : context.session?.user.id
    });
  }

  private async resolveSession(
    token: string | null,
    requirement: "none" | "optional" | "required"
  ): Promise<CurrentSession | null> {
    if (requirement === "none") return null;
    const session = token ? await this.getAuth().getCurrentSession(token) : null;
    if (requirement === "required" && !session) {
      throw new AuthError("invalid_session", "Invalid or expired session", 401);
    }
    return session;
  }

  private async audit(
    plugin: OwnAuthPluginDefinition,
    event: string,
    session: CurrentSession | null,
    request: RequestContext,
    metadata?: JsonRecord
  ): Promise<void> {
    if (!(plugin.auditEvents ?? []).includes(event)) {
      throw new Error(`Plugin ${plugin.id} used undeclared audit event ${event}`);
    }
    await this.storage.createAuditEvent({
      id: createId("evt"),
      eventType: `plugin.${plugin.id}.${event}`,
      actorUserId: session?.user.id ?? null,
      targetUserId: null,
      organisationId: null,
      apiKeyId: null,
      ipAddress: request.ipAddress ?? null,
      userAgent: request.userAgent ?? null,
      metadata: metadata ? structuredClone(metadata) : {},
      createdAt: new Date()
    });
  }

  private requirePlugin(pluginId: string): OwnAuthPluginDefinition {
    const plugin = this.plugins.get(pluginId);
    if (!plugin) throw new Error(`Unknown Own Auth plugin: ${pluginId}`);
    return plugin;
  }

  private validateStorageRequirements(plugins: readonly OwnAuthPluginDefinition[]): void {
    for (const plugin of plugins) {
      for (const requirement of plugin.storageRequirements ?? []) {
        if (typeof (this.storage as unknown as Record<string, unknown>)[requirement] !== "function") {
          throw new Error(`Plugin ${plugin.id} requires storage method ${requirement}`);
        }
      }
    }
  }

  private async reportAfterHookError(
    error: unknown,
    pluginId: string,
    hookId: string,
    operation: string
  ): Promise<void> {
    try {
      await this.options.onAfterHookError?.(error, { pluginId, hookId, operation });
    } catch {
      // Reporting failures must not change a committed authentication result.
    }
  }
}

class PluginHookTimeoutError extends Error {
  constructor(pluginId: string, hookId: string) {
    super(`Plugin hook timed out: ${pluginId}.${hookId}`);
    this.name = "PluginHookTimeoutError";
  }
}

function matchesOperation(operations: readonly string[] | undefined, operation: string): boolean {
  return !operations || operations.includes("*") || operations.includes(operation);
}

function immutableClone<T>(value: T): Readonly<T> {
  return deepFreeze(cloneHookValue(value)) as Readonly<T>;
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  if (ArrayBuffer.isView(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  return value;
}

function cloneHookValue(value: unknown, seen = new WeakMap<object, unknown>()): unknown {
  if (!value || typeof value !== "object") return value;

  const existing = seen.get(value);
  if (existing) return existing;

  if (value instanceof URLSearchParams) {
    const copy = new URLSearchParams(value);
    const denyMutation = () => {
      throw new TypeError("Plugin hook input is immutable");
    };
    for (const method of ["append", "delete", "set", "sort"] as const) {
      Object.defineProperty(copy, method, { value: denyMutation });
    }
    return copy;
  }
  if (value instanceof Date) return new Date(value.getTime());
  if (value instanceof Map) {
    const copy = new Map();
    seen.set(value, copy);
    for (const [key, child] of value) {
      copy.set(cloneHookValue(key, seen), cloneHookValue(child, seen));
    }
    return copy;
  }
  if (value instanceof Set) {
    const copy = new Set();
    seen.set(value, copy);
    for (const child of value) copy.add(cloneHookValue(child, seen));
    return copy;
  }
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    return structuredClone(value);
  }
  if (Array.isArray(value)) {
    const copy: unknown[] = [];
    seen.set(value, copy);
    for (const child of value) copy.push(cloneHookValue(child, seen));
    return copy;
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    return structuredClone(value);
  }
  const copy: Record<string, unknown> = Object.create(prototype) as Record<string, unknown>;
  seen.set(value, copy);
  for (const [key, child] of Object.entries(value)) {
    copy[key] = cloneHookValue(child, seen);
  }
  return copy;
}

function sanitizeForHook(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sanitizeForHook);
  if (!value || typeof value !== "object") return value;
  const sanitized: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    sanitized[key] = /password|token|secret|code|credential|private.?key|api.?key|raw.?key|state|nonce|response|assertion|url|uri/i.test(key)
      ? "[redacted]"
      : sanitizeForHook(child);
  }
  return sanitized;
}
