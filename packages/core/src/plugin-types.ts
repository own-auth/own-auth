import type { OwnAuth } from "./auth-engine.js";
import type { DatabaseDialect } from "./core-migrations.js";
import type { JsonSchema, OwnAuthHttpMethod } from "./http/contract.js";
import type { AuthStorage } from "./storage.js";
import type { CurrentSession, JsonRecord, RequestContext } from "./types.js";
import type { UserErasureParticipation } from "./user-erasure.js";

export type PluginSessionRequirement = "none" | "optional" | "required";

export interface OwnAuthPluginContext<Input = unknown> {
  readonly auth: OwnAuth<string, string>;
  readonly input: Readonly<Input>;
  readonly request: Readonly<RequestContext>;
  readonly session: CurrentSession | null;
  readonly signal: AbortSignal;
  audit(event: string, metadata?: JsonRecord): Promise<void>;
  deny(error: string, message: string, statusCode?: number): never;
}

export type OwnAuthPluginServerMethod = (
  context: OwnAuthPluginContext
) => unknown | Promise<unknown>;

export interface OwnAuthPluginEndpoint {
  id: string;
  method: OwnAuthHttpMethod;
  path?: string;
  summary: string;
  input?: JsonSchema;
  output: JsonSchema;
  errors?: readonly string[];
  session?: PluginSessionRequirement;
  rateLimit?: string;
  handler(context: OwnAuthPluginContext): unknown | Promise<unknown>;
}

export interface OwnAuthPluginClientMethod {
  endpoint: string;
}

export interface OwnAuthPluginRateLimit {
  id: string;
  limit: number;
  windowMs: number;
  key:
    | "ip"
    | "user"
    | ((context: OwnAuthPluginContext) => string | null | Promise<string | null>);
}

export interface OwnAuthPluginBeforeHook {
  id: string;
  operations?: readonly string[];
  run(
    context: OwnAuthPluginHookContext
  ): void | false | { allow: false; error?: string; message?: string } | Promise<
    void | false | { allow: false; error?: string; message?: string }
  >;
}

export interface OwnAuthPluginAfterHook {
  id: string;
  operations?: readonly string[];
  run(context: OwnAuthPluginAfterHookContext): void | Promise<void>;
}

export interface OwnAuthPluginHookContext {
  readonly pluginId: string;
  readonly operation: string;
  readonly input: unknown;
  readonly request: Readonly<RequestContext>;
  readonly signal: AbortSignal;
}

export interface OwnAuthPluginAfterHookContext extends OwnAuthPluginHookContext {
  readonly result: unknown;
}

export interface OwnAuthPluginMigration {
  id: string;
  sql: Partial<Record<DatabaseDialect, string>>;
}

export interface OwnAuthPluginDefinition {
  userErasure?: UserErasureParticipation;
  id: string;
  version: string;
  serverMethods?: Readonly<Record<string, OwnAuthPluginServerMethod>>;
  clientMethods?: Readonly<Record<string, OwnAuthPluginClientMethod>>;
  endpoints?: readonly OwnAuthPluginEndpoint[];
  errors?: readonly string[];
  auditEvents?: readonly string[];
  migrations?: readonly OwnAuthPluginMigration[];
  beforeHooks?: readonly OwnAuthPluginBeforeHook[];
  afterHooks?: readonly OwnAuthPluginAfterHook[];
  rateLimits?: readonly OwnAuthPluginRateLimit[];
  trustedOrigins?: readonly string[];
  storageRequirements?: readonly (keyof AuthStorage & string)[];
}

export interface OwnAuthPluginClientManifest {
  id: string;
  methods: Readonly<Record<string, {
    method: OwnAuthHttpMethod;
    path: string;
  }>>;
}

export interface OwnAuthConfig {
  plugins?: readonly OwnAuthPluginDefinition[];
}

export interface OwnAuthPluginRuntimeOptions {
  beforeHookTimeoutMs?: number;
  onAfterHookError?: (
    error: unknown,
    details: { pluginId: string; hookId: string; operation: string }
  ) => void | Promise<void>;
}

export interface CallOwnAuthPluginMethodOptions {
  sessionToken?: string;
  request?: RequestContext;
}
