import {
  AuthError,
  createOwnAuth,
  MemoryEmailProvider,
  MemorySmsProvider
} from "../../dist/index.js";
import type { AuthorizationServerStorage } from "../../dist/index.js";
import {
  createD1Persistence,
  type D1DatabaseLike
} from "../../dist/d1/index.js";
import { verifyOwnAuthWebhook } from "../../dist/webhooks.js";
import { createConformanceGoogleProvider } from "../conformance/conformance-oauth-provider.js";
import {
  evaluatePersistenceChecks,
  persistenceArtifactArrayKeys,
  persistenceConformanceAuthMethods,
  persistenceSecrets,
  type PersistenceConformanceArtifacts
} from "../conformance/persistence-conformance-contract.js";
import {
  decodeConformanceValue,
  encodeConformanceValue,
  type ConformanceRpcRequest,
  isRecord
} from "./conformance-protocol.js";

const authMethods = new Set<string>(persistenceConformanceAuthMethods);

const storageMethods = new Set([
  "consumeMfaChallenge",
  "consumeOAuthTransaction",
  "consumeRecoveryCode",
  "consumeSmsOtp",
  "consumeToken",
  "consumeWebAuthnChallenge",
  "createAccount",
  "createMfaChallenge",
  "createOAuthTransaction",
  "createPasskeyCredential",
  "createSmsOtp",
  "createToken",
  "createTotpFactor",
  "createUser",
  "createWebAuthnChallenge",
  "getLatestSmsOtp",
  "getPasskeyCredentialById",
  "getUserByEmail",
  "getUserByPhone",
  "incrementSmsOtpAttempts",
  "listAccountsByUserId",
  "listOrganisationMembers",
  "listUsers",
  "listSessionsByUserId",
  "replaceRecoveryCodes",
  "rotateOAuthCredential",
  "updatePasskeyCounter",
  "upsertOAuthCredential",
  "useTotpTimestep"
]);

const authorizationStorageMethods = new Set([
  "createAuthorizationClient",
  "createAuthorizationTokens",
  "getAuthorizationAccessTokenByHash",
  "getAuthorizationGrant",
  "getAuthorizationRefreshTokenByHash",
  "rotateAuthorizationRefreshToken",
  "upsertAuthorizationGrant"
]);

const expectedMigrations = [
  "001_initial",
  "002_external_providers",
  "003_oauth_transactions",
  "004_mfa",
  "005_oauth_credentials",
  "006_passkeys",
  "007_plugin_migrations",
  "008_webhooks",
  "009_custom_authorization",
  "010_administration",
  "011_authorization_server"
];

const expectedTables = [
  "own_auth_accounts",
  "own_auth_api_keys",
  "own_auth_audit_events",
  "own_auth_authorization_access_tokens",
  "own_auth_authorization_client_secrets",
  "own_auth_authorization_clients",
  "own_auth_authorization_codes",
  "own_auth_authorization_grants",
  "own_auth_authorization_interactions",
  "own_auth_authorization_refresh_tokens",
  "own_auth_invitations",
  "own_auth_mfa_challenges",
  "own_auth_mfa_factors",
  "own_auth_migrations",
  "own_auth_oauth_credentials",
  "own_auth_oauth_transactions",
  "own_auth_oidc_subjects",
  "own_auth_organisation_members",
  "own_auth_organisations",
  "own_auth_passkeys",
  "own_auth_plugin_migrations",
  "own_auth_rate_limits",
  "own_auth_recovery_codes",
  "own_auth_sessions",
  "own_auth_sms_otps",
  "own_auth_tokens",
  "own_auth_users",
  "own_auth_webauthn_challenges",
  "own_auth_webhook_attempts",
  "own_auth_webhook_deliveries",
  "own_auth_webhook_events"
];

export async function handleAuthRpc(request: Request, database: D1DatabaseLike): Promise<Response> {
  const rpc = await readRpc(request);
  if (!authMethods.has(rpc.method)) return methodNotAllowed();
  const auth = createWorkerAuth(database, rpc.options);
  return invoke(auth, rpc);
}

export async function handleStorageRpc(
  request: Request,
  database: D1DatabaseLike
): Promise<Response> {
  const rpc = await readRpc(request);
  if (!storageMethods.has(rpc.method)) return methodNotAllowed();
  return invoke(createD1Persistence(database).storage, rpc);
}

export async function handleAuthorizationStorageRpc(
  request: Request,
  database: D1DatabaseLike
): Promise<Response> {
  const rpc = await readRpc(request);
  if (!authorizationStorageMethods.has(rpc.method)) return methodNotAllowed();
  const storage = createD1Persistence(database).storage.authorizationServerStorage;
  return invoke(storage as AuthorizationServerStorage, rpc);
}

export async function handleRateLimitRpc(
  request: Request,
  database: D1DatabaseLike
): Promise<Response> {
  const rpc = await readRpc(request);
  if (rpc.method !== "hit" && rpc.method !== "reset") return methodNotAllowed();
  return invoke(createD1Persistence(database).rateLimitStore, rpc);
}

export async function handleWebhookVerification(request: Request): Promise<Response> {
  const event = await verifyOwnAuthWebhook({
    body: new Uint8Array(await request.arrayBuffer()),
    headers: request.headers,
    secrets: ["cloudflare-webhook-verifier-secret-32-bytes"],
    claimEvent: async () => true
  });
  return Response.json({ id: event.id, type: event.type });
}

export async function handleWebhookFlow(database: D1DatabaseLike): Promise<Response> {
  let sentBody = "";
  let sentHeaders = new Headers();
  const secret = "cloudflare-webhook-delivery-secret-32-bytes";
  const auth = createOwnAuth({
    ...createD1Persistence(database),
    tokenPepper: "cloudflare-webhook-flow",
    webhooks: {
      endpoints: [{
        id: "worker-events",
        url: "https://hooks.example.com/own-auth",
        secret,
        events: ["user.signed_up"]
      }],
      fetch: async (_input, init) => {
        sentBody = String(init?.body ?? "");
        sentHeaders = new Headers(init?.headers);
        return new Response(null, { status: 204 });
      }
    }
  });

  await auth.signUpEmailPassword({
    email: `worker-webhook-${crypto.randomUUID()}@example.com`,
    password: "correct-horse"
  });
  const queued = await auth.listWebhookDeliveries();
  const processed = await auth.processWebhookDeliveries();
  const [delivery] = await auth.listWebhookDeliveries();
  const verified = await verifyOwnAuthWebhook({
    body: sentBody,
    headers: sentHeaders,
    secrets: [secret],
    claimEvent: async () => true
  });

  return Response.json({
    queued: queued.length === 1 && queued[0]?.status === "pending",
    processed: processed.delivered === 1 && processed.leaseLost === 0,
    settled: delivery?.status === "delivered" && delivery.attempts.length === 1,
    verified: verified.id === delivery?.eventId && verified.type === "user.signed_up"
  });
}

export async function handleInspection(
  request: Request,
  database: D1DatabaseLike
): Promise<Response> {
  const artifacts = decodeConformanceValue(await request.json());
  if (!isPersistenceArtifacts(artifacts)) {
    return Response.json({ error: { message: "Invalid inspection payload" } }, { status: 400 });
  }
  return encodedJson(await inspectPersistence(database, artifacts));
}

export async function handleSchemaInspection(database: D1DatabaseLike): Promise<Response> {
  const migrations = await database.prepare(
    "select version from own_auth_migrations order by version"
  ).all<{ version: string }>();
  const tables = await database.prepare(
    "select name from sqlite_master where type = 'table' and name like 'own_auth_%' order by name"
  ).all<{ name: string }>();
  return encodedJson({
    migrationsAreCurrent: sameStrings(
      migrations.results?.map(({ version }) => version) ?? [],
      expectedMigrations
    ),
    tablesAreComplete: sameStrings(
      tables.results?.map(({ name }) => name) ?? [],
      expectedTables
    )
  });
}

export async function handleCloseLifecycle(database: D1DatabaseLike): Promise<Response> {
  const auth = createWorkerAuth(database);
  await Promise.all([auth.close(), auth.close()]);
  try {
    await auth.getCurrentSession("closed-session-token");
  } catch (error) {
    return encodedJson({
      closeIsIdempotent: true,
      queriesFailAfterClose:
        error instanceof AuthError &&
        error.code === "auth_closed" &&
        error.message === "Own Auth has been closed"
    });
  }
  return encodedJson({ closeIsIdempotent: true, queriesFailAfterClose: false });
}

export function conformanceErrorResponse(error: unknown): Response {
  if (error instanceof AuthError) {
    return Response.json(
      { error: { code: error.code, message: error.safeMessage } },
      { status: error.statusCode }
    );
  }
  return Response.json(
    { error: { message: "Conformance request failed" } },
    { status: 500 }
  );
}

function createWorkerAuth(
  database: D1DatabaseLike,
  options: ConformanceRpcRequest["options"] = {}
) {
  return createOwnAuth({
    ...createD1Persistence(database),
    emailProvider: new MemoryEmailProvider(),
    smsProvider: new MemorySmsProvider(),
    exposeRawTokens: true,
    baseUrl: "http://localhost:3000",
    tokenPepper: "cloudflare-worker-conformance",
    encryption: {
      current: { id: "worker-conformance", key: new Uint8Array(32).fill(7) }
    },
    oauth: { adapters: [createConformanceGoogleProvider()] },
    passkeys: {
      rpId: "localhost",
      rpName: "Own Auth Worker conformance",
      origins: ["http://localhost:3000"]
    },
    sms: options?.smsMaxAttempts
      ? { maxAttempts: options.smsMaxAttempts }
      : undefined
  });
}

async function readRpc(request: Request): Promise<ConformanceRpcRequest> {
  const decoded = decodeConformanceValue(await request.json());
  if (
    !isRecord(decoded) ||
    typeof decoded.method !== "string" ||
    !Array.isArray(decoded.args)
  ) {
    throw new AuthError("validation_error", "Invalid conformance request", 400);
  }
  return decoded as unknown as ConformanceRpcRequest;
}

async function invoke(target: object, rpc: ConformanceRpcRequest): Promise<Response> {
  const method = (target as Record<string, unknown>)[rpc.method];
  if (typeof method !== "function") return methodNotAllowed();
  return encodedJson(await method.apply(target, rpc.args));
}

function encodedJson(value: unknown, init?: ResponseInit): Response {
  return Response.json(encodeConformanceValue(value), init);
}

function methodNotAllowed(): Response {
  return Response.json({ error: { message: "Conformance method is not allowed" } }, { status: 405 });
}

async function inspectPersistence(
  database: D1DatabaseLike,
  artifacts: PersistenceConformanceArtifacts
): Promise<Record<string, boolean>> {
  const checks = await evaluatePersistenceChecks(artifacts, {
    countExact: (table, column, values) => countExact(database, table, column, values),
    countWhere: (table, column, value) => countWhere(database, table, column, value)
  });

  const allSecrets = persistenceSecrets(artifacts);
  const auditRows = await database.prepare(
    "select event_type, metadata from own_auth_audit_events"
  ).all<{ event_type: string; metadata: string }>();
  const deletionAudit = auditRows.results?.some(({ event_type, metadata }) => {
    if (event_type !== "organisation.deleted") return false;
    return safeJsonRecord(metadata).organisationId === artifacts.organisationId;
  }) ?? false;

  return {
    ...checks,
    auditMetadataExcludesSecrets: (auditRows.results ?? []).every(({ metadata }) =>
      allSecrets.every((secret) => !metadata.includes(secret))
    ),
    rateLimitsWerePersisted:
      await countRows(database, "own_auth_rate_limits") > 0,
    organisationDeletionWasAudited: deletionAudit
  };
}

async function countExact(
  database: D1DatabaseLike,
  table: string,
  column: string,
  values: readonly string[]
): Promise<number> {
  if (values.length === 0) return 0;
  const placeholders = values.map((_, index) => `?${index + 1}`).join(", ");
  const row = await database.prepare(
    `select count(*) as count from ${identifier(table)} ` +
    `where ${identifier(column)} in (${placeholders})`
  ).bind(...values).first<{ count: number }>();
  return Number(row?.count ?? 0);
}

async function countWhere(
  database: D1DatabaseLike,
  table: string,
  column: string,
  value: string
): Promise<number> {
  const row = await database.prepare(
    `select count(*) as count from ${identifier(table)} where ${identifier(column)} = ?1`
  ).bind(value).first<{ count: number }>();
  return Number(row?.count ?? 0);
}

async function countRows(database: D1DatabaseLike, table: string): Promise<number> {
  const row = await database.prepare(
    `select count(*) as count from ${identifier(table)}`
  ).first<{ count: number }>();
  return Number(row?.count ?? 0);
}

function identifier(value: string): string {
  if (!/^[a-z_][a-z0-9_]*$/.test(value)) {
    throw new Error(`Unsafe D1 identifier: ${value}`);
  }
  return `"${value}"`;
}

function safeJsonRecord(value: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(value);
    return isRecord(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function sameStrings(actual: string[], expected: string[]): boolean {
  return JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort());
}

function isPersistenceArtifacts(value: unknown): value is PersistenceConformanceArtifacts {
  return isRecord(value) &&
    typeof value.organisationId === "string" &&
    typeof value.ownerUserId === "string" &&
    isRecord(value.continuity) &&
    typeof value.continuity.email === "string" &&
    typeof value.continuity.sessionToken === "string" &&
    persistenceArtifactArrayKeys.every((key) => {
      const entry = value[key];
      return Array.isArray(entry) && entry.every((item) => typeof item === "string");
    });
}
