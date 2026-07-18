import {
  AuthError,
  createOwnAuth,
  MemoryEmailProvider,
  MemorySmsProvider
} from "../../dist/index.js";
import { createSaml } from "../../dist/saml.js";
import type {
  AuthorizationServerStorage,
  DeviceAuthorizationStorage,
  DpopStorage
} from "../../dist/index.js";
import {
  createD1Persistence,
  type D1DatabaseLike
} from "../../dist/d1/index.js";
import {
  coreMigrationFiles,
  databaseTables
} from "../../dist/database-metadata.js";
import type { SamlStorage } from "../../dist/saml-storage.js";
import { verifyDpopProof } from "../../dist/dpop-crypto.js";
import { createDpopProof, generateDpopKeyPair } from "../../dist/dpop.js";
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
import { invokeConformanceRpc, readConformanceRpc } from "./worker-rpc.js";

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
  "createOrganisation",
  "createPasskeyCredential",
  "createSession",
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
  "cleanupDpopProofs",
  "consumeDpopAuthorizationCode",
  "consumeDpopProof",
  "createAuthorizationClient",
  "createAuthorizationTokens",
  "createProtectedResource",
  "getAuthorizationAccessTokenByHash",
  "getAuthorizationGrant",
  "getProtectedResourceByIdentifier",
  "getAuthorizationRefreshTokenByHash",
  "findAuthorizationCodeDpopBinding",
  "rotateAuthorizationRefreshToken",
  "upsertAuthorizationGrant"
]);

const deviceAuthorizationStorageMethods = new Set([
  "approveDeviceAuthorization",
  "consumeDeviceAuthorization",
  "createDeviceAuthorization",
  "denyDeviceAuthorization"
]);

const samlStorageMethods = new Set([
  "consumeResponse",
  "createConnection",
  "createTransaction"
]);
const rateLimitMethods = new Set(["hit", "reset"]);

const expectedMigrations = coreMigrationFiles.map((file) => file.replace(/\.sql$/, ""));
const expectedTables = Object.values(databaseTables);

export async function handleAuthRpc(request: Request, database: D1DatabaseLike): Promise<Response> {
  const rpc = await readConformanceRpc(request);
  const auth = createWorkerAuth(database, rpc.options);
  return invokeConformanceRpc(auth, rpc, authMethods);
}

export async function handleStorageRpc(
  request: Request,
  database: D1DatabaseLike
): Promise<Response> {
  const rpc = await readConformanceRpc(request);
  return invokeConformanceRpc(createD1Persistence(database).storage, rpc, storageMethods);
}

export async function handleAuthorizationStorageRpc(
  request: Request,
  database: D1DatabaseLike
): Promise<Response> {
  const rpc = await readConformanceRpc(request);
  const storage = createD1Persistence(database).storage.authorizationServerStorage;
  return invokeConformanceRpc(
    storage as AuthorizationServerStorage & DpopStorage,
    rpc,
    authorizationStorageMethods
  );
}

export async function handleDeviceAuthorizationStorageRpc(
  request: Request,
  database: D1DatabaseLike
): Promise<Response> {
  const rpc = await readConformanceRpc(request);
  const storage = createD1Persistence(database).storage.authorizationServerStorage
    .deviceAuthorizationStorage;
  return invokeConformanceRpc(
    storage as DeviceAuthorizationStorage,
    rpc,
    deviceAuthorizationStorageMethods
  );
}

export async function handleSamlStorageRpc(
  request: Request,
  database: D1DatabaseLike
): Promise<Response> {
  const rpc = await readConformanceRpc(request);
  const storage = createD1Persistence(database).storage.samlStorage;
  return invokeConformanceRpc(storage as SamlStorage, rpc, samlStorageMethods);
}

export async function handleRateLimitRpc(
  request: Request,
  database: D1DatabaseLike
): Promise<Response> {
  const rpc = await readConformanceRpc(request);
  return invokeConformanceRpc(
    createD1Persistence(database).rateLimitStore,
    rpc,
    rateLimitMethods
  );
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

export async function handleDpopCrypto(): Promise<Response> {
  const keyPair = await generateDpopKeyPair();
  const accessToken = "oa_at_cloudflare_dpop_fixture";
  const proof = await createDpopProof({
    keyPair,
    method: "GET",
    url: "https://api.example.com/documents?ignored=true",
    accessToken
  });
  const verified = await verifyDpopProof({
    proof,
    method: "GET",
    url: "https://api.example.com/documents",
    accessToken,
    proofTtlMs: 5 * 60 * 1_000,
    clockSkewMs: 60 * 1_000
  });
  return Response.json({
    proofVerified: verified.jwkThumbprint === keyPair.jwkThumbprint,
    thumbprintValid: /^[A-Za-z0-9_-]{43}$/.test(keyPair.jwkThumbprint)
  });
}

export async function handleSamlEngineQualification(): Promise<Response> {
  const saml = createSaml();
  const connection = {
    acsUrl: "https://app.example.com/saml/acs",
    idpEntityId: "https://idp.example.com/metadata",
    ssoUrl: "https://idp.example.com/sso",
    idpCertificates: ["AA=="],
    spEntityId: "https://app.example.com/saml/metadata"
  };
  const metadata = saml.createMetadata(connection);
  const authorizeUrl = new URL(await saml.createAuthorizeUrl({
    connection,
    requestId: "_worker_request",
    relayState: "relay-state"
  }));
  return Response.json({
    metadataGenerated:
      metadata.includes("EntityDescriptor") &&
      metadata.includes("https://app.example.com/saml/acs"),
    redirectGenerated:
      authorizeUrl.origin === "https://idp.example.com" &&
      authorizeUrl.searchParams.has("SAMLRequest") &&
      authorizeUrl.searchParams.get("RelayState") === "relay-state"
  });
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

function encodedJson(value: unknown, init?: ResponseInit): Response {
  return Response.json(encodeConformanceValue(value), init);
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
