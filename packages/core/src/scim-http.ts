import type { OwnAuth } from "./auth-engine.js";
import { AuthError, isAuthError } from "./errors.js";
import {
  authenticateScimRequest,
  createScimUser,
  deleteScimUser,
  getScimUser,
  listScimUsers,
  replaceScimUser
} from "./scim-internals.js";
import {
  applyScimPatch,
  parseIfMatch,
  parsePagination,
  parseScimFilter,
  parseScimUserPayload,
  resourceTypes,
  schemas,
  scimErrorSchema,
  scimListSchema,
  scimUserSchema,
  scimUserRepresentation,
  serviceProviderConfig,
  userResourceType,
  userSchema
} from "./scim-protocol.js";
import { ScimProtocolError } from "./scim-protocol-error.js";
import type { RequestContext } from "./types.js";
import { traceHttpEndpoint } from "./telemetry.js";
import type { ScimConnection, ScimUser } from "./scim-types.js";

export interface OwnAuthScimHandlerOptions {
  basePath?: string;
  maxRequestBodyBytes?: number;
  getRequestContext?: (request: Request) => RequestContext | Promise<RequestContext>;
  onError?: (error: unknown, request: Request) => void | Promise<void>;
}

export type OwnAuthScimHandler = (request: Request) => Promise<Response>;

export function createOwnAuthScimHandler(
  auth: OwnAuth<string, string>,
  options: OwnAuthScimHandlerOptions = {}
): OwnAuthScimHandler {
  const basePath = normalizeBasePath(options.basePath ?? "/scim/v2");
  const maximumBodyBytes = positiveInteger(options.maxRequestBodyBytes ?? 256 * 1024);

  return async (request) => {
    const url = new URL(request.url);
    const path = routePath(url.pathname, basePath);
    if (!path || !auth.scim.isConfigured()) return scimError(404, null, "SCIM endpoint not found");
    return traceHttpEndpoint({
      endpointId: `scim.${routeId(request.method, path)}`,
      method: request.method,
      route: `${basePath}${routePattern(path)}`
    }, async () => {
      try {
        const context = await requestContext(request, options);
        const authenticated = await auth.scim[authenticateScimRequest](bearerToken(request), context);
        const baseUrl = `${url.origin}${basePath}`;
        return await dispatch({
          auth,
          request,
          url,
          path,
          baseUrl,
          maximumBodyBytes,
          context,
          connection: authenticated.connection
        });
      } catch (error) {
        if (!(error instanceof ScimProtocolError) && !isAuthError(error)) {
          await reportError(options.onError, error, request);
        }
        return mapError(error);
      }
    });
  };
}

interface DispatchInput {
  auth: OwnAuth<string, string>;
  request: Request;
  url: URL;
  path: string;
  baseUrl: string;
  maximumBodyBytes: number;
  context: RequestContext;
  connection: ScimConnection;
}

async function dispatch(input: DispatchInput): Promise<Response> {
  const { auth, request, url, path, baseUrl, connection, context } = input;
  if (request.method === "GET" && path === "/ServiceProviderConfig") {
    return scimJson(serviceProviderConfig(baseUrl));
  }
  if (request.method === "GET" && path === "/ResourceTypes") {
    return scimJson(resourceTypes(baseUrl));
  }
  if (request.method === "GET" && path === "/ResourceTypes/User") {
    return scimJson(userResourceType(baseUrl));
  }
  if (request.method === "GET" && path === "/Schemas") {
    return scimJson(schemas(baseUrl));
  }
  if (request.method === "GET" && schemaId(path) === scimUserSchema) {
    return scimJson(userSchema(baseUrl));
  }
  if (path === "/Users" && request.method === "POST") {
    const body = await readBody(request, input.maximumBodyBytes);
    const user = await auth.scim[createScimUser](connection, parseScimUserPayload(body), context);
    return userResponse(user, baseUrl, 201);
  }
  if (path === "/Users" && request.method === "GET") {
    const { startIndex, count } = parsePagination(url);
    const page = await auth.scim[listScimUsers](
      connection.id,
      parseScimFilter(url.searchParams.get("filter")),
      startIndex,
      count
    );
    return scimJson({
      schemas: [scimListSchema],
      totalResults: page.totalResults,
      startIndex,
      itemsPerPage: page.users.length,
      Resources: page.users.map((user) => scimUserRepresentation(user, baseUrl))
    });
  }
  const resourceId = userResourceId(path);
  if (!resourceId) return scimError(404, null, "SCIM endpoint not found");
  if (request.method === "GET") {
    return userResponse(await auth.scim[getScimUser](connection.id, resourceId), baseUrl);
  }
  const expectedVersion = parseIfMatch(request.headers.get("if-match"));
  if (request.method === "PUT") {
    const body = await readBody(request, input.maximumBodyBytes);
    const user = await auth.scim[replaceScimUser](
      connection,
      resourceId,
      parseScimUserPayload(body),
      expectedVersion,
      context
    );
    return userResponse(user, baseUrl);
  }
  if (request.method === "PATCH") {
    const current = await auth.scim[getScimUser](connection.id, resourceId);
    const body = await readBody(request, input.maximumBodyBytes);
    const user = await auth.scim[replaceScimUser](
      connection,
      resourceId,
      applyScimPatch(current, body),
      expectedVersion,
      context
    );
    return userResponse(user, baseUrl);
  }
  if (request.method === "DELETE") {
    await auth.scim[deleteScimUser](connection, resourceId, expectedVersion, context);
    return new Response(null, { status: 204, headers: baseHeaders() });
  }
  return scimError(405, null, "Method not allowed");
}

async function readBody(request: Request, maximumBodyBytes: number): Promise<unknown> {
  const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/scim+json") {
    throw new ScimProtocolError(415, "invalidSyntax", "Content-Type must be application/scim+json");
  }
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maximumBodyBytes) {
    throw new ScimProtocolError(413, "tooMany", "SCIM request body is too large");
  }
  const bytes = await request.arrayBuffer();
  if (bytes.byteLength > maximumBodyBytes) {
    throw new ScimProtocolError(413, "tooMany", "SCIM request body is too large");
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
  } catch {
    throw new ScimProtocolError(400, "invalidSyntax", "SCIM request body is invalid JSON");
  }
}

function userResponse(
  user: ScimUser,
  baseUrl: string,
  status = 200
): Response {
  const body = scimUserRepresentation(user, baseUrl);
  const headers = baseHeaders();
  headers.set("etag", body.meta.version);
  headers.set("location", body.meta.location);
  return new Response(JSON.stringify(body), { status, headers });
}

function bearerToken(request: Request): string {
  const authorization = request.headers.get("authorization") ?? "";
  const match = /^Bearer ([^\s]+)$/i.exec(authorization);
  if (!match?.[1]) throw new AuthError("scim_token_invalid", "Invalid SCIM token", 401);
  return match[1];
}

function mapError(error: unknown): Response {
  if (error instanceof ScimProtocolError) {
    return scimError(error.status, error.scimType, error.message);
  }
  if (isAuthError(error)) {
    const scimType = error.code === "validation_error" ? "invalidValue" : null;
    return scimError(error.statusCode, scimType, error.safeMessage, error.statusCode === 401);
  }
  return scimError(500, null, "SCIM request failed");
}

function scimJson(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: baseHeaders() });
}

function scimError(
  status: number,
  scimType: string | null,
  detail: string,
  authenticate = false
): Response {
  const headers = baseHeaders();
  if (authenticate) headers.set("www-authenticate", "Bearer");
  return new Response(JSON.stringify({
    schemas: [scimErrorSchema],
    ...(scimType ? { scimType } : {}),
    detail,
    status: String(status)
  }), { status, headers });
}

function baseHeaders(): Headers {
  return new Headers({
    "cache-control": "no-store",
    "content-type": "application/scim+json; charset=utf-8",
    "x-content-type-options": "nosniff"
  });
}

function normalizeBasePath(value: string): string {
  if (!value.startsWith("/") || value.includes("?") || value.includes("#")) {
    throw new Error("SCIM basePath must be a pathname");
  }
  const normalized = value.replace(/\/+$/, "");
  return normalized || "/";
}

function routePath(pathname: string, basePath: string): string | null {
  if (pathname === basePath) return "/";
  return pathname.startsWith(`${basePath}/`) ? pathname.slice(basePath.length) : null;
}

function userResourceId(path: string): string | null {
  const match = /^\/Users\/([^/]+)$/.exec(path);
  if (!match?.[1]) return null;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    throw new ScimProtocolError(400, "invalidValue", "SCIM resource ID is invalid");
  }
}

function schemaId(path: string): string | null {
  const match = /^\/Schemas\/(.+)$/.exec(path);
  if (!match?.[1]) return null;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    throw new ScimProtocolError(400, "invalidValue", "SCIM schema ID is invalid");
  }
}

function routePattern(path: string): string {
  return userResourceIdSafe(path) ? "/Users/{id}" : path;
}

function routeId(method: string, path: string): string {
  return `${method.toLowerCase()}.${routePattern(path).replace(/[^a-zA-Z]+/g, ".")}`;
}

function userResourceIdSafe(path: string): boolean {
  return /^\/Users\/[^/]+$/.test(path);
}

function positiveInteger(value: number): number {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error("maxRequestBodyBytes must be a positive integer");
  }
  return value;
}

async function requestContext(
  request: Request,
  options: OwnAuthScimHandlerOptions
): Promise<RequestContext> {
  const provided = await options.getRequestContext?.(request);
  return {
    ...provided,
    userAgent: provided?.userAgent ?? request.headers.get("user-agent") ?? undefined
  };
}

async function reportError(
  onError: OwnAuthScimHandlerOptions["onError"],
  error: unknown,
  request: Request
): Promise<void> {
  if (!onError) return;
  try {
    await onError(error, request);
  } catch {
    // Error reporting must not replace the SCIM response.
  }
}

export interface OwnAuthScimOpenApiOptions {
  basePath?: string;
  title?: string;
}

export function createOwnAuthScimOpenApiDocument(
  options: OwnAuthScimOpenApiOptions = {}
) {
  const basePath = normalizeBasePath(options.basePath ?? "/scim/v2");
  const userOperations = {
    get: { summary: "Get SCIM user", responses: { "200": { description: "SCIM User" } } },
    put: { summary: "Replace SCIM user", responses: { "200": { description: "SCIM User" } } },
    patch: { summary: "Patch SCIM user", responses: { "200": { description: "SCIM User" } } },
    delete: { summary: "Delete SCIM user", responses: { "204": { description: "Deleted" } } }
  };
  return {
    openapi: "3.1.0",
    info: { title: options.title ?? "Own Auth SCIM API", version: "2.0" },
    paths: {
      [`${basePath}/ServiceProviderConfig`]: discoveryOperation("Service provider configuration"),
      [`${basePath}/ResourceTypes`]: discoveryOperation("SCIM resource types"),
      [`${basePath}/ResourceTypes/User`]: discoveryOperation("SCIM User resource type"),
      [`${basePath}/Schemas`]: discoveryOperation("SCIM schemas"),
      [`${basePath}/Schemas/{schemaId}`]: discoveryOperation("SCIM User schema"),
      [`${basePath}/Users`]: {
        get: { summary: "List SCIM users", responses: { "200": { description: "SCIM users" } } },
        post: { summary: "Create SCIM user", responses: { "201": { description: "SCIM User" } } }
      },
      [`${basePath}/Users/{id}`]: userOperations
    },
    components: {
      securitySchemes: { scimBearer: { type: "http", scheme: "bearer" } }
    },
    security: [{ scimBearer: [] }]
  } as const;
}

function discoveryOperation(summary: string) {
  return { get: { summary, responses: { "200": { description: summary } } } };
}
