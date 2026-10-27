import {
  ownAuthEndpointContract,
  type OwnAuthEndpointDefinition,
  type OwnAuthHttpErrorCode
} from "./contract.js";
import { OWN_AUTH_VERSION } from "../version.js";
import { isRecord } from "../value-guards.js";
import { defaultMfaCookieName, defaultSessionCookieName } from "./cookies.js";
import { normalizeOwnAuthBasePath } from "./routing.js";

export interface OwnAuthOpenApiOptions {
  title?: string;
  version?: string;
  basePath?: string;
  serverUrl?: string;
  sessionCookieName?: string;
  mfaCookieName?: string;
  includeAdministration?: boolean;
}

export interface OwnAuthOpenApiDocument {
  openapi: "3.1.0";
  info: { title: string; version: string };
  servers?: Array<{ url: string }>;
  paths: Record<string, Record<string, unknown>>;
  components: Record<string, unknown>;
}

export function createOwnAuthOpenApiDocument(
  options: OwnAuthOpenApiOptions = {}
): OwnAuthOpenApiDocument {
  const basePath = normalizeOwnAuthBasePath(options.basePath ?? "/api/auth");
  const document: OwnAuthOpenApiDocument = {
    openapi: "3.1.0",
    info: {
      title: options.title ?? "Own Auth HTTP API",
      version: options.version ?? OWN_AUTH_VERSION
    },
    paths: {},
    components: {
      securitySchemes: {
        sessionCookie: {
          type: "apiKey",
          in: "cookie",
          name: options.sessionCookieName ?? defaultSessionCookieName
        },
        bearerSession: {
          type: "http",
          scheme: "bearer"
        },
        mfaChallengeCookie: {
          type: "apiKey",
          in: "cookie",
          name: options.mfaCookieName ?? defaultMfaCookieName
        }
      },
      schemas: {
        OwnAuthError: {
          type: "object",
          required: ["error"],
          additionalProperties: false,
          properties: {
            error: {
              type: "object",
              required: ["code", "message"],
              additionalProperties: false,
              properties: {
                code: { type: "string" },
                message: { type: "string" },
                details: {
                  type: "object", additionalProperties: false,
                  properties: {
                    organisationIds: { type: "array", items: { type: "string" } },
                    stores: { type: "array", items: { type: "string" } }
                  }
                }
              }
            }
          }
        }
      }
    }
  };

  if (options.serverUrl) {
    document.servers = [{ url: options.serverUrl }];
  }

  for (const endpoint of ownAuthEndpointContract) {
    if (endpoint.feature === "administration" && !options.includeAdministration) {
      continue;
    }
    const path = `${basePath}${endpoint.path}`;
    const pathItem = document.paths[path] ?? {};
    pathItem[endpoint.method.toLowerCase()] = operationFor(endpoint);
    document.paths[path] = pathItem;
  }

  return document;
}

function operationFor(endpoint: OwnAuthEndpointDefinition): Record<string, unknown> {
  const operation: Record<string, unknown> = {
    operationId: endpoint.id,
    summary: endpoint.summary,
    tags: [tagFor(endpoint.path)],
    responses: responsesFor(endpoint),
    "x-own-auth-errors": endpoint.errors
  };

  addRequestContract(operation, endpoint);

  if (endpoint.session === "required") {
    operation.security = [{ sessionCookie: [] }, { bearerSession: [] }];
  } else if (endpoint.session === "optional" || endpoint.session === "clear") {
    operation.security = [{}, { sessionCookie: [] }, { bearerSession: [] }];
  }
  if (endpoint.id === "completeMfaTotp" || endpoint.id === "completeMfaRecovery") {
    operation.security = [{ mfaChallengeCookie: [] }];
  } else if (endpoint.id === "beginPasskeyAuthentication") {
    operation.security = [{}, { mfaChallengeCookie: [] }];
  }

  return operation;
}

function responsesFor(endpoint: OwnAuthEndpointDefinition): Record<string, unknown> {
  if (endpoint.responseKind === "oauth_callback") {
    const responses: Record<string, unknown> = {
      "200": {
        description: "Popup callback response",
        content: { "text/html": { schema: { type: "string" } } }
      },
      "302": {
        description: "Redirect callback response",
        headers: { location: { schema: { type: "string", format: "uri" } } }
      },
      "400": errorOpenApiResponse("Invalid OAuth callback request"),
      "429": errorOpenApiResponse("Rate limit exceeded"),
      "500": errorOpenApiResponse("Internal error")
    };
    addBodyTransportErrors(responses, endpoint);
    return responses;
  }
  if (endpoint.responseKind === "saml_callback") {
    const responses: Record<string, unknown> = {
      "302": {
        description: "SAML callback redirect",
        headers: { location: { schema: { type: "string", format: "uri" } } }
      },
      "400": errorOpenApiResponse("Invalid SAML callback request"),
      "401": errorOpenApiResponse("Invalid SAML response"),
      "429": errorOpenApiResponse("Rate limit exceeded"),
      "500": errorOpenApiResponse("Internal error")
    };
    addBodyTransportErrors(responses, endpoint);
    return responses;
  }
  if (endpoint.responseKind === "xml") {
    return {
      "200": {
        description: "SAML service-provider metadata",
        content: { "application/samlmetadata+xml": { schema: endpoint.response } }
      },
      "404": errorOpenApiResponse("SAML connection not found"),
      "500": errorOpenApiResponse("Internal error")
    };
  }
  const responses: Record<string, unknown> = {
    "200": {
      description: "Successful response",
      content: {
        "application/json": { schema: endpoint.response }
      }
    }
  };

  const statuses = errorStatusesFor(endpoint.errors);
  if (endpoint.pendingResponse) responses["202"] = {
    description: "Authentication records deleted; remaining Own Auth cleanup is pending",
    content: { "application/json": { schema: endpoint.response } }
  };
  statuses.add(400);
  statuses.add(403);
  statuses.add(500);
  for (const status of statuses) {
    responses[String(status)] = {
      description: errorDescription(status),
      content: {
        "application/json": {
          schema: { $ref: "#/components/schemas/OwnAuthError" }
        }
      }
    };
  }
  addBodyTransportErrors(responses, endpoint);

  return responses;
}

function addBodyTransportErrors(
  responses: Record<string, unknown>,
  endpoint: OwnAuthEndpointDefinition
): void {
  if (!endpoint.request || (endpoint.requestTransport ?? "json") === "query") {
    return;
  }
  responses["413"] = errorOpenApiResponse("Request body is too large");
  responses["415"] = errorOpenApiResponse("Unsupported request content type");
}

function errorStatusesFor(errors: readonly OwnAuthHttpErrorCode[]): Set<number> {
  return new Set(errors.flatMap(statusesForError));
}

function statusesForError(code: OwnAuthHttpErrorCode): number[] {
  if (code === "oauth_provider_error") return [401, 502];
  return [statusForError(code)];
}

function addRequestContract(
  operation: Record<string, unknown>,
  endpoint: OwnAuthEndpointDefinition
): void {
  if (!endpoint.request) return;
  const transport = endpoint.requestTransport ?? "json";
  if (transport === "query") {
    operation.parameters = queryParametersForSchema(endpoint.request);
    return;
  }
  const contentType = transport === "form"
    ? "application/x-www-form-urlencoded"
    : "application/json";
  operation.requestBody = {
    required: true,
    content: { [contentType]: { schema: endpoint.request } }
  };
}

export function queryParametersForSchema(
  schema: Record<string, unknown>
): Record<string, unknown>[] {
  const properties = isRecord(schema.properties) ? schema.properties : {};
  const required = new Set(Array.isArray(schema.required) ? schema.required : []);
  return Object.entries(properties).map(([name, value]) => ({
    name,
    in: "query",
    required: required.has(name),
    schema: value
  }));
}

function errorOpenApiResponse(description: string): Record<string, unknown> {
  return {
    description,
    content: {
      "application/json": { schema: { $ref: "#/components/schemas/OwnAuthError" } }
    }
  };
}

function statusForError(code: OwnAuthHttpErrorCode): number {
  if (code === "rate_limited" || code === "otp_attempts_exceeded") return 429;
  if (
    code === "email_already_exists" ||
    code === "user_erasure_unsupported" ||
    code === "user_erasure_ownership_required" ||
    code === "erasure_operation_conflict" ||
    code === "erasure_operation_closed" ||
    code === "phone_already_exists" ||
    code === "invite_exists" ||
    code === "already_member" ||
    code === "last_owner" ||
    code === "role_not_configured" ||
    code === "account_linking_required" ||
    code === "oauth_account_conflict" ||
    code === "oauth_verified_email_required" ||
    code === "authentication_method_required"
  ) return 409;
  if (
    code === "permission_denied" ||
    code === "disabled_user" ||
    code === "csrf_failed" ||
    code === "plugin_denied" ||
    code.startsWith("plugin.")
  ) return 403;
  if (
    code === "user_not_found" ||
    code === "erasure_operation_not_found" ||
    code === "organisation_not_found" ||
    code === "member_not_found" ||
    code === "invitation_not_found" ||
    code === "passkey_not_found" ||
    code === "external_credential_missing"
  ) return 404;
  if (
    code === "invalid_credentials" ||
    code === "reauthentication_required" ||
    code === "invalid_session" ||
    code === "invalid_token" ||
    code === "expired_token" ||
    code === "token_already_used" ||
    code === "invalid_otp" ||
    code === "mfa_challenge_invalid" ||
    code === "mfa_code_invalid" ||
    code === "mfa_timestep_reused" ||
    code === "passkey_invalid"
  ) return 401;
  if (code === "plugin_hook_timeout") return 504;
  if (
    code === "internal_error" ||
    code === "encryption_not_configured" ||
    code === "encryption_key_unavailable" ||
    code === "encrypted_data_invalid"
  ) return 500;
  return 400;
}

function errorDescription(status: number): string {
  if (status === 401) return "Authentication failed";
  if (status === 403) return "Request forbidden";
  if (status === 404) return "Resource not found";
  if (status === 409) return "Resource conflict";
  if (status === 429) return "Rate limit exceeded";
  if (status === 500) return "Internal error";
  if (status === 502) return "OAuth provider request failed";
  if (status === 504) return "Plugin hook timed out";
  return "Invalid request";
}

function tagFor(path: string): string {
  const segment = path.split("/").filter(Boolean)[0] ?? "auth";
  return segment.replace(/(^|-)([a-z])/g, (_match, _separator, letter: string) =>
    letter.toUpperCase()
  );
}
