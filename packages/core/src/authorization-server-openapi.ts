import { authorizationServerPaths } from "./authorization-server-constants.js";
import { dpopJwkThumbprintPattern } from "./dpop-crypto.js";
import { OWN_AUTH_VERSION } from "./version.js";

export interface OwnAuthAuthorizationServerOpenApiOptions {
  title?: string;
  version?: string;
  serverUrl?: string;
  includeDeviceAuthorization?: boolean;
}

export interface OwnAuthAuthorizationServerOpenApiDocument {
  openapi: "3.1.0";
  info: { title: string; version: string };
  servers?: Array<{ url: string }>;
  paths: Record<string, Record<string, unknown>>;
  components: Record<string, unknown>;
}

export function createOwnAuthAuthorizationServerOpenApiDocument(
  options: OwnAuthAuthorizationServerOpenApiOptions = {}
): OwnAuthAuthorizationServerOpenApiDocument {
  const includeDeviceAuthorization = options.includeDeviceAuthorization ?? true;
  const document: OwnAuthAuthorizationServerOpenApiDocument = {
    openapi: "3.1.0",
    info: {
      title: options.title ?? "Own Auth Authorization Server",
      version: options.version ?? OWN_AUTH_VERSION
    },
    paths: {
      "/.well-known/oauth-authorization-server": {
        get: discoveryOperation("OAuth authorization-server metadata")
      },
      "/.well-known/openid-configuration": {
        get: discoveryOperation("OpenID Connect provider metadata")
      },
      [authorizationServerPaths.authorization]: {
        get: authorizationOperation()
      },
      ...(includeDeviceAuthorization
        ? {
            [authorizationServerPaths.deviceAuthorization]: {
              post: formOperation({
                operationId: "startDeviceAuthorization",
                summary: "Start an OAuth device authorization flow",
                fields: {
                  client_id: stringSchema(),
                  client_secret: stringSchema(),
                  scope: stringSchema(),
                  resource: { type: "string", format: "uri" },
                  dpop_jkt: {
                    type: "string",
                    pattern: dpopJwkThumbprintPattern
                  }
                },
                response: { $ref: "#/components/schemas/DeviceAuthorizationResponse" }
              })
            }
          }
        : {}),
      [authorizationServerPaths.token]: {
        post: formOperation({
          operationId: "exchangeAuthorizationToken",
          summary: "Exchange an authorization code, refresh token, or device code",
          fields: tokenFields(),
          requiredFields: ["grant_type"],
          dpopHeader: true,
          response: { $ref: "#/components/schemas/TokenResponse" }
        })
      },
      [authorizationServerPaths.revocation]: {
        post: formOperation({
          operationId: "revokeAuthorizationToken",
          summary: "Revoke an access or refresh token",
          fields: {
            token: stringSchema(),
            token_type_hint: stringSchema(),
            client_id: stringSchema(),
            client_secret: stringSchema()
          },
          requiredFields: ["token"],
          dpopHeader: true,
          response: { type: "object", additionalProperties: false }
        })
      },
      [authorizationServerPaths.introspection]: {
        post: formOperation({
          operationId: "introspectAuthorizationToken",
          summary: "Introspect an access or refresh token",
          fields: {
            token: stringSchema(),
            token_type_hint: stringSchema(),
            client_id: stringSchema(),
            client_secret: stringSchema(),
            dpop_proof: stringSchema(),
            request_method: stringSchema(),
            request_url: { type: "string", format: "uri" }
          },
          requiredFields: ["token"],
          response: { $ref: "#/components/schemas/IntrospectionResponse" }
        })
      },
      [authorizationServerPaths.userinfo]: {
        get: userInfoOperation("getAuthorizationUserInfo"),
        post: userInfoOperation("postAuthorizationUserInfo")
      },
      [authorizationServerPaths.jwks]: {
        get: {
          operationId: "getAuthorizationServerJwks",
          summary: "Read authorization-server signing keys",
          responses: jsonResponses({ type: "object" })
        }
      }
    },
    components: {
      securitySchemes: {
        clientBasic: { type: "http", scheme: "basic" },
        bearerToken: { type: "http", scheme: "bearer" },
        dpopToken: { type: "http", scheme: "DPoP" },
        dpopProof: { type: "apiKey", in: "header", name: "DPoP" }
      },
      schemas: {
        ProtocolError: protocolErrorSchema(),
        TokenResponse: tokenResponseSchema(),
        DeviceAuthorizationResponse: deviceAuthorizationResponseSchema(),
        IntrospectionResponse: introspectionResponseSchema()
      }
    }
  };
  if (options.serverUrl) document.servers = [{ url: options.serverUrl }];
  return document;
}

function discoveryOperation(summary: string): Record<string, unknown> {
  return {
    operationId: summary.startsWith("OAuth")
      ? "getOAuthAuthorizationServerMetadata"
      : "getOpenIdConfiguration",
    summary,
    responses: jsonResponses({ type: "object" })
  };
}

function authorizationOperation(): Record<string, unknown> {
  const parameters = [
    queryParameter("response_type", true),
    queryParameter("client_id", true),
    queryParameter("redirect_uri", true, "uri"),
    queryParameter("scope", true),
    queryParameter("state"),
    queryParameter("nonce"),
    queryParameter("code_challenge", true),
    queryParameter("code_challenge_method", true, undefined, ["S256"]),
    queryParameter("prompt"),
    queryParameter("max_age"),
    queryParameter("acr_values"),
    queryParameter("display"),
    queryParameter("ui_locales"),
    queryParameter("claims_locales"),
    queryParameter("login_hint"),
    queryParameter("resource", false, "uri"),
    {
      ...queryParameter("dpop_jkt"),
      description: "RFC 7638 thumbprint of the DPoP public key",
      schema: { type: "string", pattern: dpopJwkThumbprintPattern }
    }
  ];
  return {
    operationId: "startAuthorization",
    summary: "Start an OAuth authorization-code flow",
    parameters,
    responses: {
      "302": {
        description: "Continue to the interaction or registered redirect URI",
        headers: { location: { schema: { type: "string", format: "uri" } } }
      },
      ...errorResponses()
    }
  };
}

function formOperation(input: {
  operationId: string;
  summary: string;
  fields: Record<string, Record<string, unknown>>;
  requiredFields?: string[];
  dpopHeader?: boolean;
  response: Record<string, unknown>;
}): Record<string, unknown> {
  return {
    operationId: input.operationId,
    summary: input.summary,
    ...(input.dpopHeader
      ? { parameters: [headerParameter("DPoP", "A proof JWT for a bound token")] }
      : {}),
    requestBody: {
      required: true,
      content: {
        "application/x-www-form-urlencoded": {
          schema: {
            type: "object",
            properties: input.fields,
            ...(input.requiredFields ? { required: input.requiredFields } : {})
          }
        }
      }
    },
    responses: jsonResponses(input.response)
  };
}

function userInfoOperation(operationId: string): Record<string, unknown> {
  return {
    operationId,
    summary: "Read OpenID Connect claims for an access token",
    parameters: [headerParameter("DPoP", "Required for DPoP-bound tokens")],
    security: [
      { bearerToken: [] },
      { dpopToken: [], dpopProof: [] }
    ],
    responses: jsonResponses({ type: "object" })
  };
}

function tokenFields(): Record<string, Record<string, unknown>> {
  return {
    grant_type: stringSchema(),
    client_id: stringSchema(),
    client_secret: stringSchema(),
    code: stringSchema(),
    redirect_uri: { type: "string", format: "uri" },
    code_verifier: stringSchema(),
    refresh_token: stringSchema(),
    device_code: stringSchema(),
    scope: stringSchema(),
    resource: { type: "string", format: "uri" }
  };
}

function deviceAuthorizationResponseSchema(): Record<string, unknown> {
  return {
    type: "object",
    required: [
      "device_code",
      "user_code",
      "verification_uri",
      "verification_uri_complete",
      "expires_in",
      "interval"
    ],
    properties: {
      device_code: { type: "string" },
      user_code: { type: "string", pattern: "^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$" },
      verification_uri: { type: "string", format: "uri" },
      verification_uri_complete: { type: "string", format: "uri" },
      expires_in: { type: "integer", minimum: 0 },
      interval: { type: "integer", minimum: 1 }
    }
  };
}

function tokenResponseSchema(): Record<string, unknown> {
  return {
    type: "object",
    required: ["token_type", "access_token", "expires_in", "scope"],
    properties: {
      token_type: { type: "string", enum: ["Bearer", "DPoP"] },
      access_token: { type: "string" },
      expires_in: { type: "integer", minimum: 0 },
      refresh_token: { type: "string" },
      id_token: { type: "string" },
      scope: { type: "string" }
    }
  };
}

function introspectionResponseSchema(): Record<string, unknown> {
  return {
    type: "object",
    required: ["active"],
    properties: {
      active: { type: "boolean" },
      scope: { type: "string" },
      client_id: { type: "string" },
      token_type: { type: "string", enum: ["Bearer", "DPoP"] },
      cnf: {
        type: "object",
        required: ["jkt"],
        properties: { jkt: { type: "string" } }
      },
      exp: { type: "integer" },
      iat: { type: "integer" },
      sub: { type: "string" },
      aud: { type: "string", format: "uri" }
    }
  };
}

function jsonResponses(schema: Record<string, unknown>): Record<string, unknown> {
  return {
    "200": {
      description: "Successful response",
      content: { "application/json": { schema } }
    },
    ...errorResponses()
  };
}

function errorResponses(): Record<string, unknown> {
  const response = {
    description: "OAuth protocol error",
    content: {
      "application/json": { schema: { $ref: "#/components/schemas/ProtocolError" } }
    }
  };
  return { "400": response, "401": response, "429": response, "500": response };
}

function protocolErrorSchema(): Record<string, unknown> {
  return {
    type: "object",
    required: ["error"],
    properties: {
      error: { type: "string" },
      error_description: { type: "string" },
      error_uri: { type: "string", format: "uri" }
    }
  };
}

function queryParameter(
  name: string,
  required = false,
  format?: string,
  values?: string[]
): Record<string, unknown> {
  return {
    name,
    in: "query",
    required,
    schema: {
      type: "string",
      ...(format ? { format } : {}),
      ...(values ? { enum: values } : {})
    }
  };
}

function headerParameter(name: string, description: string): Record<string, unknown> {
  return {
    name,
    in: "header",
    required: false,
    description,
    schema: { type: "string" }
  };
}

function stringSchema(): Record<string, unknown> {
  return { type: "string" };
}
