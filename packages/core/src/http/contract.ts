import {
  authSessionSchema,
  nullableStringSchema,
  objectSchema,
  openObjectSchema,
  publicAdministrationAuditEventSchema,
  publicAdministrationSessionSchema,
  publicAdministrationUserSchema,
  publicAuthUserSchema,
  publicPasskeySchema,
  signInSchema,
  stringSchema
} from "./contract-schemas.js";
import type {
  JsonSchema,
  OwnAuthEndpointDefinition,
  OwnAuthEndpointId
} from "./contract-types.js";
import { externalAccountProviders } from "../oauth-types.js";
import { cloneAndDeepFreeze } from "../immutable-config.js";
import { organisationRolePattern } from "../authorization.js";

export * from "./contract-schemas.js";
export type * from "./contract-types.js";

const emailSchema = stringSchema("email");
const emailRequestSchema = objectSchema({ email: emailSchema }, ["email"]);
const tokenSchema = objectSchema({ token: stringSchema() }, ["token"]);
const successSchema = objectSchema({ success: { const: true } }, ["success"]);
const userResponseSchema = objectSchema({ user: publicAuthUserSchema }, ["user"]);
const deliverySchema = objectSchema(
  {
    sent: { type: "boolean" },
    expiresAt: nullableStringSchema,
    delivery: objectSchema(
      {
        status: { type: "string", enum: ["sent", "failed"] },
        reason: {
          type: "string",
          enum: ["quota_exhausted", "provider_rejected", "transient_error", "invalid_request"]
        }
      },
      ["status"]
    )
  },
  ["sent", "expiresAt", "delivery"]
);
const smsPurposeSchema: JsonSchema = {
  type: "string",
  enum: ["phone_login", "phone_verification", "account_recovery"]
};
const oauthProviderSchema: JsonSchema = {
  type: "string",
  enum: externalAccountProviders
};
const publicOrganisationSchema = objectSchema(
  { id: stringSchema(), name: stringSchema(), slug: stringSchema() },
  ["id", "name", "slug"]
);
const publicOrganisationMemberSchema = objectSchema(
  {
    id: stringSchema(),
    organisationId: stringSchema(),
    userId: stringSchema(),
    role: { type: "string", pattern: organisationRolePattern },
    joinedAt: nullableStringSchema
  },
  ["id", "organisationId", "userId", "role", "joinedAt"]
);
const oauthCallbackSchema = objectSchema(
  { status: { type: "string", enum: ["complete", "mfa_required", "linked"] } },
  ["status"]
);
const oauthCallbackRequestSchema = objectSchema(
  {
    code: stringSchema(),
    state: stringSchema(),
    error: stringSchema(),
    error_description: stringSchema(),
    id_token: stringSchema(),
    user: stringSchema()
  },
  [],
  true
);
const passkeyResponseSchema = objectSchema({ response: openObjectSchema, name: stringSchema() }, ["response"]);
const deliveryErrors = ["rate_limited", "validation_error"] as const;
const tokenErrors = ["invalid_token", "expired_token", "token_already_used", "rate_limited"] as const;
const oauthErrors = [
  "oauth_transaction_invalid",
  "oauth_provider_error",
  "account_linking_required",
  "oauth_account_conflict",
  "oauth_verified_email_required",
  "rate_limited"
] as const;
const samlErrors = [
  "saml_connection_not_found",
  "saml_connection_disabled",
  "saml_transaction_invalid",
  "saml_response_invalid",
  "saml_signature_algorithm_unsupported",
  "saml_identity_conflict",
  "saml_verified_email_required",
  "saml_membership_required",
  "account_linking_required",
  "authentication_method_required",
  "rate_limited"
] as const;
const mfaErrors = [
  "mfa_challenge_invalid",
  "mfa_code_invalid",
  "mfa_timestep_reused",
  "rate_limited"
] as const;
const administrationErrors = [
  "invalid_session",
  "permission_denied",
  "user_not_found",
  "rate_limited",
  "validation_error"
] as const;
const administrationUserIdSchema = objectSchema(
  { userId: stringSchema() },
  ["userId"]
);
const administrationMutationSchema = objectSchema(
  {
    userId: stringSchema(),
    reason: stringSchema()
  },
  ["userId", "reason"]
);
const administrationUserResponseSchema = objectSchema(
  { user: publicAdministrationUserSchema },
  ["user"]
);

type OwnAuthEndpointSpec = Omit<OwnAuthEndpointDefinition, "id">;
type OwnAuthEndpointSpecMap = { readonly [Id in OwnAuthEndpointId]: OwnAuthEndpointSpec };
type OwnAuthEndpointMap = {
  readonly [Id in OwnAuthEndpointId]: Readonly<OwnAuthEndpointDefinition & { id: Id }>;
};

const ownAuthEndpointSpecs = {
  signUpEmailPassword: endpoint("POST", "/sign-up/email", "Create a user with an email and password", {
    request: objectSchema(
      { email: emailSchema, password: stringSchema(), name: stringSchema() },
      ["email", "password"]
    ),
    response: authSessionSchema,
    errors: [
      "email_already_exists",
      "weak_password",
      "password_too_long",
      "rate_limited",
      "validation_error"
    ],
    session: "create"
  }),
  signInEmailPassword: endpoint("POST", "/sign-in/email", "Sign in with an email and password", {
    request: objectSchema({ email: emailSchema, password: stringSchema() }, ["email", "password"]),
    response: signInSchema,
    errors: ["invalid_credentials", "disabled_user", "rate_limited", "validation_error"],
    session: "create"
  }),
  getSession: endpoint("GET", "/session", "Get the current session", {
    response: objectSchema({ session: { anyOf: [authSessionSchema, { type: "null" }] } }, ["session"]),
    errors: [], session: "optional"
  }),
  signOut: endpoint("POST", "/sign-out", "Revoke the current session", {
    response: successSchema, errors: [], session: "clear"
  }),
  changePassword: endpoint("POST", "/password/change", "Change the current user's password", {
    request: objectSchema(
      { currentPassword: stringSchema(), newPassword: stringSchema() },
      ["currentPassword", "newPassword"]
    ),
    response: userResponseSchema,
    errors: [
      "invalid_session",
      "invalid_credentials",
      "weak_password",
      "password_too_long",
      "rate_limited"
    ],
    session: "required"
  }),
  requestMagicLink: endpoint("POST", "/magic-link/request", "Send a magic link", {
    request: objectSchema({ email: emailSchema, redirectUrl: stringSchema("uri-reference") }, ["email"]),
    response: deliverySchema, errors: [...deliveryErrors, "redirect_not_allowed"], session: "none"
  }),
  verifyMagicLink: endpoint("POST", "/magic-link/verify", "Verify a magic link", {
    request: tokenSchema, response: signInSchema, errors: tokenErrors, session: "create"
  }),
  requestEmailVerification: endpoint("POST", "/email-verification/request", "Send an email verification link", {
    request: emailRequestSchema, response: deliverySchema, errors: deliveryErrors, session: "none"
  }),
  verifyEmail: endpoint("POST", "/email-verification/verify", "Verify an email address", {
    request: tokenSchema, response: userResponseSchema, errors: tokenErrors, session: "none"
  }),
  requestPasswordReset: endpoint("POST", "/password-reset/request", "Send a password reset link", {
    request: emailRequestSchema, response: deliverySchema, errors: deliveryErrors, session: "none"
  }),
  resetPassword: endpoint("POST", "/password-reset/confirm", "Reset a password", {
    request: objectSchema({ token: stringSchema(), newPassword: stringSchema() }, ["token", "newPassword"]),
    response: userResponseSchema,
    errors: [...tokenErrors, "weak_password", "password_too_long"],
    session: "clear"
  }),
  requestSmsOtp: endpoint("POST", "/sms/request", "Send an SMS one-time code", {
    request: objectSchema({ phone: stringSchema(), purpose: smsPurposeSchema }, ["phone"]),
    response: deliverySchema,
    errors: [
      ...deliveryErrors,
      "invalid_session",
      "disabled_user",
      "user_not_found"
    ],
    session: "optional"
  }),
  verifySmsOtp: endpoint("POST", "/sms/verify", "Verify an SMS one-time code", {
    request: objectSchema(
      { phone: stringSchema(), code: stringSchema(), purpose: smsPurposeSchema },
      ["phone", "code"]
    ),
    response: { anyOf: [signInSchema, objectSchema({ status: { const: "verified" }, user: publicAuthUserSchema }, ["status", "user"])] },
    errors: [
      "invalid_otp",
      "otp_attempts_exceeded",
      "user_not_found",
      "rate_limited",
      "validation_error"
    ],
    session: "optional"
  }),
  acceptInvite: endpoint("POST", "/invitations/accept", "Accept an organisation invitation", {
    request: tokenSchema,
    response: objectSchema(
      { organisation: publicOrganisationSchema, member: publicOrganisationMemberSchema },
      ["organisation", "member"]
    ),
    errors: [
      ...tokenErrors,
      "invalid_session",
      "permission_denied",
      "role_not_configured"
    ],
    session: "required"
  }),
  oauthStart: endpoint("POST", "/oauth/start", "Start OAuth authorization", {
    request: objectSchema({
      provider: oauthProviderSchema,
      intent: { type: "string", enum: ["sign_in", "link"] },
      destination: stringSchema("uri-reference"),
      mode: { type: "string", enum: ["redirect", "popup"] },
      openerOrigin: stringSchema("uri")
    }, ["provider"]),
    response: objectSchema({ url: stringSchema("uri"), expiresAt: stringSchema("date-time") }, ["url", "expiresAt"]),
    errors: ["redirect_not_allowed", "rate_limited", "validation_error"], session: "optional"
  }),
  oauthGoogleCallback: oauthCallback("GET", "/oauth/google/callback", "Complete Google OAuth"),
  oauthGitHubCallback: oauthCallback("GET", "/oauth/github/callback", "Complete GitHub OAuth"),
  oauthAppleCallback: oauthCallback("GET", "/oauth/apple/callback", "Complete Apple OAuth"),
  oauthAppleCallbackPost: oauthCallback("POST", "/oauth/apple/callback", "Complete Apple form-post OAuth", "form"),
  prepareGoogleOneTap: endpoint("POST", "/oauth/google/one-tap/prepare", "Prepare Google One Tap", {
    response: objectSchema({ nonce: stringSchema(), expiresAt: stringSchema("date-time") }, ["nonce", "expiresAt"]),
    errors: ["rate_limited", "validation_error"], session: "none"
  }),
  signInGoogleOneTap: endpoint("POST", "/oauth/google/one-tap/verify", "Verify Google One Tap", {
    request: objectSchema({ credential: stringSchema(), nonce: stringSchema() }, ["credential", "nonce"]),
    response: signInSchema, errors: oauthErrors, session: "create"
  }),
  unlinkOAuthProvider: endpoint("POST", "/oauth/unlink", "Unlink an OAuth provider", {
    request: objectSchema({ provider: oauthProviderSchema, providerAccountId: stringSchema() }, ["provider", "providerAccountId"]),
    response: successSchema,
    errors: ["invalid_session", "authentication_method_required", "invalid_credentials"],
    session: "required"
  }),
  samlStart: endpoint("POST", "/saml/start", "Start SAML sign-in", {
    request: objectSchema({
      connectionId: stringSchema(),
      intent: { type: "string", enum: ["sign_in", "link"] },
      destination: stringSchema("uri-reference")
    }, ["connectionId"]),
    response: objectSchema(
      { url: stringSchema("uri"), expiresAt: stringSchema("date-time") },
      ["url", "expiresAt"]
    ),
    errors: [
      "saml_connection_not_found",
      "saml_connection_disabled",
      "redirect_not_allowed",
      "invalid_session",
      "rate_limited"
    ],
    session: "optional",
    feature: "saml"
  }),
  samlAcs: endpoint("POST", "/saml/acs", "Complete SAML sign-in", {
    request: objectSchema(
      { SAMLResponse: stringSchema(), RelayState: stringSchema() },
      ["SAMLResponse", "RelayState"]
    ),
    requestTransport: "form",
    response: oauthCallbackSchema,
    responseKind: "saml_callback",
    errors: samlErrors,
    session: "create",
    csrf: "saml_state",
    feature: "saml"
  }),
  samlMetadata: endpoint("GET", "/saml/metadata", "Get SAML service-provider metadata", {
    request: objectSchema({ connectionId: stringSchema() }, ["connectionId"]),
    requestTransport: "query",
    response: { type: "string" },
    responseKind: "xml",
    errors: ["saml_connection_not_found", "saml_connection_disabled"],
    session: "none",
    feature: "saml"
  }),
  completeMfaTotp: endpoint("POST", "/mfa/totp/complete", "Complete MFA with TOTP", {
    request: objectSchema({ code: stringSchema() }, ["code"]), response: authSessionSchema,
    errors: mfaErrors, session: "create"
  }),
  completeMfaRecovery: endpoint("POST", "/mfa/recovery/complete", "Complete MFA with a recovery code", {
    request: objectSchema({ code: stringSchema() }, ["code"]), response: authSessionSchema,
    errors: mfaErrors, session: "create"
  }),
  beginTotpEnrollment: endpoint("POST", "/mfa/totp/enroll", "Begin TOTP enrollment", {
    response: objectSchema({ factorId: stringSchema(), secret: stringSchema(), uri: stringSchema("uri") }, ["factorId", "secret", "uri"]),
    errors: ["invalid_session", "encryption_not_configured"], session: "required"
  }),
  confirmTotpEnrollment: endpoint("POST", "/mfa/totp/confirm", "Confirm TOTP enrollment", {
    request: objectSchema({ factorId: stringSchema(), code: stringSchema() }, ["factorId", "code"]),
    response: objectSchema({ recoveryCodes: { type: "array", items: stringSchema() } }, ["recoveryCodes"]),
    errors: ["invalid_session", "mfa_code_invalid"], session: "required"
  }),
  disableTotp: endpoint("POST", "/mfa/totp/disable", "Disable TOTP", {
    request: objectSchema({ code: stringSchema() }, ["code"]), response: successSchema,
    errors: ["invalid_session", "mfa_code_invalid", "mfa_timestep_reused"], session: "required"
  }),
  regenerateRecoveryCodes: endpoint("POST", "/mfa/recovery/regenerate", "Regenerate recovery codes", {
    request: objectSchema({ code: stringSchema() }, ["code"]),
    response: objectSchema({ recoveryCodes: { type: "array", items: stringSchema() } }, ["recoveryCodes"]),
    errors: ["invalid_session", "mfa_code_invalid", "mfa_timestep_reused"], session: "required"
  }),
  beginPasskeyRegistration: endpoint("POST", "/passkeys/register/options", "Create passkey registration options", {
    response: objectSchema({ options: openObjectSchema }, ["options"]), errors: ["invalid_session", "validation_error"], session: "required"
  }),
  completePasskeyRegistration: endpoint("POST", "/passkeys/register/verify", "Verify passkey registration", {
    request: passkeyResponseSchema,
    response: objectSchema({ passkey: publicPasskeySchema }, ["passkey"]),
    errors: ["invalid_session", "passkey_invalid"], session: "required"
  }),
  beginPasskeyAuthentication: endpoint("POST", "/passkeys/authenticate/options", "Create passkey authentication options", {
    request: objectSchema({ userId: stringSchema(), mfa: { type: "boolean" } }),
    response: objectSchema({ options: openObjectSchema }, ["options"]),
    errors: ["passkey_not_found", "mfa_challenge_invalid", "validation_error"], session: "optional"
  }),
  completePasskeyAuthentication: endpoint("POST", "/passkeys/authenticate/verify", "Verify passkey authentication", {
    request: objectSchema({ response: openObjectSchema }, ["response"]), response: authSessionSchema,
    errors: ["passkey_invalid", "mfa_challenge_invalid"], session: "create"
  }),
  listPasskeys: endpoint("GET", "/passkeys", "List passkeys", {
    response: objectSchema({ passkeys: { type: "array", items: publicPasskeySchema } }, ["passkeys"]),
    errors: ["invalid_session"], session: "required"
  }),
  renamePasskey: endpoint("POST", "/passkeys/rename", "Rename a passkey", {
    request: objectSchema({ passkeyId: stringSchema(), name: stringSchema() }, ["passkeyId", "name"]),
    response: objectSchema({ passkey: publicPasskeySchema }, ["passkey"]),
    errors: ["invalid_session", "passkey_not_found", "validation_error"], session: "required"
  }),
  revokePasskey: endpoint("POST", "/passkeys/revoke", "Revoke a passkey", {
    request: objectSchema({ passkeyId: stringSchema() }, ["passkeyId"]), response: successSchema,
    errors: ["invalid_session", "passkey_not_found", "authentication_method_required"], session: "required"
  }),
  adminListUsers: administrationEndpoint("GET", "/admin/users", "List users for administration", {
    request: objectSchema({
      query: stringSchema(),
      status: { type: "string", enum: ["active", "disabled", "all"] },
      cursor: stringSchema(),
      limit: stringSchema()
    }),
    requestTransport: "query",
    response: objectSchema(
      {
        users: { type: "array", items: publicAdministrationUserSchema },
        nextCursor: nullableStringSchema
      },
      ["users", "nextCursor"]
    )
  }),
  adminGetUser: administrationEndpoint("GET", "/admin/user", "Get a user for administration", {
    request: administrationUserIdSchema,
    requestTransport: "query",
    response: administrationUserResponseSchema
  }),
  adminListUserSessions: administrationEndpoint(
    "GET",
    "/admin/user/sessions",
    "List a user's sessions for administration",
    {
      request: administrationUserIdSchema,
      requestTransport: "query",
      response: objectSchema(
        { sessions: { type: "array", items: publicAdministrationSessionSchema } },
        ["sessions"]
      )
    }
  ),
  adminListUserAuditEvents: administrationEndpoint(
    "GET",
    "/admin/user/audit-events",
    "List a user's audit events for administration",
    {
      request: objectSchema(
        {
          userId: stringSchema(),
          cursor: stringSchema(),
          limit: stringSchema()
        },
        ["userId"]
      ),
      requestTransport: "query",
      response: objectSchema(
        {
          events: { type: "array", items: publicAdministrationAuditEventSchema },
          nextCursor: nullableStringSchema
        },
        ["events", "nextCursor"]
      )
    }
  ),
  adminDisableUser: administrationEndpoint("POST", "/admin/user/disable", "Disable a user", {
    request: administrationMutationSchema,
    response: administrationUserResponseSchema
  }),
  adminEnableUser: administrationEndpoint("POST", "/admin/user/enable", "Enable a user", {
    request: administrationMutationSchema,
    response: administrationUserResponseSchema
  }),
  adminRevokeUserSessions: administrationEndpoint(
    "POST",
    "/admin/user/sessions/revoke",
    "Revoke all sessions for a user",
    {
      request: administrationMutationSchema,
      response: objectSchema({ revoked: { type: "integer" } }, ["revoked"])
    }
  )
} satisfies OwnAuthEndpointSpecMap;

const ownAuthEndpointMap = cloneAndDeepFreeze(Object.fromEntries(
  (Object.entries(ownAuthEndpointSpecs) as Array<[OwnAuthEndpointId, OwnAuthEndpointSpec]>)
    .map(([id, definition]) => [id, { id, ...definition }] as const)
)) as OwnAuthEndpointMap;

export const ownAuthEndpointContract: readonly OwnAuthEndpointDefinition[] = Object.freeze(
  Object.values(ownAuthEndpointMap)
);

const ownAuthEndpointsByPath = createEndpointPathLookup(ownAuthEndpointContract);
const noOwnAuthEndpoints = Object.freeze([]) as readonly OwnAuthEndpointDefinition[];

export function getOwnAuthEndpoint<Id extends OwnAuthEndpointId>(
  id: Id
): OwnAuthEndpointDefinition & { id: Id } {
  return ownAuthEndpointMap[id];
}

export function getOwnAuthEndpointsForPath(path: string): readonly OwnAuthEndpointDefinition[] {
  return ownAuthEndpointsByPath[path] ?? noOwnAuthEndpoints;
}

function endpoint(
  method: "GET" | "POST",
  path: string,
  summary: string,
  rest: Omit<OwnAuthEndpointDefinition, "id" | "method" | "path" | "summary">
): OwnAuthEndpointSpec {
  return { method, path, summary, ...rest };
}

function administrationEndpoint(
  method: "GET" | "POST",
  path: string,
  summary: string,
  rest: Omit<
    OwnAuthEndpointDefinition,
    "id" | "method" | "path" | "summary" | "errors" | "session" | "feature"
  >
): OwnAuthEndpointSpec {
  return endpoint(method, path, summary, {
    ...rest,
    errors: administrationErrors,
    session: "required",
    feature: "administration"
  });
}

function oauthCallback(
  method: "GET" | "POST",
  path: string,
  summary: string,
  requestTransport: "query" | "form" = "query"
): OwnAuthEndpointSpec {
  return endpoint(method, path, summary, {
    request: oauthCallbackRequestSchema,
    requestTransport,
    response: oauthCallbackSchema,
    responseKind: "oauth_callback",
    errors: oauthErrors,
    session: "create",
    csrf: "oauth_state"
  });
}

function createEndpointPathLookup(
  endpoints: readonly OwnAuthEndpointDefinition[]
): Readonly<Record<string, readonly OwnAuthEndpointDefinition[]>> {
  const entries: Record<string, OwnAuthEndpointDefinition[]> = Object.create(null) as Record<
    string,
    OwnAuthEndpointDefinition[]
  >;
  for (const endpointDefinition of endpoints) {
    (entries[endpointDefinition.path] ??= []).push(endpointDefinition);
  }
  return Object.freeze(Object.fromEntries(
    Object.entries(entries).map(([path, definitions]) => [path, Object.freeze(definitions)])
  ));
}
