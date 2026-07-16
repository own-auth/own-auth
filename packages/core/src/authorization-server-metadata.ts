import type { AuthEngineContext } from "./auth-engine-context.js";
import {
  authorizationClientAuthenticationMethods,
  authorizationPrompts,
  authorizationServerPaths,
  confidentialClientAuthenticationMethods
} from "./authorization-server-constants.js";
import {
  authorizationServerUrl,
  requireAuthorizationServer
} from "./authorization-server-helpers.js";
import type { AuthorizationMetadata } from "./authorization-server-types.js";

export async function getAuthorizationServerMetadata(
  ctx: AuthEngineContext
): Promise<AuthorizationMetadata> {
  const { config } = requireAuthorizationServer(ctx);
  return {
    issuer: config.issuer,
    authorization_endpoint: authorizationServerUrl(
      config,
      authorizationServerPaths.authorization
    ),
    token_endpoint: authorizationServerUrl(config, authorizationServerPaths.token),
    revocation_endpoint: authorizationServerUrl(
      config,
      authorizationServerPaths.revocation
    ),
    introspection_endpoint: authorizationServerUrl(
      config,
      authorizationServerPaths.introspection
    ),
    userinfo_endpoint: authorizationServerUrl(
      config,
      authorizationServerPaths.userinfo
    ),
    jwks_uri: authorizationServerUrl(config, authorizationServerPaths.jwks),
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    token_endpoint_auth_methods_supported: [...authorizationClientAuthenticationMethods],
    revocation_endpoint_auth_methods_supported: [...authorizationClientAuthenticationMethods],
    introspection_endpoint_auth_methods_supported: [
      ...confidentialClientAuthenticationMethods
    ],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: [...config.scopes.keys()],
    claims_supported: [
      "sub",
      "name",
      "picture",
      "email",
      "email_verified",
      "phone_number",
      "phone_number_verified",
      "auth_time",
      "acr",
      "amr"
    ],
    prompt_values_supported: [...authorizationPrompts]
  };
}

export function getAuthorizationServerJwks(ctx: AuthEngineContext) {
  return requireAuthorizationServer(ctx).config.signer.jwks();
}
