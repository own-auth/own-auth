import type {
  AuthorizationPrompt,
  TokenEndpointAuthMethod
} from "./authorization-server-types.js";

export const authorizationClientAuthenticationMethods = [
  "none",
  "client_secret_basic",
  "client_secret_post"
] as const satisfies readonly TokenEndpointAuthMethod[];

export const confidentialClientAuthenticationMethods = [
  "client_secret_basic",
  "client_secret_post"
] as const satisfies readonly TokenEndpointAuthMethod[];

export const authorizationPrompts = [
  "none",
  "login",
  "consent",
  "select_account"
] as const satisfies readonly AuthorizationPrompt[];

export const authorizationServerPaths = Object.freeze({
  authorization: "/oauth/authorize",
  token: "/oauth/token",
  revocation: "/oauth/revoke",
  introspection: "/oauth/introspect",
  userinfo: "/oauth/userinfo",
  jwks: "/oauth/jwks"
});

export const authorizationServerTokenPrefixes = Object.freeze({
  clientId: "oa_client_",
  clientSecret: "oa_cs_",
  interaction: "oa_ix_",
  authorizationCode: "oa_ac_",
  accessToken: "oa_at_",
  refreshToken: "oa_rt_"
});

export const authorizationServerRateLimits = Object.freeze({
  start: 60,
  interaction: 30,
  protocol: 120
});
export const authorizationServerRateLimitWindowMs = 10 * 60 * 1000;
