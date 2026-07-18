import type { JsonRecord, RequestContext, SessionAssuranceLevel } from "./types.js";

export type AuthorizationClientType = "public" | "confidential";
export type AuthorizationApplicationType = "web" | "native";
export type AuthorizationClientGrantType =
  | "authorization_code"
  | "refresh_token"
  | "urn:ietf:params:oauth:grant-type:device_code";
export type AuthorizationClientStatus = "active" | "revoked";
export type ProtectedResourceStatus = "active" | "revoked";
export type TokenEndpointAuthMethod =
  | "none"
  | "client_secret_basic"
  | "client_secret_post";
export type AuthorizationInteractionStatus = "pending" | "approved" | "denied";
export type AuthorizationTokenType = "Bearer" | "DPoP";
export type AuthorizationPrompt =
  | "none"
  | "login"
  | "consent"
  | "select_account";

export interface AuthorizationScopeDefinition {
  label: string;
  description?: string;
}

export interface AuthorizationServerSigningKeyInput {
  id: string;
  privateKey: string;
}

export interface AuthorizationServerPreviousSigningKeyInput {
  id: string;
  publicKey: string;
}

export interface AuthorizationServerOptions {
  issuer: string;
  interactionUrl: string;
  signingKeys: {
    current: AuthorizationServerSigningKeyInput;
    previous?: AuthorizationServerPreviousSigningKeyInput[];
  };
  scopes?: Readonly<Record<string, AuthorizationScopeDefinition>>;
  interactionTtlMs?: number;
  authorizationCodeTtlMs?: number;
  accessTokenTtlMs?: number;
  refreshTokenTtlMs?: number;
  resourceIntrospectionRequestsPerMinute?: number;
  failedIntrospectionAttemptsPerMinute?: number;
  dpop?: {
    proofTtlMs?: number;
    clockSkewMs?: number;
  };
  deviceAuthorization?: {
    verificationUrl: string;
    ttlMs?: number;
    pollingIntervalSeconds?: number;
  };
}

export interface AuthorizationClient {
  id: string;
  clientId: string;
  name: string;
  clientType: AuthorizationClientType;
  applicationType: AuthorizationApplicationType;
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  redirectUris: string[];
  allowedScopes: string[];
  grantTypes: AuthorizationClientGrantType[];
  dpopBoundAccessTokens?: boolean;
  status: AuthorizationClientStatus;
  createdAt: Date;
  updatedAt: Date;
  revokedAt: Date | null;
}

export interface AuthorizationClientSecret {
  id: string;
  authorizationClientId: string;
  prefix: string;
  secretHash: string;
  createdAt: Date;
  expiresAt: Date | null;
  revokedAt: Date | null;
}

export interface ProtectedResource {
  id: string;
  identifier: string;
  name: string;
  allowedScopes: string[];
  requireDpop?: boolean;
  status: ProtectedResourceStatus;
  createdAt: Date;
  updatedAt: Date;
  revokedAt: Date | null;
}

export interface ProtectedResourceSecret {
  id: string;
  protectedResourceId: string;
  prefix: string;
  secretHash: string;
  createdAt: Date;
  expiresAt: Date | null;
  revokedAt: Date | null;
}

export interface AuthorizationInteraction {
  id: string;
  interactionHash: string;
  authorizationClientId: string;
  userId: string | null;
  requestCiphertext: string;
  requestNonce: string;
  encryptionKeyId: string;
  status: AuthorizationInteractionStatus;
  expiresAt: Date;
  consumedAt: Date | null;
  createdAt: Date;
}

export interface StoredAuthorizationRequest {
  redirectUri: string;
  scopes: string[];
  state: string | null;
  nonce: string | null;
  codeChallenge: string;
  prompts: AuthorizationPrompt[];
  maxAgeSeconds: number | null;
  acrValues: string[];
  display: string | null;
  uiLocales: string[];
  claimsLocales: string[];
  loginHint: string | null;
  resource: string | null;
  dpopJkt: string | null;
}

export interface AuthorizationGrant {
  id: string;
  authorizationClientId: string;
  userId: string;
  protectedResourceId: string | null;
  scopes: string[];
  createdAt: Date;
  updatedAt: Date;
  revokedAt: Date | null;
}

export interface AuthorizationCode {
  id: string;
  codeHash: string;
  grantId: string;
  authorizationClientId: string;
  userId: string;
  protectedResourceId: string | null;
  sessionId: string;
  redirectUri: string;
  scopes: string[];
  codeChallenge: string;
  nonceCiphertext: string | null;
  nonceNonce: string | null;
  encryptionKeyId: string | null;
  dpopJkt?: string | null;
  expiresAt: Date;
  consumedAt: Date | null;
  createdAt: Date;
}

export interface AuthorizationAccessToken {
  id: string;
  tokenHash: string;
  prefix: string;
  grantId: string;
  authorizationClientId: string;
  userId: string;
  protectedResourceId: string | null;
  scopes: string[];
  dpopJkt?: string | null;
  expiresAt: Date;
  revokedAt: Date | null;
  createdAt: Date;
}

export interface AuthorizationRefreshToken {
  id: string;
  tokenHash: string;
  prefix: string;
  grantId: string;
  authorizationClientId: string;
  userId: string;
  protectedResourceId: string | null;
  scopes: string[];
  generation: number;
  replacedByTokenId: string | null;
  dpopJkt?: string | null;
  expiresAt: Date;
  consumedAt: Date | null;
  revokedAt: Date | null;
  createdAt: Date;
}

export interface OidcSubject {
  id: string;
  userId: string;
  subject: string;
  createdAt: Date;
}

export interface CreateAuthorizationClientInput {
  name: string;
  clientType: AuthorizationClientType;
  applicationType: AuthorizationApplicationType;
  redirectUris?: string[];
  allowedScopes?: string[];
  grantTypes?: AuthorizationClientGrantType[];
  tokenEndpointAuthMethod?: TokenEndpointAuthMethod;
  dpopBoundAccessTokens?: boolean;
  actorUserId?: string;
  request?: RequestContext;
}

export interface CreatedAuthorizationClient {
  client: AuthorizationClient;
  clientSecret: string | null;
}

export interface CreateProtectedResourceInput {
  identifier: string;
  name: string;
  allowedScopes: string[];
  requireDpop?: boolean;
  actorUserId?: string;
  request?: RequestContext;
}

export interface CreatedProtectedResource {
  resource: ProtectedResource;
  resourceSecret: string;
}

export interface UpdateProtectedResourceInput {
  identifier: string;
  name?: string;
  allowedScopes?: string[];
  requireDpop?: boolean;
  actorUserId?: string;
  request?: RequestContext;
}

export interface RotateProtectedResourceSecretInput {
  identifier: string;
  expiresAt?: Date;
  actorUserId?: string;
  request?: RequestContext;
}

export interface RevokeProtectedResourceInput {
  identifier: string;
  actorUserId?: string;
  request?: RequestContext;
}

export interface UpdateAuthorizationClientInput {
  clientId: string;
  name?: string;
  redirectUris?: string[];
  allowedScopes?: string[];
  grantTypes?: AuthorizationClientGrantType[];
  dpopBoundAccessTokens?: boolean;
  actorUserId?: string;
  request?: RequestContext;
}

export interface RotateAuthorizationClientSecretInput {
  clientId: string;
  expiresAt?: Date;
  actorUserId?: string;
  request?: RequestContext;
}

export interface RevokeAuthorizationClientInput {
  clientId: string;
  actorUserId?: string;
  request?: RequestContext;
}

export interface GetAuthorizationInteractionInput {
  interactionToken: string;
  sessionToken?: string | null;
}

export type AuthorizationInteractionAction =
  | "sign_in"
  | "reauthenticate"
  | "select_account"
  | "mfa"
  | "consent"
  | "continue";

export interface PublicAuthorizationInteraction {
  action: AuthorizationInteractionAction;
  client: Pick<AuthorizationClient, "clientId" | "name" | "applicationType"> | null;
  resource: Pick<ProtectedResource, "identifier" | "name"> | null;
  scopes: Array<{ name: string; label: string; description: string | null }>;
  requiredAssuranceLevel: SessionAssuranceLevel | null;
  expiresAt: Date;
}

export interface CompleteAuthorizationInteractionInput {
  interactionToken: string;
  sessionToken: string;
  approvedScopes?: string[];
  request?: RequestContext;
}

export interface DenyAuthorizationInteractionInput {
  interactionToken: string;
  sessionToken: string;
  request?: RequestContext;
}

export interface AuthorizationRedirectResult {
  redirectUrl: string;
}

export interface VerifyAuthorizationAccessTokenInput {
  accessToken: string;
  requiredScopes?: string[];
  resource?: string;
}

export interface VerifiedAuthorizationAccessToken {
  client: AuthorizationClient;
  grant: AuthorizationGrant;
  userId: string;
  resource: string | null;
  scopes: string[];
  expiresAt: Date;
}

export interface AuthorizationUserGrant {
  grant: AuthorizationGrant;
  client: AuthorizationClient;
  resource: ProtectedResource | null;
}

export interface ListAuthorizationUserGrantsInput {
  actorUserId: string;
}

export interface RevokeAuthorizationUserGrantInput {
  actorUserId: string;
  clientId: string;
  resource?: string;
  request?: RequestContext;
}

export interface AuthorizationProtocolErrorShape {
  error: string;
  error_description?: string;
  error_uri?: string;
}

export interface AuthorizationRequestInput {
  responseType?: string;
  responseMode?: string;
  clientId?: string;
  redirectUri?: string;
  scope?: string;
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  nonce?: string;
  prompt?: string;
  maxAge?: string;
  acrValues?: string;
  display?: string;
  uiLocales?: string;
  claimsLocales?: string;
  loginHint?: string;
  requestObject?: string;
  requestUri?: string;
  resource?: string;
  dpopJkt?: string;
  sessionToken?: string | null;
  request?: RequestContext;
}

export interface AuthorizationTokenRequestInput {
  grantType?: string;
  clientId?: string;
  clientSecret?: string;
  clientAuthenticationMethod?: TokenEndpointAuthMethod;
  code?: string;
  redirectUri?: string;
  codeVerifier?: string;
  refreshToken?: string;
  deviceCode?: string;
  scope?: string;
  resource?: string;
  dpopProof?: string;
  requestMethod?: string;
  requestUrl?: string;
  request?: RequestContext;
}

export interface AuthorizationTokenResponse {
  token_type: AuthorizationTokenType;
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope: string;
}

export interface AuthorizationTokenActionInput {
  token?: string;
  tokenTypeHint?: string;
  clientId?: string;
  clientSecret?: string;
  clientAuthenticationMethod?: TokenEndpointAuthMethod;
  dpopProof?: string;
  requestMethod?: string;
  requestUrl?: string;
  request?: RequestContext;
}

export interface AuthorizationIntrospectionResponse extends JsonRecord {
  active: boolean;
  scope?: string;
  client_id?: string;
  token_type?: AuthorizationTokenType;
  cnf?: { jkt: string };
  exp?: number;
  iat?: number;
  sub?: string;
  aud?: string;
}

export interface AuthorizationUserInfo extends JsonRecord {
  sub: string;
  name?: string;
  picture?: string;
  email?: string;
  email_verified?: boolean;
  phone_number?: string;
  phone_number_verified?: boolean;
}

export interface AuthorizationUserInfoRequestInput {
  accessToken: string;
  tokenType: AuthorizationTokenType;
  dpopProof?: string;
  requestMethod: string;
  requestUrl: string;
}

export interface CleanupDpopProofsInput {
  expiredBefore?: Date;
}

export interface AuthorizationMetadata extends JsonRecord {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  revocation_endpoint: string;
  introspection_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  dpop_signing_alg_values_supported?: string[];
}
