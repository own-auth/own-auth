import type {
  AuthorizationAccessToken,
  AuthorizationClient,
  AuthorizationClientSecret,
  AuthorizationCode,
  AuthorizationGrant,
  AuthorizationInteraction,
  AuthorizationRefreshToken,
  OidcSubject
} from "./authorization-server-types.js";
import {
  databaseColumnList,
  type EntityColumnMap as ColumnMap
} from "./database-types.js";

export const authorizationClientColumns: ColumnMap<AuthorizationClient> = {
  id: "id",
  clientId: "client_id",
  name: "name",
  clientType: "client_type",
  applicationType: "application_type",
  tokenEndpointAuthMethod: "token_endpoint_auth_method",
  redirectUris: "redirect_uris",
  allowedScopes: "allowed_scopes",
  status: "status",
  createdAt: "created_at",
  updatedAt: "updated_at",
  revokedAt: "revoked_at"
};

export const authorizationClientSecretColumns: ColumnMap<AuthorizationClientSecret> = {
  id: "id",
  authorizationClientId: "authorization_client_id",
  prefix: "prefix",
  secretHash: "secret_hash",
  createdAt: "created_at",
  expiresAt: "expires_at",
  revokedAt: "revoked_at"
};

export const authorizationInteractionColumns: ColumnMap<AuthorizationInteraction> = {
  id: "id",
  interactionHash: "interaction_hash",
  authorizationClientId: "authorization_client_id",
  userId: "user_id",
  requestCiphertext: "request_ciphertext",
  requestNonce: "request_nonce",
  encryptionKeyId: "encryption_key_id",
  status: "status",
  expiresAt: "expires_at",
  consumedAt: "consumed_at",
  createdAt: "created_at"
};

export const authorizationGrantColumns: ColumnMap<AuthorizationGrant> = {
  id: "id",
  authorizationClientId: "authorization_client_id",
  userId: "user_id",
  scopes: "scopes",
  createdAt: "created_at",
  updatedAt: "updated_at",
  revokedAt: "revoked_at"
};

export const authorizationCodeColumns: ColumnMap<AuthorizationCode> = {
  id: "id",
  codeHash: "code_hash",
  grantId: "grant_id",
  authorizationClientId: "authorization_client_id",
  userId: "user_id",
  sessionId: "session_id",
  redirectUri: "redirect_uri",
  scopes: "scopes",
  codeChallenge: "code_challenge",
  nonceCiphertext: "nonce_ciphertext",
  nonceNonce: "nonce_nonce",
  encryptionKeyId: "encryption_key_id",
  expiresAt: "expires_at",
  consumedAt: "consumed_at",
  createdAt: "created_at"
};

export const authorizationAccessTokenColumns: ColumnMap<AuthorizationAccessToken> = {
  id: "id",
  tokenHash: "token_hash",
  prefix: "prefix",
  grantId: "grant_id",
  authorizationClientId: "authorization_client_id",
  userId: "user_id",
  scopes: "scopes",
  expiresAt: "expires_at",
  revokedAt: "revoked_at",
  createdAt: "created_at"
};

export const authorizationRefreshTokenColumns: ColumnMap<AuthorizationRefreshToken> = {
  id: "id",
  tokenHash: "token_hash",
  prefix: "prefix",
  grantId: "grant_id",
  authorizationClientId: "authorization_client_id",
  userId: "user_id",
  scopes: "scopes",
  generation: "generation",
  replacedByTokenId: "replaced_by_token_id",
  expiresAt: "expires_at",
  consumedAt: "consumed_at",
  revokedAt: "revoked_at",
  createdAt: "created_at"
};

export const oidcSubjectColumns: ColumnMap<OidcSubject> = {
  id: "id",
  userId: "user_id",
  subject: "subject",
  createdAt: "created_at"
};

export const authorizationClientReturning = databaseColumnList(authorizationClientColumns);
export const authorizationClientSecretReturning =
  databaseColumnList(authorizationClientSecretColumns);
export const authorizationInteractionReturning =
  databaseColumnList(authorizationInteractionColumns);
export const authorizationGrantReturning = databaseColumnList(authorizationGrantColumns);
export const authorizationCodeReturning = databaseColumnList(authorizationCodeColumns);
export const authorizationAccessTokenReturning =
  databaseColumnList(authorizationAccessTokenColumns);
export const authorizationRefreshTokenReturning =
  databaseColumnList(authorizationRefreshTokenColumns);
export const oidcSubjectReturning = databaseColumnList(oidcSubjectColumns);
