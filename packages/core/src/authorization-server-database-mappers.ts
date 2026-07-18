import type {
  AuthorizationAccessToken,
  AuthorizationApplicationType,
  AuthorizationClient,
  AuthorizationClientGrantType,
  AuthorizationClientSecret,
  AuthorizationClientStatus,
  AuthorizationClientType,
  AuthorizationCode,
  AuthorizationGrant,
  AuthorizationInteraction,
  AuthorizationInteractionStatus,
  AuthorizationRefreshToken,
  OidcSubject,
  ProtectedResource,
  ProtectedResourceSecret,
  ProtectedResourceStatus,
  TokenEndpointAuthMethod
} from "./authorization-server-types.js";
import type {
  DeviceAuthorization,
  DeviceAuthorizationStatus
} from "./authorization-server-device-types.js";
import type { AuthorizationCodeDpopBinding } from "./authorization-server-storage.js";
import {
  booleanValue,
  dateValue,
  nullableDate,
  nullableString,
  numberValue,
  stringArray,
  stringValue
} from "./database-row.js";
import type { DatabaseRow } from "./database-types.js";

export function mapAuthorizationClient(row: DatabaseRow): AuthorizationClient {
  return {
    id: stringValue(row.id),
    clientId: stringValue(row.client_id),
    name: stringValue(row.name),
    clientType: stringValue(row.client_type) as AuthorizationClientType,
    applicationType: stringValue(row.application_type) as AuthorizationApplicationType,
    tokenEndpointAuthMethod: stringValue(
      row.token_endpoint_auth_method
    ) as TokenEndpointAuthMethod,
    redirectUris: stringArray(row.redirect_uris),
    allowedScopes: stringArray(row.allowed_scopes),
    grantTypes: stringArray(row.grant_types) as AuthorizationClientGrantType[],
    dpopBoundAccessTokens: booleanValue(row.dpop_bound_access_tokens),
    status: stringValue(row.status) as AuthorizationClientStatus,
    createdAt: dateValue(row.created_at),
    updatedAt: dateValue(row.updated_at),
    revokedAt: nullableDate(row.revoked_at)
  };
}

export function mapAuthorizationClientSecret(
  row: DatabaseRow
): AuthorizationClientSecret {
  return {
    id: stringValue(row.id),
    authorizationClientId: stringValue(row.authorization_client_id),
    prefix: stringValue(row.prefix),
    secretHash: stringValue(row.secret_hash),
    createdAt: dateValue(row.created_at),
    expiresAt: nullableDate(row.expires_at),
    revokedAt: nullableDate(row.revoked_at)
  };
}

export function mapProtectedResource(row: DatabaseRow): ProtectedResource {
  return {
    id: stringValue(row.id),
    identifier: stringValue(row.identifier),
    name: stringValue(row.name),
    allowedScopes: stringArray(row.allowed_scopes),
    requireDpop: booleanValue(row.require_dpop),
    status: stringValue(row.status) as ProtectedResourceStatus,
    createdAt: dateValue(row.created_at),
    updatedAt: dateValue(row.updated_at),
    revokedAt: nullableDate(row.revoked_at)
  };
}

export function mapProtectedResourceSecret(
  row: DatabaseRow
): ProtectedResourceSecret {
  return {
    id: stringValue(row.id),
    protectedResourceId: stringValue(row.protected_resource_id),
    prefix: stringValue(row.prefix),
    secretHash: stringValue(row.secret_hash),
    createdAt: dateValue(row.created_at),
    expiresAt: nullableDate(row.expires_at),
    revokedAt: nullableDate(row.revoked_at)
  };
}

export function mapAuthorizationInteraction(
  row: DatabaseRow
): AuthorizationInteraction {
  return {
    id: stringValue(row.id),
    interactionHash: stringValue(row.interaction_hash),
    authorizationClientId: stringValue(row.authorization_client_id),
    userId: nullableString(row.user_id),
    requestCiphertext: stringValue(row.request_ciphertext),
    requestNonce: stringValue(row.request_nonce),
    encryptionKeyId: stringValue(row.encryption_key_id),
    status: stringValue(row.status) as AuthorizationInteractionStatus,
    expiresAt: dateValue(row.expires_at),
    consumedAt: nullableDate(row.consumed_at),
    createdAt: dateValue(row.created_at)
  };
}

export function mapAuthorizationGrant(row: DatabaseRow): AuthorizationGrant {
  return {
    id: stringValue(row.id),
    authorizationClientId: stringValue(row.authorization_client_id),
    userId: stringValue(row.user_id),
    protectedResourceId: nullableString(row.protected_resource_id),
    scopes: stringArray(row.scopes),
    createdAt: dateValue(row.created_at),
    updatedAt: dateValue(row.updated_at),
    revokedAt: nullableDate(row.revoked_at)
  };
}

export function mapAuthorizationCode(row: DatabaseRow): AuthorizationCode {
  return {
    id: stringValue(row.id),
    codeHash: stringValue(row.code_hash),
    grantId: stringValue(row.grant_id),
    authorizationClientId: stringValue(row.authorization_client_id),
    userId: stringValue(row.user_id),
    protectedResourceId: nullableString(row.protected_resource_id),
    sessionId: stringValue(row.session_id),
    redirectUri: stringValue(row.redirect_uri),
    scopes: stringArray(row.scopes),
    codeChallenge: stringValue(row.code_challenge),
    nonceCiphertext: nullableString(row.nonce_ciphertext),
    nonceNonce: nullableString(row.nonce_nonce),
    encryptionKeyId: nullableString(row.encryption_key_id),
    dpopJkt: nullableString(row.dpop_jkt),
    expiresAt: dateValue(row.expires_at),
    consumedAt: nullableDate(row.consumed_at),
    createdAt: dateValue(row.created_at)
  };
}

export function mapAuthorizationCodeDpopBinding(
  row: DatabaseRow
): AuthorizationCodeDpopBinding {
  return {
    dpopJkt: nullableString(row.dpop_jkt),
    dpopRequired: booleanValue(row.dpop_required)
  };
}

export function mapAuthorizationAccessToken(
  row: DatabaseRow
): AuthorizationAccessToken {
  return {
    id: stringValue(row.id),
    tokenHash: stringValue(row.token_hash),
    prefix: stringValue(row.prefix),
    grantId: stringValue(row.grant_id),
    authorizationClientId: stringValue(row.authorization_client_id),
    userId: stringValue(row.user_id),
    protectedResourceId: nullableString(row.protected_resource_id),
    scopes: stringArray(row.scopes),
    dpopJkt: nullableString(row.dpop_jkt),
    expiresAt: dateValue(row.expires_at),
    revokedAt: nullableDate(row.revoked_at),
    createdAt: dateValue(row.created_at)
  };
}

export function mapAuthorizationRefreshToken(
  row: DatabaseRow
): AuthorizationRefreshToken {
  return {
    id: stringValue(row.id),
    tokenHash: stringValue(row.token_hash),
    prefix: stringValue(row.prefix),
    grantId: stringValue(row.grant_id),
    authorizationClientId: stringValue(row.authorization_client_id),
    userId: stringValue(row.user_id),
    protectedResourceId: nullableString(row.protected_resource_id),
    scopes: stringArray(row.scopes),
    generation: numberValue(row.generation),
    replacedByTokenId: nullableString(row.replaced_by_token_id),
    dpopJkt: nullableString(row.dpop_jkt),
    expiresAt: dateValue(row.expires_at),
    consumedAt: nullableDate(row.consumed_at),
    revokedAt: nullableDate(row.revoked_at),
    createdAt: dateValue(row.created_at)
  };
}

export function mapOidcSubject(row: DatabaseRow): OidcSubject {
  return {
    id: stringValue(row.id),
    userId: stringValue(row.user_id),
    subject: stringValue(row.subject),
    createdAt: dateValue(row.created_at)
  };
}

export function mapDeviceAuthorization(row: DatabaseRow): DeviceAuthorization {
  return {
    id: stringValue(row.id),
    deviceCodeHash: stringValue(row.device_code_hash),
    userCodeHash: stringValue(row.user_code_hash),
    authorizationClientId: stringValue(row.authorization_client_id),
    protectedResourceId: nullableString(row.protected_resource_id),
    requestCiphertext: stringValue(row.request_ciphertext),
    requestNonce: stringValue(row.request_nonce),
    encryptionKeyId: stringValue(row.encryption_key_id),
    dpopJkt: nullableString(row.dpop_jkt),
    status: stringValue(row.status) as DeviceAuthorizationStatus,
    userId: nullableString(row.user_id),
    sessionId: nullableString(row.session_id),
    grantId: nullableString(row.grant_id),
    approvedScopes: stringArray(row.approved_scopes),
    pollingIntervalSeconds: numberValue(row.polling_interval_seconds),
    nextPollAt: dateValue(row.next_poll_at),
    expiresAt: dateValue(row.expires_at),
    approvedAt: nullableDate(row.approved_at),
    deniedAt: nullableDate(row.denied_at),
    consumedAt: nullableDate(row.consumed_at),
    createdAt: dateValue(row.created_at)
  };
}
