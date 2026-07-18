import type { AuthStorage } from "./storage.js";
import type {
  AuthorizationAccessToken,
  AuthorizationClient,
  AuthorizationClientSecret,
  AuthorizationCode,
  AuthorizationGrant,
  AuthorizationInteraction,
  AuthorizationRefreshToken,
  AuthorizationInteractionStatus,
  OidcSubject,
  ProtectedResource,
  ProtectedResourceSecret
} from "./authorization-server-types.js";

export interface RotateAuthorizationRefreshTokenInput {
  tokenHash: string;
  authorizationClientId: string;
  replacementRefreshToken: AuthorizationRefreshToken;
  accessToken: AuthorizationAccessToken;
  rotatedAt: Date;
}

export type RotateAuthorizationRefreshTokenResult =
  | "rotated"
  | "reused"
  | "invalid";

export interface FindAuthorizationCodeDpopBindingInput {
  codeHash: string;
  authorizationClientId: string;
  redirectUri: string;
  codeChallenge: string;
  resourceIdentifier: string | null;
  now: Date;
}

export interface AuthorizationCodeDpopBinding {
  dpopJkt: string | null;
  dpopRequired: boolean;
}

export interface ConsumeDpopProofInput {
  proofHash: string;
  consumedAt: Date;
  expiresAt: Date;
}

export interface DpopStorage {
  findAuthorizationCodeDpopBinding(
    input: FindAuthorizationCodeDpopBindingInput
  ): Promise<AuthorizationCodeDpopBinding | null>;
  consumeDpopAuthorizationCode(
    codeHash: string,
    authorizationClientId: string,
    redirectUri: string,
    codeChallenge: string,
    resourceIdentifier: string | null,
    dpopJkt: string | null,
    consumedAt: Date
  ): Promise<AuthorizationCode | null>;
  consumeDpopProof(input: ConsumeDpopProofInput): Promise<boolean>;
  cleanupDpopProofs(expiredBefore: Date): Promise<number>;
}

export interface AuthorizationServerStorage {
  createAuthorizationClient(
    client: AuthorizationClient,
    secret: AuthorizationClientSecret | null
  ): Promise<AuthorizationClient>;
  getAuthorizationClientById(id: string): Promise<AuthorizationClient | null>;
  getAuthorizationClientByClientId(clientId: string): Promise<AuthorizationClient | null>;
  listAuthorizationClients(): Promise<AuthorizationClient[]>;
  updateAuthorizationClient(
    id: string,
    patch: Partial<AuthorizationClient>
  ): Promise<AuthorizationClient | null>;
  replaceAuthorizationClientSecret(
    authorizationClientId: string,
    secret: AuthorizationClientSecret,
    revokedAt: Date
  ): Promise<AuthorizationClientSecret>;
  getAuthorizationClientSecretByPrefix(
    authorizationClientId: string,
    prefix: string
  ): Promise<AuthorizationClientSecret | null>;
  revokeAuthorizationClient(id: string, revokedAt: Date): Promise<AuthorizationClient | null>;

  createProtectedResource(
    resource: ProtectedResource,
    secret: ProtectedResourceSecret
  ): Promise<ProtectedResource>;
  getProtectedResourceById(id: string): Promise<ProtectedResource | null>;
  getProtectedResourceByIdentifier(identifier: string): Promise<ProtectedResource | null>;
  listProtectedResources(): Promise<ProtectedResource[]>;
  updateProtectedResource(
    id: string,
    patch: Partial<ProtectedResource>
  ): Promise<ProtectedResource | null>;
  replaceProtectedResourceSecret(
    protectedResourceId: string,
    secret: ProtectedResourceSecret,
    revokedAt: Date
  ): Promise<ProtectedResourceSecret>;
  getProtectedResourceSecretByPrefix(
    protectedResourceId: string,
    prefix: string
  ): Promise<ProtectedResourceSecret | null>;
  revokeProtectedResource(
    id: string,
    revokedAt: Date
  ): Promise<ProtectedResource | null>;

  createAuthorizationInteraction(
    interaction: AuthorizationInteraction
  ): Promise<AuthorizationInteraction>;
  getAuthorizationInteractionByHash(
    interactionHash: string,
    now: Date
  ): Promise<AuthorizationInteraction | null>;
  bindAuthorizationInteractionToUser(
    interactionHash: string,
    userId: string,
    now: Date
  ): Promise<AuthorizationInteraction | null>;
  consumeAuthorizationInteraction(
    interactionHash: string,
    userId: string,
    status: Exclude<AuthorizationInteractionStatus, "pending">,
    consumedAt: Date
  ): Promise<AuthorizationInteraction | null>;

  getAuthorizationGrant(
    authorizationClientId: string,
    userId: string,
    protectedResourceId: string | null
  ): Promise<AuthorizationGrant | null>;
  upsertAuthorizationGrant(grant: AuthorizationGrant): Promise<AuthorizationGrant>;
  listAuthorizationGrantsByUserId(userId: string): Promise<AuthorizationGrant[]>;
  revokeAuthorizationGrant(id: string, revokedAt: Date): Promise<AuthorizationGrant | null>;

  createAuthorizationCode(code: AuthorizationCode): Promise<AuthorizationCode>;
  consumeAuthorizationCode(
    codeHash: string,
    authorizationClientId: string,
    redirectUri: string,
    codeChallenge: string,
    resourceIdentifier: string | null,
    consumedAt: Date
  ): Promise<AuthorizationCode | null>;

  createAuthorizationTokens(
    accessToken: AuthorizationAccessToken,
    refreshToken: AuthorizationRefreshToken | null
  ): Promise<void>;
  getAuthorizationAccessTokenByHash(
    tokenHash: string
  ): Promise<AuthorizationAccessToken | null>;
  getAuthorizationRefreshTokenByHash(
    tokenHash: string
  ): Promise<AuthorizationRefreshToken | null>;
  rotateAuthorizationRefreshToken(
    input: RotateAuthorizationRefreshTokenInput
  ): Promise<RotateAuthorizationRefreshTokenResult>;
  revokeAuthorizationToken(
    tokenHash: string,
    authorizationClientId: string,
    revokedAt: Date
  ): Promise<void>;

  getOidcSubjectByUserId(userId: string): Promise<OidcSubject | null>;
  createOidcSubject(subject: OidcSubject): Promise<OidcSubject>;
}

export interface AuthorizationServerCapableStorage extends AuthStorage {
  readonly authorizationServerStorage: AuthorizationServerStorage;
}

export interface DpopCapableAuthorizationServerStorage
  extends AuthorizationServerStorage {
  readonly dpopStorage: DpopStorage;
}

export function isAuthorizationServerCapableStorage(
  storage: AuthStorage
): storage is AuthorizationServerCapableStorage {
  const candidate = storage as Partial<AuthorizationServerCapableStorage>;
  const providerStorage = candidate.authorizationServerStorage;
  return Boolean(providerStorage) && [
    "createAuthorizationClient",
    "getAuthorizationClientById",
    "getAuthorizationClientByClientId",
    "listAuthorizationClients",
    "updateAuthorizationClient",
    "replaceAuthorizationClientSecret",
    "getAuthorizationClientSecretByPrefix",
    "revokeAuthorizationClient",
    "createProtectedResource",
    "getProtectedResourceById",
    "getProtectedResourceByIdentifier",
    "listProtectedResources",
    "updateProtectedResource",
    "replaceProtectedResourceSecret",
    "getProtectedResourceSecretByPrefix",
    "revokeProtectedResource",
    "createAuthorizationInteraction",
    "getAuthorizationInteractionByHash",
    "bindAuthorizationInteractionToUser",
    "consumeAuthorizationInteraction",
    "getAuthorizationGrant",
    "upsertAuthorizationGrant",
    "listAuthorizationGrantsByUserId",
    "revokeAuthorizationGrant",
    "createAuthorizationCode",
    "consumeAuthorizationCode",
    "createAuthorizationTokens",
    "getAuthorizationAccessTokenByHash",
    "getAuthorizationRefreshTokenByHash",
    "rotateAuthorizationRefreshToken",
    "revokeAuthorizationToken",
    "getOidcSubjectByUserId",
    "createOidcSubject"
  ].every(
    (method) =>
      typeof providerStorage?.[method as keyof AuthorizationServerStorage] === "function"
  );
}

export function isDpopCapableAuthorizationServerStorage(
  storage: AuthorizationServerStorage
): storage is DpopCapableAuthorizationServerStorage {
  const candidate = storage as Partial<DpopCapableAuthorizationServerStorage>;
  const dpopStorage = candidate.dpopStorage;
  return Boolean(dpopStorage) && [
    "findAuthorizationCodeDpopBinding",
    "consumeDpopAuthorizationCode",
    "consumeDpopProof",
    "cleanupDpopProofs"
  ].every(
    (method) => typeof dpopStorage?.[method as keyof DpopStorage] === "function"
  );
}

export {
  isDeviceAuthorizationCapableStorage
} from "./authorization-server-device-storage.js";
export type {
  ApproveDeviceAuthorizationStorageInput,
  DenyDeviceAuthorizationStorageInput,
  DeviceAuthorizationCapableAuthorizationServerStorage,
  DeviceAuthorizationStorage,
  PollDeviceAuthorizationInput
} from "./authorization-server-device-storage.js";
