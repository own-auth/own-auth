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
  OidcSubject
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
    userId: string
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
