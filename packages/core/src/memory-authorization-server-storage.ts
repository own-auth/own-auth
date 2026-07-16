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
import type {
  AuthorizationServerStorage,
  RotateAuthorizationRefreshTokenInput,
  RotateAuthorizationRefreshTokenResult
} from "./authorization-server-storage.js";
import {
  cloneStored,
  findStored,
  updateStoredEntity
} from "./memory-storage-helpers.js";

export class MemoryAuthorizationServerStorage implements AuthorizationServerStorage {
  private readonly clients = new Map<string, AuthorizationClient>();
  private readonly secrets = new Map<string, AuthorizationClientSecret>();
  private readonly interactions = new Map<string, AuthorizationInteraction>();
  private readonly grants = new Map<string, AuthorizationGrant>();
  private readonly codes = new Map<string, AuthorizationCode>();
  private readonly accessTokens = new Map<string, AuthorizationAccessToken>();
  private readonly refreshTokens = new Map<string, AuthorizationRefreshToken>();
  private readonly subjects = new Map<string, OidcSubject>();

  async createAuthorizationClient(
    client: AuthorizationClient,
    secret: AuthorizationClientSecret | null
  ): Promise<AuthorizationClient> {
    if (this.findClientByClientId(client.clientId)) {
      throw new Error("Authorization client already exists");
    }
    this.clients.set(client.id, cloneStored(client));
    if (secret) this.secrets.set(secret.id, cloneStored(secret));
    return cloneStored(client);
  }

  async getAuthorizationClientByClientId(
    clientId: string
  ): Promise<AuthorizationClient | null> {
    const client = this.findClientByClientId(clientId);
    return client ? cloneStored(client) : null;
  }

  async getAuthorizationClientById(id: string): Promise<AuthorizationClient | null> {
    const client = this.clients.get(id);
    return client ? cloneStored(client) : null;
  }

  async listAuthorizationClients(): Promise<AuthorizationClient[]> {
    return [...this.clients.values()]
      .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime())
      .map(cloneStored);
  }

  async updateAuthorizationClient(
    id: string,
    patch: Partial<AuthorizationClient>
  ): Promise<AuthorizationClient | null> {
    return updateStoredEntity(this.clients, id, patch);
  }

  async replaceAuthorizationClientSecret(
    authorizationClientId: string,
    secret: AuthorizationClientSecret,
    revokedAt: Date
  ): Promise<AuthorizationClientSecret> {
    for (const [id, existing] of this.secrets) {
      if (existing.authorizationClientId === authorizationClientId && !existing.revokedAt) {
        updateStoredEntity(this.secrets, id, { revokedAt });
      }
    }
    this.secrets.set(secret.id, cloneStored(secret));
    return cloneStored(secret);
  }

  async getAuthorizationClientSecretByPrefix(
    authorizationClientId: string,
    prefix: string
  ): Promise<AuthorizationClientSecret | null> {
    const now = Date.now();
    return findStored(
      this.secrets,
      (secret) =>
        secret.authorizationClientId === authorizationClientId &&
        secret.prefix === prefix &&
        !secret.revokedAt &&
        (!secret.expiresAt || secret.expiresAt.getTime() > now)
    );
  }

  async revokeAuthorizationClient(
    id: string,
    revokedAt: Date
  ): Promise<AuthorizationClient | null> {
    const client = this.clients.get(id);
    if (!client) return null;
    for (const [secretId, secret] of this.secrets) {
      if (secret.authorizationClientId === id && !secret.revokedAt) {
        updateStoredEntity(this.secrets, secretId, { revokedAt });
      }
    }
    for (const grant of this.grants.values()) {
      if (grant.authorizationClientId === id) this.revokeGrantFamily(grant.id, revokedAt);
    }
    return updateStoredEntity(this.clients, id, {
      status: "revoked",
      revokedAt,
      updatedAt: revokedAt
    });
  }

  async createAuthorizationInteraction(
    interaction: AuthorizationInteraction
  ): Promise<AuthorizationInteraction> {
    this.interactions.set(interaction.id, cloneStored(interaction));
    return cloneStored(interaction);
  }

  async getAuthorizationInteractionByHash(
    interactionHash: string,
    now: Date
  ): Promise<AuthorizationInteraction | null> {
    const interaction = this.findUsableInteraction(interactionHash, now);
    return interaction ? cloneStored(interaction) : null;
  }

  async bindAuthorizationInteractionToUser(
    interactionHash: string,
    userId: string,
    now: Date
  ): Promise<AuthorizationInteraction | null> {
    const interaction = this.findUsableInteraction(interactionHash, now);
    if (!interaction || (interaction.userId && interaction.userId !== userId)) return null;
    return updateStoredEntity(this.interactions, interaction.id, { userId });
  }

  async consumeAuthorizationInteraction(
    interactionHash: string,
    userId: string,
    status: Exclude<AuthorizationInteractionStatus, "pending">,
    consumedAt: Date
  ): Promise<AuthorizationInteraction | null> {
    const interaction = this.findUsableInteraction(interactionHash, consumedAt);
    if (!interaction || interaction.userId !== userId) return null;
    return updateStoredEntity(this.interactions, interaction.id, { status, consumedAt });
  }

  async getAuthorizationGrant(
    authorizationClientId: string,
    userId: string
  ): Promise<AuthorizationGrant | null> {
    return findStored(
      this.grants,
      (grant) =>
        grant.authorizationClientId === authorizationClientId &&
        grant.userId === userId
    );
  }

  async upsertAuthorizationGrant(grant: AuthorizationGrant): Promise<AuthorizationGrant> {
    const existing = findStored(
      this.grants,
      (candidate) =>
        candidate.authorizationClientId === grant.authorizationClientId &&
        candidate.userId === grant.userId
    );
    if (existing) {
      const updated = updateStoredEntity(this.grants, existing.id, {
        scopes: [...grant.scopes],
        updatedAt: grant.updatedAt,
        revokedAt: null
      });
      if (!updated) throw new Error("Authorization grant disappeared during update");
      return updated;
    }
    this.grants.set(grant.id, cloneStored(grant));
    return cloneStored(grant);
  }

  async listAuthorizationGrantsByUserId(userId: string): Promise<AuthorizationGrant[]> {
    return [...this.grants.values()]
      .filter((grant) => grant.userId === userId)
      .map(cloneStored);
  }

  async revokeAuthorizationGrant(
    id: string,
    revokedAt: Date
  ): Promise<AuthorizationGrant | null> {
    const grant = this.grants.get(id);
    if (!grant) return null;
    this.revokeGrantFamily(id, revokedAt);
    return cloneStored(this.grants.get(id)!);
  }

  async createAuthorizationCode(code: AuthorizationCode): Promise<AuthorizationCode> {
    this.codes.set(code.id, cloneStored(code));
    return cloneStored(code);
  }

  async consumeAuthorizationCode(
    codeHash: string,
    authorizationClientId: string,
    redirectUri: string,
    codeChallenge: string,
    consumedAt: Date
  ): Promise<AuthorizationCode | null> {
    const code = [...this.codes.values()].find(
      (candidate) =>
        candidate.codeHash === codeHash &&
        candidate.authorizationClientId === authorizationClientId &&
        candidate.redirectUri === redirectUri &&
        candidate.codeChallenge === codeChallenge &&
        !candidate.consumedAt &&
        candidate.expiresAt.getTime() > consumedAt.getTime()
    );
    return code
      ? updateStoredEntity(this.codes, code.id, { consumedAt })
      : null;
  }

  async createAuthorizationTokens(
    accessToken: AuthorizationAccessToken,
    refreshToken: AuthorizationRefreshToken | null
  ): Promise<void> {
    this.accessTokens.set(accessToken.id, cloneStored(accessToken));
    if (refreshToken) this.refreshTokens.set(refreshToken.id, cloneStored(refreshToken));
  }

  async getAuthorizationAccessTokenByHash(
    tokenHash: string
  ): Promise<AuthorizationAccessToken | null> {
    return findStored(this.accessTokens, (token) => token.tokenHash === tokenHash);
  }

  async getAuthorizationRefreshTokenByHash(
    tokenHash: string
  ): Promise<AuthorizationRefreshToken | null> {
    return findStored(this.refreshTokens, (token) => token.tokenHash === tokenHash);
  }

  async rotateAuthorizationRefreshToken(
    input: RotateAuthorizationRefreshTokenInput
  ): Promise<RotateAuthorizationRefreshTokenResult> {
    const current = [...this.refreshTokens.values()].find(
      (token) =>
        token.tokenHash === input.tokenHash &&
        token.authorizationClientId === input.authorizationClientId
    );
    if (
      !current ||
      current.revokedAt ||
      current.expiresAt.getTime() <= input.rotatedAt.getTime() ||
      this.grants.get(current.grantId)?.revokedAt
    ) {
      return "invalid";
    }
    if (current.consumedAt || current.replacedByTokenId) {
      this.revokeGrantFamily(current.grantId, input.rotatedAt);
      return "reused";
    }

    updateStoredEntity(this.refreshTokens, current.id, {
      consumedAt: input.rotatedAt,
      replacedByTokenId: input.replacementRefreshToken.id
    });
    this.refreshTokens.set(
      input.replacementRefreshToken.id,
      cloneStored(input.replacementRefreshToken)
    );
    this.accessTokens.set(input.accessToken.id, cloneStored(input.accessToken));
    return "rotated";
  }

  async revokeAuthorizationToken(
    tokenHash: string,
    authorizationClientId: string,
    revokedAt: Date
  ): Promise<void> {
    const refreshToken = [...this.refreshTokens.values()].find(
      (token) =>
        token.tokenHash === tokenHash &&
        token.authorizationClientId === authorizationClientId
    );
    if (refreshToken) {
      this.revokeGrantFamily(refreshToken.grantId, revokedAt);
      return;
    }
    const accessToken = [...this.accessTokens.values()].find(
      (token) =>
        token.tokenHash === tokenHash &&
        token.authorizationClientId === authorizationClientId
    );
    if (accessToken && !accessToken.revokedAt) {
      updateStoredEntity(this.accessTokens, accessToken.id, { revokedAt });
    }
  }

  async getOidcSubjectByUserId(userId: string): Promise<OidcSubject | null> {
    return findStored(this.subjects, (subject) => subject.userId === userId);
  }

  async createOidcSubject(subject: OidcSubject): Promise<OidcSubject> {
    const existing = findStored(
      this.subjects,
      (candidate) => candidate.userId === subject.userId
    );
    if (existing) return existing;
    this.subjects.set(subject.id, cloneStored(subject));
    return cloneStored(subject);
  }

  private findClientByClientId(clientId: string): AuthorizationClient | null {
    return [...this.clients.values()].find((client) => client.clientId === clientId) ?? null;
  }

  private findUsableInteraction(
    interactionHash: string,
    now: Date
  ): AuthorizationInteraction | null {
    return [...this.interactions.values()].find(
      (interaction) =>
        interaction.interactionHash === interactionHash &&
        interaction.status === "pending" &&
        !interaction.consumedAt &&
        interaction.expiresAt.getTime() > now.getTime()
    ) ?? null;
  }

  private revokeGrantFamily(grantId: string, revokedAt: Date): void {
    updateStoredEntity(this.grants, grantId, { revokedAt, updatedAt: revokedAt });
    for (const [id, token] of this.accessTokens) {
      if (token.grantId === grantId && !token.revokedAt) {
        updateStoredEntity(this.accessTokens, id, { revokedAt });
      }
    }
    for (const [id, token] of this.refreshTokens) {
      if (token.grantId === grantId && !token.revokedAt) {
        updateStoredEntity(this.refreshTokens, id, { revokedAt });
      }
    }
  }
}
