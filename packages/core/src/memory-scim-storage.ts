import { cloneStored, findStored, updateStoredEntity } from "./memory-storage-helpers.js";
import type { ScimStorage } from "./scim-storage.js";
import type {
  ScimConnection,
  ScimEmailVerificationCommit,
  ScimProvisionCommit,
  ScimToken,
  ScimUser,
  ScimUserFilter,
  ScimUserMutation,
  ScimUserPage
} from "./scim-types.js";
import type { AuditEvent, OrganisationMember, User } from "./types.js";

interface MemoryScimRecords {
  users: Map<string, User>;
  members: Map<string, OrganisationMember<string>>;
  auditEvents: Map<string, AuditEvent>;
}

export class MemoryScimStorage implements ScimStorage {
  /** @internal Runs inside the parent storage's synchronous email ownership operation. */
  reassignEmailOwner(sourceUserId: string, ownerUserId: string, email: string, at: Date): OrganisationMember<string>[] {
    const memberships: OrganisationMember<string>[] = [];
    for (const resource of this.scimUsers.values()) {
      if (resource.userId !== sourceUserId || resource.normalizedEmail !== email || resource.deletedAt) continue;
      const membership = this.records.members.get(resource.membershipId);
      if (membership?.userId === sourceUserId) {
        const reassigned = { ...membership, userId: ownerUserId, updatedAt: at };
        this.records.members.set(membership.id, reassigned);
        memberships.push(cloneStored(reassigned));
      }
      this.scimUsers.set(resource.id, {
        ...resource, userId: ownerUserId, version: resource.version + 1, updatedAt: at
      });
    }
    return memberships;
  }
  private readonly connections = new Map<string, ScimConnection>();
  private readonly tokens = new Map<string, ScimToken>();
  private readonly scimUsers = new Map<string, ScimUser>();

  constructor(private readonly records: MemoryScimRecords) {}

  async createConnection(connection: ScimConnection): Promise<ScimConnection> {
    if ([...this.connections.values()].some((candidate) =>
      candidate.key === connection.key ||
      Boolean(connection.samlConnectionId && candidate.samlConnectionId === connection.samlConnectionId)
    )) throw new Error("SCIM connection already exists");
    this.connections.set(connection.id, cloneStored(connection));
    return cloneStored(connection);
  }

  async getConnectionById(id: string): Promise<ScimConnection | null> {
    const connection = this.connections.get(id);
    return connection ? cloneStored(connection) : null;
  }

  async listConnectionsByOrganisationId(organisationId: string): Promise<ScimConnection[]> {
    return [...this.connections.values()]
      .filter((connection) => connection.organisationId === organisationId)
      .sort((left, right) => left.createdAt.getTime() - right.createdAt.getTime())
      .map(cloneStored);
  }

  async updateConnection(
    id: string,
    patch: Partial<ScimConnection>
  ): Promise<ScimConnection | null> {
    const { id: _id, organisationId: _organisationId, key: _key, createdAt: _createdAt, ...safe } = patch;
    return updateStoredEntity(this.connections, id, safe);
  }

  async createToken(token: ScimToken): Promise<ScimToken> {
    if ([...this.tokens.values()].some((candidate) =>
      candidate.prefix === token.prefix || candidate.tokenHash === token.tokenHash
    )) throw new Error("SCIM token already exists");
    this.tokens.set(token.id, cloneStored(token));
    return cloneStored(token);
  }

  async getTokenById(id: string): Promise<ScimToken | null> {
    const token = this.tokens.get(id);
    return token ? cloneStored(token) : null;
  }

  async getTokenByHash(tokenHash: string): Promise<ScimToken | null> {
    return findStored(this.tokens, (token) => token.tokenHash === tokenHash);
  }

  async listTokensByConnectionId(connectionId: string): Promise<ScimToken[]> {
    return [...this.tokens.values()]
      .filter((token) => token.connectionId === connectionId)
      .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime())
      .map(cloneStored);
  }

  async updateToken(id: string, patch: Partial<ScimToken>): Promise<ScimToken | null> {
    const {
      id: _id,
      connectionId: _connectionId,
      prefix: _prefix,
      tokenHash: _tokenHash,
      createdAt: _createdAt,
      ...safe
    } = patch;
    return updateStoredEntity(this.tokens, id, safe);
  }

  async getUserById(id: string): Promise<ScimUser | null> {
    const user = this.scimUsers.get(id);
    return user ? cloneStored(user) : null;
  }

  async getUserByExternalId(connectionId: string, externalId: string): Promise<ScimUser | null> {
    return this.findUser((user) => user.connectionId === connectionId && user.externalId === externalId);
  }

  async getUserByUserName(connectionId: string, normalizedUserName: string): Promise<ScimUser | null> {
    return this.findUser((user) =>
      user.connectionId === connectionId && user.normalizedUserName === normalizedUserName
    );
  }

  async getActiveUserByEmail(connectionId: string, normalizedEmail: string): Promise<ScimUser | null> {
    return this.findUser((user) =>
      user.connectionId === connectionId && user.normalizedEmail === normalizedEmail &&
      !user.deletedAt
    );
  }

  async listUsers(
    connectionId: string,
    filter: ScimUserFilter | null,
    startIndex: number,
    count: number
  ): Promise<ScimUserPage> {
    const matches = [...this.scimUsers.values()]
      .filter((user) => user.connectionId === connectionId && !user.deletedAt)
      .filter((user) => !filter || matchesFilter(user, filter))
      .sort((left, right) => left.createdAt.getTime() - right.createdAt.getTime() ||
        left.id.localeCompare(right.id));
    return {
      totalResults: matches.length,
      users: matches.slice(startIndex - 1, startIndex - 1 + count).map(cloneStored)
    };
  }

  async listUsersByOrganisationAndUser(organisationId: string, userId: string): Promise<ScimUser[]> {
    const connectionIds = new Set(
      [...this.connections.values()]
        .filter((connection) => connection.organisationId === organisationId)
        .map((connection) => connection.id)
    );
    return [...this.scimUsers.values()]
      .filter((user) => connectionIds.has(user.connectionId) && user.userId === userId)
      .map(cloneStored);
  }

  async findActiveUserBySamlConnection(
    samlConnectionId: string,
    normalizedEmail: string
  ): Promise<ScimUser | null> {
    const connection = findStored(
      this.connections,
      (candidate) => candidate.samlConnectionId === samlConnectionId && !candidate.disabledAt
    );
    if (!connection) return null;
    const matches = [...this.scimUsers.values()].filter((user) =>
      user.connectionId === connection.id && user.normalizedEmail === normalizedEmail &&
      user.active && !user.deletedAt
    );
    return matches.length === 1 ? cloneStored(matches[0]!) : null;
  }

  async commitProvision(input: ScimProvisionCommit): Promise<void> {
    validateProvision(this.records, this.scimUsers, input);
    if (input.user) this.records.users.set(input.user.id, cloneStored(input.user));
    this.records.members.set(input.membership.id, cloneStored(input.membership));
    this.scimUsers.set(input.scimUser.id, cloneStored(input.scimUser));
    for (const event of input.auditEvents) {
      this.records.auditEvents.set(event.id, cloneStored(event));
    }
  }

  async mutateUser(input: ScimUserMutation): Promise<ScimUser | null> {
    const current = this.scimUsers.get(input.id);
    if (!current || current.version !== input.expectedVersion) return null;
    if (input.membershipPatch) {
      const member = this.records.members.get(current.membershipId);
      if (!member) return null;
      updateStoredEntity(this.records.members, member.id, input.membershipPatch);
    }
    const updated = updateStoredEntity(this.scimUsers, input.id, {
      ...input.patch,
      version: current.version + 1
    });
    if (input.auditEvent) {
      this.records.auditEvents.set(input.auditEvent.id, cloneStored(input.auditEvent));
    }
    return updated;
  }

  async verifyPairedSamlEmail(input: ScimEmailVerificationCommit): Promise<boolean> {
    const user = this.records.users.get(input.userId);
    if (!user || user.email !== input.normalizedEmail || user.emailVerifiedAt) return false;
    updateStoredEntity(this.records.users, user.id, {
      emailVerifiedAt: input.verifiedAt,
      updatedAt: input.verifiedAt
    });
    this.records.auditEvents.set(input.auditEvent.id, cloneStored(input.auditEvent));
    return true;
  }

  private findUser(predicate: (user: ScimUser) => boolean): ScimUser | null {
    return findStored(this.scimUsers, predicate);
  }
}

function matchesFilter(user: ScimUser, filter: ScimUserFilter): boolean {
  if (filter.attribute === "id") return user.id === filter.value;
  if (filter.attribute === "externalId") return user.externalId === filter.value;
  return user.normalizedUserName === filter.value;
}

function validateProvision(
  records: MemoryScimRecords,
  scimUsers: Map<string, ScimUser>,
  input: ScimProvisionCommit
): void {
  if (input.user && [...records.users.values()].some((user) =>
    user.id === input.user?.id || Boolean(user.email && user.email === input.user?.email)
  )) throw new Error("SCIM user already exists");
  if ([...records.members.values()].some((member) =>
    member.id === input.membership.id ||
    (member.organisationId === input.membership.organisationId &&
     member.userId === input.membership.userId)
  )) throw new Error("SCIM membership already exists");
  if ([...scimUsers.values()].some((user) =>
    user.id === input.scimUser.id ||
    (user.connectionId === input.scimUser.connectionId && (
      user.userId === input.scimUser.userId ||
      user.normalizedUserName === input.scimUser.normalizedUserName ||
      Boolean(user.externalId && user.externalId === input.scimUser.externalId) ||
      Boolean(
        !user.deletedAt && !input.scimUser.deletedAt && user.normalizedEmail &&
        user.normalizedEmail === input.scimUser.normalizedEmail
      )
    ))
  )) throw new Error("SCIM resource already exists");
}
