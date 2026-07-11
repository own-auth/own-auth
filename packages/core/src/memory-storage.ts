import type { AuthStorage } from "./storage.js";
import type {
  Account,
  ApiKey,
  AuditEvent,
  AuthToken,
  Invitation,
  Organisation,
  OrganisationMember,
  Session,
  SmsOtp,
  TokenType,
  User
} from "./types.js";

function clone<T>(value: T): T {
  return structuredClone(value);
}

function mergeEntity<T extends { id: string }>(entity: T, patch: Partial<T>): T {
  return { ...entity, ...patch };
}

export class InMemoryAuthStorage implements AuthStorage {
  private readonly users = new Map<string, User>();
  private readonly accounts = new Map<string, Account>();
  private readonly sessions = new Map<string, Session>();
  private readonly tokens = new Map<string, AuthToken>();
  private readonly smsOtps = new Map<string, SmsOtp>();
  private readonly apiKeys = new Map<string, ApiKey>();
  private readonly organisations = new Map<string, Organisation>();
  private readonly members = new Map<string, OrganisationMember>();
  private readonly invitations = new Map<string, Invitation>();
  private readonly auditEvents = new Map<string, AuditEvent>();

  async createUser(user: User): Promise<User> {
    this.users.set(user.id, clone(user));
    return clone(user);
  }

  async updateUser(id: string, patch: Partial<User>): Promise<User | null> {
    const existing = this.users.get(id);
    if (!existing) return null;
    const updated = mergeEntity(existing, patch);
    this.users.set(id, clone(updated));
    return clone(updated);
  }

  async getUserById(id: string): Promise<User | null> {
    const user = this.users.get(id);
    return user ? clone(user) : null;
  }

  async getUserByEmail(email: string): Promise<User | null> {
    for (const user of this.users.values()) {
      if (user.email === email) {
        return clone(user);
      }
    }

    return null;
  }

  async getUserByPhone(phone: string): Promise<User | null> {
    for (const user of this.users.values()) {
      if (user.phone === phone) {
        return clone(user);
      }
    }

    return null;
  }

  async createAccount(account: Account): Promise<Account> {
    this.accounts.set(account.id, clone(account));
    return clone(account);
  }

  async getAccountByProvider(
    provider: string,
    providerAccountId: string
  ): Promise<Account | null> {
    for (const account of this.accounts.values()) {
      if (account.provider === provider && account.providerAccountId === providerAccountId) {
        return clone(account);
      }
    }

    return null;
  }

  async createSession(session: Session): Promise<Session> {
    this.sessions.set(session.id, clone(session));
    return clone(session);
  }

  async getSessionByTokenHash(tokenHash: string): Promise<Session | null> {
    for (const session of this.sessions.values()) {
      if (session.tokenHash === tokenHash) {
        return clone(session);
      }
    }

    return null;
  }

  async updateSession(id: string, patch: Partial<Session>): Promise<Session | null> {
    const existing = this.sessions.get(id);
    if (!existing) return null;
    const updated = mergeEntity(existing, patch);
    this.sessions.set(id, clone(updated));
    return clone(updated);
  }

  async listSessionsByUserId(userId: string): Promise<Session[]> {
    return [...this.sessions.values()]
      .filter((session) => session.userId === userId)
      .map((session) => clone(session));
  }

  async createToken(token: AuthToken): Promise<AuthToken> {
    this.tokens.set(token.id, clone(token));
    return clone(token);
  }

  async getTokenByHash(tokenHash: string, type?: TokenType): Promise<AuthToken | null> {
    for (const token of this.tokens.values()) {
      if (token.tokenHash === tokenHash && (!type || token.type === type)) {
        return clone(token);
      }
    }

    return null;
  }

  async updateToken(id: string, patch: Partial<AuthToken>): Promise<AuthToken | null> {
    const existing = this.tokens.get(id);
    if (!existing) return null;
    const updated = mergeEntity(existing, patch);
    this.tokens.set(id, clone(updated));
    return clone(updated);
  }

  async createSmsOtp(otp: SmsOtp): Promise<SmsOtp> {
    this.smsOtps.set(otp.id, clone(otp));
    return clone(otp);
  }

  async getLatestSmsOtp(phone: string, purpose: string): Promise<SmsOtp | null> {
    const matching = [...this.smsOtps.values()]
      .filter((otp) => otp.phone === phone && otp.purpose === purpose)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    return matching[0] ? clone(matching[0]) : null;
  }

  async updateSmsOtp(id: string, patch: Partial<SmsOtp>): Promise<SmsOtp | null> {
    const existing = this.smsOtps.get(id);
    if (!existing) return null;
    const updated = mergeEntity(existing, patch);
    this.smsOtps.set(id, clone(updated));
    return clone(updated);
  }

  async createApiKey(apiKey: ApiKey): Promise<ApiKey> {
    this.apiKeys.set(apiKey.id, clone(apiKey));
    return clone(apiKey);
  }

  async getApiKeyByPrefix(keyPrefix: string): Promise<ApiKey | null> {
    for (const apiKey of this.apiKeys.values()) {
      if (apiKey.keyPrefix === keyPrefix) {
        return clone(apiKey);
      }
    }

    return null;
  }

  async updateApiKey(id: string, patch: Partial<ApiKey>): Promise<ApiKey | null> {
    const existing = this.apiKeys.get(id);
    if (!existing) return null;
    const updated = mergeEntity(existing, patch);
    this.apiKeys.set(id, clone(updated));
    return clone(updated);
  }

  async listApiKeysByOrganisationId(organisationId: string): Promise<ApiKey[]> {
    return [...this.apiKeys.values()]
      .filter((key) => key.organisationId === organisationId)
      .map((key) => clone(key));
  }

  async listApiKeysByUserId(userId: string): Promise<ApiKey[]> {
    return [...this.apiKeys.values()]
      .filter((key) => key.userId === userId)
      .map((key) => clone(key));
  }

  async createOrganisation(organisation: Organisation): Promise<Organisation> {
    this.organisations.set(organisation.id, clone(organisation));
    return clone(organisation);
  }

  async updateOrganisation(
    id: string,
    patch: Partial<Organisation>
  ): Promise<Organisation | null> {
    const existing = this.organisations.get(id);
    if (!existing) return null;
    const updated = mergeEntity(existing, patch);
    this.organisations.set(id, clone(updated));
    return clone(updated);
  }

  async deleteOrganisation(id: string): Promise<boolean> {
    if (!this.organisations.delete(id)) {
      return false;
    }

    const deletedApiKeyIds = new Set<string>();

    for (const [tokenId, token] of this.tokens) {
      if (token.organisationId === id) {
        this.tokens.delete(tokenId);
      }
    }

    for (const [apiKeyId, apiKey] of this.apiKeys) {
      if (apiKey.organisationId === id) {
        deletedApiKeyIds.add(apiKeyId);
        this.apiKeys.delete(apiKeyId);
      }
    }

    for (const [memberId, member] of this.members) {
      if (member.organisationId === id) {
        this.members.delete(memberId);
      }
    }

    for (const [invitationId, invitation] of this.invitations) {
      if (invitation.organisationId === id) {
        this.invitations.delete(invitationId);
      }
    }

    for (const [eventId, event] of this.auditEvents) {
      if (
        event.organisationId === id ||
        (event.apiKeyId && deletedApiKeyIds.has(event.apiKeyId))
      ) {
        this.auditEvents.set(eventId, {
          ...event,
          organisationId: event.organisationId === id ? null : event.organisationId,
          apiKeyId: event.apiKeyId && deletedApiKeyIds.has(event.apiKeyId)
            ? null
            : event.apiKeyId
        });
      }
    }

    return true;
  }

  async getOrganisationById(id: string): Promise<Organisation | null> {
    const organisation = this.organisations.get(id);
    return organisation ? clone(organisation) : null;
  }

  async getOrganisationBySlug(slug: string): Promise<Organisation | null> {
    for (const organisation of this.organisations.values()) {
      if (organisation.slug === slug) {
        return clone(organisation);
      }
    }

    return null;
  }

  async listOrganisationsByUserId(userId: string): Promise<Organisation[]> {
    const memberOrgIds = new Set(
      [...this.members.values()]
        .filter((m) => m.userId === userId && m.status === "active")
        .map((m) => m.organisationId)
    );
    return [...this.organisations.values()]
      .filter((org) => memberOrgIds.has(org.id))
      .map((org) => clone(org));
  }

  async createOrganisationMember(
    member: OrganisationMember
  ): Promise<OrganisationMember> {
    this.members.set(member.id, clone(member));
    return clone(member);
  }

  async updateOrganisationMember(
    id: string,
    patch: Partial<OrganisationMember>
  ): Promise<OrganisationMember | null> {
    const existing = this.members.get(id);
    if (!existing) return null;
    const updated = mergeEntity(existing, patch);
    this.members.set(id, clone(updated));
    return clone(updated);
  }

  async getOrganisationMember(
    organisationId: string,
    userId: string
  ): Promise<OrganisationMember | null> {
    for (const member of this.members.values()) {
      if (member.organisationId === organisationId && member.userId === userId) {
        return clone(member);
      }
    }

    return null;
  }

  async getOrganisationMemberById(id: string): Promise<OrganisationMember | null> {
    const member = this.members.get(id);
    return member ? clone(member) : null;
  }

  async listOrganisationMembers(organisationId: string): Promise<OrganisationMember[]> {
    return [...this.members.values()]
      .filter((member) => member.organisationId === organisationId)
      .map((member) => clone(member));
  }

  async listInvitationsByOrganisationId(organisationId: string): Promise<Invitation[]> {
    return [...this.invitations.values()]
      .filter((inv) => inv.organisationId === organisationId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .map((inv) => clone(inv));
  }

  async createInvitation(invitation: Invitation): Promise<Invitation> {
    this.invitations.set(invitation.id, clone(invitation));
    return clone(invitation);
  }

  async updateInvitation(
    id: string,
    patch: Partial<Invitation>
  ): Promise<Invitation | null> {
    const existing = this.invitations.get(id);
    if (!existing) return null;
    const updated = mergeEntity(existing, patch);
    this.invitations.set(id, clone(updated));
    return clone(updated);
  }

  async getInvitationById(id: string): Promise<Invitation | null> {
    const invitation = this.invitations.get(id);
    return invitation ? clone(invitation) : null;
  }

  async getInvitationByTokenId(tokenId: string): Promise<Invitation | null> {
    const invitation = [...this.invitations.values()].find(
      (candidate) => candidate.tokenId === tokenId
    );
    return invitation ? clone(invitation) : null;
  }

  async getPendingInvitationByOrganisationAndEmail(
    organisationId: string,
    email: string
  ): Promise<Invitation | null> {
    const matching = [...this.invitations.values()]
      .filter(
        (invitation) =>
          invitation.organisationId === organisationId &&
          invitation.email === email &&
          invitation.status === "pending"
      )
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    return matching[0] ? clone(matching[0]) : null;
  }

  async createAuditEvent(event: AuditEvent): Promise<AuditEvent> {
    this.auditEvents.set(event.id, clone(event));
    return clone(event);
  }

  async listAuditEvents(filter?: {
    userId?: string;
    organisationId?: string;
    apiKeyId?: string;
  }): Promise<AuditEvent[]> {
    return [...this.auditEvents.values()]
      .filter((event) => {
        if (filter?.userId && event.actorUserId !== filter.userId && event.targetUserId !== filter.userId) {
          return false;
        }

        if (filter?.organisationId && event.organisationId !== filter.organisationId) {
          return false;
        }

        if (filter?.apiKeyId && event.apiKeyId !== filter.apiKeyId) {
          return false;
        }

        return true;
      })
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .map((event) => clone(event));
  }

  async deleteAuditEventsBefore(olderThan: Date): Promise<number> {
    let deleted = 0;

    for (const [id, event] of this.auditEvents) {
      if (event.createdAt < olderThan) {
        this.auditEvents.delete(id);
        deleted += 1;
      }
    }

    return deleted;
  }
}
