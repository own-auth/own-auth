import type {
  AtomicAuthEventWrite,
  AtomicAuthenticationMethodRemovalInput,
  AtomicEmailOwnershipInput,
  AtomicEmailOwnershipResult,
  AtomicPasswordUpdateInput,
  AtomicAuthenticationMethodRemovalResult,
  AtomicInvitationAcceptanceInput,
  AtomicInvitationAcceptanceResult,
  AtomicInvitationRevocationInput
} from "./auth-storage-atomic.js";
import type {
  AuditEventFilter,
  AuthStorage,
  ListUsersFilter,
  StoragePageCursor
} from "./storage.js";
import { MemoryIdentityStorage } from "./memory-identity-storage.js";
import {
  cloneStored as clone,
  findStored,
  someStored,
  updateStoredEntity
} from "./memory-storage-helpers.js";
import { createIdentityConflictError } from "./errors.js";
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
import { MemoryWebhookStorage } from "./memory-webhook-storage.js";
import { MemoryAuthorizationServerStorage } from "./memory-authorization-server-storage.js";
import { MemorySamlStorage } from "./memory-saml-storage.js";
import { MemoryScimStorage } from "./memory-scim-storage.js";
import { MemoryCloudStorage } from "./memory-cloud-storage.js";

function isUsableSmsOtp(otp: SmsOtp, at: Date): boolean {
  return (
    !otp.consumedAt &&
    otp.expiresAt.getTime() > at.getTime() &&
    otp.attempts < otp.maxAttempts
  );
}

export class InMemoryAuthStorage extends MemoryIdentityStorage implements AuthStorage {
  private readonly passwordResetVersions = new Map<string, number>();

  async updatePasswordAtomically(input: AtomicPasswordUpdateInput): Promise<User | null> {
    const user = this.users.get(input.userId);
    if (!user || user.passwordHash !== input.expectedPasswordHash || user.disabledAt) return null;
    const updated = { ...user, passwordHash: input.passwordHash, updatedAt: input.updatedAt };
    this.users.set(user.id, updated);
    if (input.purpose === "replacement") {
      this.passwordResetVersions.set(user.id, (this.passwordResetVersions.get(user.id) ?? 1) + 1);
    }
    return clone(updated);
  }

  async claimEmailOwnershipAtomically(input: AtomicEmailOwnershipInput): Promise<AtomicEmailOwnershipResult | null> {
    const source = input.sourceUserId ? this.users.get(input.sourceUserId) : undefined;
    const proof = input.proof;
    const token = proof.kind === "token"
      ? findStored(this.tokens, (candidate) =>
          candidate.tokenHash === proof.tokenHash && candidate.type === proof.type &&
          candidate.email === input.email && (!candidate.userId || candidate.userId === input.sourceUserId) &&
          !candidate.usedAt && candidate.expiresAt > input.verifiedAt)
      : undefined;
    if (input.proof.kind === "token" && !token) return null;
    if (token && !this.isCurrentResetToken(token)) return null;
    if (input.sourceUserId && (!source || source.email !== input.email ||
      (source.emailVerifiedAt && source.disabledAt &&
        !(input.proof.kind === "token" && input.proof.type === "password_reset")))) return null;
    if (source && proof.kind === "provider" && proof.samlOrganisationId &&
      someStored(this.members, (member) => member.userId === source.id &&
        member.organisationId === proof.samlOrganisationId && member.status !== "active")) return null;
    if (!source && someStored(this.users, (user) => user.email === input.email)) return null;
    const originalSession = source && someStored(this.sessions, (session) =>
      session.userId === source.id && session.tokenHash === input.sessionTokenHash &&
      !session.revokedAt && session.expiresAt > input.verifiedAt && session.idleExpiresAt > input.verifiedAt);
    const noUnprovedAccess = source && !source.passwordHash && !source.phone &&
      !someStored(this.sessions, (session) => session.userId === source.id) &&
      !someStored(this.apiKeys, (key) => key.userId === source.id) &&
      !someStored(this.organisations, (organisation) => organisation.ownerUserId === source.id) &&
      !this.authorizationServerStorage.hasUserAuthorization(source.id) &&
      !this.hasUnprovedCredentials(source.id, input.verifiedAccountId);
    const keep = source && (source.emailVerifiedAt !== null || (!source.disabledAt &&
      (originalSession || noUnprovedAccess ||
        (input.proof.kind === "provider" && input.proof.originalActorUserId === source.id))));
    const owner: User = keep ? {
      ...source,
      emailVerifiedAt: source.emailVerifiedAt ?? input.verifiedAt,
      ...(input.passwordHash === undefined ? {} : { passwordHash: input.passwordHash }),
      updatedAt: input.verifiedAt
    } : clone(input.replacementUser);
    if (!keep && this.users.has(owner.id)) throw createIdentityConflictError("email");
    if (!keep && (this.accounts.has(input.replacementAccount.id) ||
      someStored(this.accounts, (account) => account.provider === input.replacementAccount.provider &&
        account.providerAccountId === input.replacementAccount.providerAccountId &&
        !(source && account.userId === source.id &&
          (account.provider === "password" || account.provider === "magic_link") && account.providerAccountId === input.email)))) {
      throw createIdentityConflictError("providerAccount");
    }
    let reassignedMemberships: OrganisationMember<string>[] = [];
    const revokedSessions: Session[] = [];
    if (!keep && source) {
      this.users.set(source.id, { ...source, email: null, emailVerifiedAt: null, updatedAt: input.verifiedAt });
      for (const account of this.accounts.values()) {
        if (account.userId !== source.id) continue;
        if ((account.provider === "password" || account.provider === "magic_link") &&
          account.providerAccountId === input.email) this.deleteStoredAccount(account.id);
        else if (account.id === input.verifiedAccountId) {
          this.accounts.set(account.id, { ...account, userId: owner.id, updatedAt: input.verifiedAt });
        }
      }
      reassignedMemberships = this.scimStorage.reassignEmailOwner(source.id, owner.id, input.email, input.verifiedAt);
      for (const session of this.sessions.values()) {
        if (session.userId !== source.id || session.revokedAt) continue;
        const revoked = { ...session, revokedAt: input.verifiedAt, revokeReason: "email_ownership_changed" };
        this.sessions.set(session.id, revoked);
        revokedSessions.push(clone(revoked));
      }
    }
    this.users.set(owner.id, clone(owner));
    if (input.passwordHash !== undefined && source) {
      this.passwordResetVersions.set(source.id, (this.passwordResetVersions.get(source.id) ?? 1) + 1);
    }
    if (!keep) this.accounts.set(input.replacementAccount.id, clone(input.replacementAccount));
    if (token) this.tokens.set(token.id, { ...token, usedAt: input.verifiedAt });
    return { user: clone(owner), created: !keep, verified: !source?.emailVerifiedAt, revokedSessions, reassignedMemberships };
  }
  protected readonly users = new Map<string, User>();
  protected readonly sessions = new Map<string, Session>();
  private readonly tokens = new Map<string, AuthToken>();
  private readonly smsOtps = new Map<string, SmsOtp>();
  private readonly apiKeys = new Map<string, ApiKey>();
  protected readonly organisations = new Map<string, Organisation>();
  protected readonly members = new Map<string, OrganisationMember<string>>();
  private readonly invitations = new Map<string, Invitation<string>>();
  protected readonly auditEvents = new Map<string, AuditEvent>();
  readonly webhookStorage = new MemoryWebhookStorage(this.auditEvents);
  readonly authorizationServerStorage = new MemoryAuthorizationServerStorage();
  readonly samlStorage = new MemorySamlStorage({
    users: this.users,
    accounts: this.accounts,
    members: this.members,
    auditEvents: this.auditEvents
  });
  readonly scimStorage = new MemoryScimStorage({
    users: this.users,
    members: this.members,
    auditEvents: this.auditEvents
  });
  readonly cloudStorage = new MemoryCloudStorage({
    users: this.users,
    sessions: this.sessions,
    organisations: this.organisations,
    members: this.members
  });

  async createUser(user: User): Promise<User> {
    this.assertUserIdentityAvailable(user);
    this.users.set(user.id, clone(user));
    return clone(user);
  }

  async updateUser(id: string, patch: Partial<User>): Promise<User | null> {
    const existing = this.users.get(id);
    if (!existing) {
      return null;
    }
    this.assertUserIdentityAvailable({ ...existing, ...patch, id }, id);
    return updateStoredEntity(this.users, id, patch);
  }

  async getUserById(id: string): Promise<User | null> {
    const user = this.users.get(id);
    return user ? clone(user) : null;
  }

  async getUserByEmail(email: string): Promise<User | null> {
    return findStored(this.users, (user) => user.email === email);
  }

  async getUserByPhone(phone: string): Promise<User | null> {
    return findStored(this.users, (user) => user.phone === phone);
  }

  async listUsers(filter?: ListUsersFilter): Promise<User[]> {
    const query = filter?.query?.toLowerCase();
    const status = filter?.status ?? "all";
    const users = [...this.users.values()]
      .filter((user) => {
        if (status === "active" && user.disabledAt) return false;
        if (status === "disabled" && !user.disabledAt) return false;
        if (
          query &&
          !user.email?.toLowerCase().startsWith(query) &&
          !user.name?.toLowerCase().startsWith(query)
        ) {
          return false;
        }
        return isBeforeCursor(user, filter?.cursor);
      })
      .sort(compareNewestFirst);
    return take(users, filter?.limit)
      .map((user) => clone(user));
  }

  async createUserAndAccount(user: User, account: Account): Promise<Account> {
    this.assertUserIdentityAvailable(user);
    this.users.set(user.id, clone(user));
    try {
      return await this.createAccount(account);
    } catch (error) {
      this.users.delete(user.id);
      throw error;
    }
  }

  private assertUserIdentityAvailable(user: User, excludeId?: string): void {
    for (const candidate of this.users.values()) {
      if (candidate.id === excludeId) {
        continue;
      }
      if (user.email && candidate.email === user.email) {
        throw createIdentityConflictError("email");
      }
      if (user.phone && candidate.phone === user.phone) {
        throw createIdentityConflictError("phone");
      }
    }
  }

  async createSession(session: Session): Promise<Session> {
    this.sessions.set(session.id, clone(session));
    return clone(session);
  }

  async getSessionByTokenHash(tokenHash: string): Promise<Session | null> {
    return findStored(this.sessions, (session) => session.tokenHash === tokenHash);
  }

  async updateSession(id: string, patch: Partial<Session>): Promise<Session | null> {
    return updateStoredEntity(this.sessions, id, patch);
  }

  async listSessionsByUserId(userId: string): Promise<Session[]> {
    return [...this.sessions.values()]
      .filter((session) => session.userId === userId)
      .map((session) => clone(session));
  }

  async createToken(token: AuthToken): Promise<AuthToken> {
    const stored = token.type === "password_reset"
      ? { ...token, passwordResetVersion: this.passwordResetVersions.get(token.userId ?? "") ?? 1 }
      : token;
    this.tokens.set(token.id, clone(stored));
    return clone(stored);
  }

  async getTokenByHash(tokenHash: string, type?: TokenType): Promise<AuthToken | null> {
    return findStored(
      this.tokens,
      (token) => token.tokenHash === tokenHash && (!type || token.type === type) &&
        (token.usedAt !== null || this.isCurrentResetToken(token))
    );
  }

  async consumeToken(
    tokenHash: string,
    type: TokenType,
    consumedAt: Date
  ): Promise<AuthToken | null> {
    for (const [id, token] of this.tokens) {
      if (
        token.tokenHash !== tokenHash ||
        token.type !== type ||
        token.usedAt ||
        !this.isCurrentResetToken(token) ||
        token.expiresAt.getTime() <= consumedAt.getTime()
      ) {
        continue;
      }

      return updateStoredEntity(this.tokens, id, { usedAt: consumedAt });
    }

    return null;
  }

  async updateToken(id: string, patch: Partial<AuthToken>): Promise<AuthToken | null> {
    return updateStoredEntity(this.tokens, id, patch);
  }

  private isCurrentResetToken(token: AuthToken): boolean {
    return token.type !== "password_reset" || Boolean(token.userId && this.users.has(token.userId) &&
      (token.passwordResetVersion ?? 0) === (this.passwordResetVersions.get(token.userId) ?? 1));
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

  async incrementSmsOtpAttempts(id: string, attemptedAt: Date): Promise<SmsOtp | null> {
    const existing = this.smsOtps.get(id);
    if (!existing || !isUsableSmsOtp(existing, attemptedAt)) {
      return null;
    }

    return updateStoredEntity(this.smsOtps, id, {
      attempts: existing.attempts + 1
    });
  }

  async consumeSmsOtp(id: string, consumedAt: Date): Promise<SmsOtp | null> {
    const existing = this.smsOtps.get(id);
    if (!existing || !isUsableSmsOtp(existing, consumedAt)) {
      return null;
    }

    return updateStoredEntity(this.smsOtps, id, {
      attempts: existing.attempts + 1,
      consumedAt
    });
  }

  async updateSmsOtp(id: string, patch: Partial<SmsOtp>): Promise<SmsOtp | null> {
    return updateStoredEntity(this.smsOtps, id, patch);
  }

  async createApiKey(apiKey: ApiKey): Promise<ApiKey> {
    this.apiKeys.set(apiKey.id, clone(apiKey));
    return clone(apiKey);
  }

  async getApiKeyByPrefix(keyPrefix: string): Promise<ApiKey | null> {
    return findStored(this.apiKeys, (apiKey) => apiKey.keyPrefix === keyPrefix);
  }

  async updateApiKey(id: string, patch: Partial<ApiKey>): Promise<ApiKey | null> {
    return updateStoredEntity(this.apiKeys, id, patch);
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
    return updateStoredEntity(this.organisations, id, patch);
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
    return findStored(this.organisations, (organisation) => organisation.slug === slug);
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
    member: OrganisationMember<string>
  ): Promise<OrganisationMember<string>> {
    this.members.set(member.id, clone(member));
    return clone(member);
  }

  async updateOrganisationMember(
    id: string,
    patch: Partial<OrganisationMember<string>>
  ): Promise<OrganisationMember<string> | null> {
    return updateStoredEntity(this.members, id, patch);
  }

  async getOrganisationMember(
    organisationId: string,
    userId: string
  ): Promise<OrganisationMember<string> | null> {
    return findStored(
      this.members,
      (member) => member.organisationId === organisationId && member.userId === userId
    );
  }

  async getOrganisationMemberById(id: string): Promise<OrganisationMember<string> | null> {
    const member = this.members.get(id);
    return member ? clone(member) : null;
  }

  async listOrganisationMembers(
    organisationId: string
  ): Promise<OrganisationMember<string>[]> {
    return [...this.members.values()]
      .filter((member) => member.organisationId === organisationId)
      .map((member) => clone(member));
  }

  async listInvitationsByOrganisationId(
    organisationId: string
  ): Promise<Invitation<string>[]> {
    return [...this.invitations.values()]
      .filter((inv) => inv.organisationId === organisationId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .map((inv) => clone(inv));
  }

  async createInvitation(invitation: Invitation<string>): Promise<Invitation<string>> {
    this.invitations.set(invitation.id, clone(invitation));
    return clone(invitation);
  }

  async updateInvitation(
    id: string,
    patch: Partial<Invitation<string>>
  ): Promise<Invitation<string> | null> {
    return updateStoredEntity(this.invitations, id, patch);
  }

  async getInvitationById(id: string): Promise<Invitation<string> | null> {
    const invitation = this.invitations.get(id);
    return invitation ? clone(invitation) : null;
  }

  async getInvitationByTokenId(tokenId: string): Promise<Invitation<string> | null> {
    return findStored(this.invitations, (invitation) => invitation.tokenId === tokenId);
  }

  async getPendingInvitationByOrganisationAndEmail(
    organisationId: string,
    email: string
  ): Promise<Invitation<string> | null> {
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

  async acceptInvitationAtomically(
    input: AtomicInvitationAcceptanceInput
  ): Promise<AtomicInvitationAcceptanceResult | null> {
    const token = this.tokens.get(input.tokenId);
    const invitation = this.invitations.get(input.invitationId);
    const user = this.users.get(input.userId);
    const organisation = invitation
      ? this.organisations.get(invitation.organisationId)
      : undefined;
    if (
      !token ||
      token.tokenHash !== input.tokenHash ||
      token.type !== "organisation_invite" ||
      token.usedAt ||
      token.expiresAt <= input.acceptedAt ||
      !invitation ||
      invitation.tokenId !== token.id ||
      invitation.status !== "pending" ||
      invitation.expiresAt <= input.acceptedAt ||
      invitation.organisationId !== token.organisationId ||
      !invitation.email ||
      invitation.email !== token.email ||
      !user ||
      user.disabledAt ||
      user.email !== token.email ||
      !organisation ||
      organisation.disabledAt
    ) {
      return null;
    }

    const existingMember = [...this.members.values()].find(
      (member) =>
        member.organisationId === invitation.organisationId &&
        member.userId === user.id
    );
    const member: OrganisationMember<string> = existingMember
      ? {
          ...existingMember,
          role: invitation.role,
          status: "active",
          joinedAt: existingMember.joinedAt ?? input.acceptedAt,
          removedAt: null,
          updatedAt: input.acceptedAt
        }
      : {
          id: input.memberId,
          organisationId: invitation.organisationId,
          userId: user.id,
          role: invitation.role,
          status: "active",
          joinedAt: input.acceptedAt,
          removedAt: null,
          createdAt: input.acceptedAt,
          updatedAt: input.acceptedAt
        };
    const acceptedInvitation: Invitation<string> = {
      ...invitation,
      status: "accepted",
      acceptedAt: input.acceptedAt
    };

    this.recordAtomicEvent(input.event);
    this.tokens.set(token.id, clone({ ...token, usedAt: input.acceptedAt }));
    this.members.set(member.id, clone(member));
    this.invitations.set(invitation.id, clone(acceptedInvitation));

    return {
      invitation: clone(acceptedInvitation),
      member: clone(member)
    };
  }

  async removeAuthenticationMethodAtomically(
    input: AtomicAuthenticationMethodRemovalInput
  ): Promise<AtomicAuthenticationMethodRemovalResult> {
    const user = this.users.get(input.userId);
    const account = input.method.kind === "account"
      ? this.accounts.get(input.method.id)
      : undefined;
    const passkey = input.method.kind === "passkey"
      ? this.passkeys.get(input.method.id)
      : undefined;
    if (
      !user ||
      (input.method.kind === "account" && account?.userId !== user.id) ||
      (input.method.kind === "passkey" && passkey?.userId !== user.id)
    ) {
      return "not_found";
    }

    const hasRemainingMethod = Boolean(
      user.passwordHash ||
      user.email ||
      user.phone ||
      [...this.accounts.values()].some(
        (candidate) =>
          candidate.userId === user.id &&
          (input.method.kind !== "account" || candidate.id !== input.method.id) &&
          isLoginAccount(candidate)
      ) ||
      [...this.passkeys.values()].some(
        (candidate) =>
          candidate.userId === user.id &&
          (input.method.kind !== "passkey" || candidate.id !== input.method.id)
      )
    );
    if (!hasRemainingMethod) {
      return "last_method";
    }

    this.recordAtomicEvent(input.event);
    if (input.method.kind === "account") {
      this.deleteStoredAccount(input.method.id);
    } else {
      this.deleteStoredPasskey(input.method.id);
    }
    return "removed";
  }

  async revokeInvitationAtomically(
    input: AtomicInvitationRevocationInput
  ): Promise<Invitation<string> | null> {
    const invitation = this.invitations.get(input.invitationId);
    if (!invitation || invitation.status !== "pending") {
      return null;
    }

    const revokedInvitation: Invitation<string> = {
      ...invitation,
      status: "revoked",
      revokedAt: input.revokedAt
    };
    const token = invitation.tokenId
      ? this.tokens.get(invitation.tokenId)
      : undefined;

    this.recordAtomicEvent(input.event);
    this.invitations.set(invitation.id, clone(revokedInvitation));
    if (token) {
      this.tokens.set(token.id, clone({
        ...token,
        usedAt: token.usedAt ?? input.revokedAt
      }));
    }
    return clone(revokedInvitation);
  }

  async createAuditEvent(event: AuditEvent): Promise<AuditEvent> {
    this.auditEvents.set(event.id, clone(event));
    return clone(event);
  }

  async listAuditEvents(filter?: AuditEventFilter): Promise<AuditEvent[]> {
    const events = [...this.auditEvents.values()]
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
      .filter((event) => isBeforeCursor(event, filter?.cursor))
      .sort(compareNewestFirst);
    return take(events, filter?.limit)
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

  private recordAtomicEvent(write: AtomicAuthEventWrite): void {
    if (write.webhookEvent) {
      this.webhookStorage.recordAuditEventWithWebhooksSync(
        write.auditEvent,
        write.webhookEvent,
        write.webhookDeliveries
      );
      return;
    }
    if (write.webhookDeliveries.length > 0) {
      throw new Error("Webhook deliveries require a webhook event");
    }
    if (this.auditEvents.has(write.auditEvent.id)) {
      throw new Error("Audit event already exists");
    }
    this.auditEvents.set(write.auditEvent.id, clone(write.auditEvent));
  }
}

function isLoginAccount(account: Account): boolean {
  return (
    account.provider === "apple" ||
    account.provider === "github" ||
    account.provider === "google" ||
    account.provider.startsWith("saml.")
  );
}

function compareNewestFirst(
  left: { createdAt: Date; id: string },
  right: { createdAt: Date; id: string }
): number {
  return right.createdAt.getTime() - left.createdAt.getTime() ||
    right.id.localeCompare(left.id);
}

function take<Value>(values: Value[], limit: number | undefined): Value[] {
  return limit === undefined ? values : values.slice(0, limit);
}

function isBeforeCursor(
  value: { createdAt: Date; id: string },
  cursor: StoragePageCursor | undefined
): boolean {
  if (!cursor) return true;
  const timeDifference = value.createdAt.getTime() - cursor.createdAt.getTime();
  return timeDifference < 0 || (timeDifference === 0 && value.id < cursor.id);
}
