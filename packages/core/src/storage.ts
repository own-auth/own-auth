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

export interface AuthStorage {
  createUser(user: User): Promise<User>;
  updateUser(id: string, patch: Partial<User>): Promise<User | null>;
  getUserById(id: string): Promise<User | null>;
  getUserByEmail(email: string): Promise<User | null>;
  getUserByPhone(phone: string): Promise<User | null>;

  createAccount(account: Account): Promise<Account>;
  getAccountByProvider(provider: string, providerAccountId: string): Promise<Account | null>;

  createSession(session: Session): Promise<Session>;
  getSessionByTokenHash(tokenHash: string): Promise<Session | null>;
  updateSession(id: string, patch: Partial<Session>): Promise<Session | null>;
  listSessionsByUserId(userId: string): Promise<Session[]>;

  createToken(token: AuthToken): Promise<AuthToken>;
  getTokenByHash(tokenHash: string, type?: TokenType): Promise<AuthToken | null>;
  updateToken(id: string, patch: Partial<AuthToken>): Promise<AuthToken | null>;

  createSmsOtp(otp: SmsOtp): Promise<SmsOtp>;
  getLatestSmsOtp(phone: string, purpose: string): Promise<SmsOtp | null>;
  updateSmsOtp(id: string, patch: Partial<SmsOtp>): Promise<SmsOtp | null>;

  createApiKey(apiKey: ApiKey): Promise<ApiKey>;
  getApiKeyByPrefix(keyPrefix: string): Promise<ApiKey | null>;
  updateApiKey(id: string, patch: Partial<ApiKey>): Promise<ApiKey | null>;
  listApiKeysByOrganisationId(organisationId: string): Promise<ApiKey[]>;
  listApiKeysByUserId(userId: string): Promise<ApiKey[]>;

  createOrganisation(organisation: Organisation): Promise<Organisation>;
  updateOrganisation(id: string, patch: Partial<Organisation>): Promise<Organisation | null>;
  deleteOrganisation(id: string): Promise<boolean>;
  getOrganisationById(id: string): Promise<Organisation | null>;
  getOrganisationBySlug(slug: string): Promise<Organisation | null>;
  listOrganisationsByUserId(userId: string): Promise<Organisation[]>;

  createOrganisationMember(member: OrganisationMember): Promise<OrganisationMember>;
  updateOrganisationMember(
    id: string,
    patch: Partial<OrganisationMember>
  ): Promise<OrganisationMember | null>;
  getOrganisationMember(
    organisationId: string,
    userId: string
  ): Promise<OrganisationMember | null>;
  getOrganisationMemberById(id: string): Promise<OrganisationMember | null>;
  listOrganisationMembers(organisationId: string): Promise<OrganisationMember[]>;

  createInvitation(invitation: Invitation): Promise<Invitation>;
  updateInvitation(id: string, patch: Partial<Invitation>): Promise<Invitation | null>;
  getInvitationById(id: string): Promise<Invitation | null>;
  getInvitationByTokenId(tokenId: string): Promise<Invitation | null>;
  listInvitationsByOrganisationId(organisationId: string): Promise<Invitation[]>;
  getPendingInvitationByOrganisationAndEmail(
    organisationId: string,
    email: string
  ): Promise<Invitation | null>;

  createAuditEvent(event: AuditEvent): Promise<AuditEvent>;
  listAuditEvents(filter?: {
    userId?: string;
    organisationId?: string;
    apiKeyId?: string;
  }): Promise<AuditEvent[]>;
  deleteAuditEventsBefore(olderThan: Date): Promise<number>;
}
