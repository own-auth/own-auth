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
import type {
  MfaChallenge,
  OAuthCredential,
  OAuthTransaction,
  PasskeyCredential,
  RecoveryCode,
  TotpFactor,
  WebAuthnChallenge
} from "./identity-types.js";

export interface AuditEventFilter {
  userId?: string;
  organisationId?: string;
  apiKeyId?: string;
}

export interface AuthStorage {
  createUser(user: User): Promise<User>;
  updateUser(id: string, patch: Partial<User>): Promise<User | null>;
  getUserById(id: string): Promise<User | null>;
  getUserByEmail(email: string): Promise<User | null>;
  getUserByPhone(phone: string): Promise<User | null>;

  createAccount(account: Account): Promise<Account>;
  createUserAndAccount(user: User, account: Account): Promise<Account>;
  getAccountByProvider(provider: string, providerAccountId: string): Promise<Account | null>;
  listAccountsByUserId(userId: string): Promise<Account[]>;
  deleteAccount(id: string): Promise<boolean>;

  createSession(session: Session): Promise<Session>;
  getSessionByTokenHash(tokenHash: string): Promise<Session | null>;
  updateSession(id: string, patch: Partial<Session>): Promise<Session | null>;
  listSessionsByUserId(userId: string): Promise<Session[]>;

  createToken(token: AuthToken): Promise<AuthToken>;
  getTokenByHash(tokenHash: string, type?: TokenType): Promise<AuthToken | null>;
  /** Atomically marks one unused, unexpired token as consumed. */
  consumeToken(tokenHash: string, type: TokenType, consumedAt: Date): Promise<AuthToken | null>;
  updateToken(id: string, patch: Partial<AuthToken>): Promise<AuthToken | null>;

  createSmsOtp(otp: SmsOtp): Promise<SmsOtp>;
  getLatestSmsOtp(phone: string, purpose: string): Promise<SmsOtp | null>;
  /** Atomically increments attempts only while the OTP remains usable. */
  incrementSmsOtpAttempts(id: string, attemptedAt: Date): Promise<SmsOtp | null>;
  /** Atomically consumes one unused, unexpired OTP below its attempt limit. */
  consumeSmsOtp(id: string, consumedAt: Date): Promise<SmsOtp | null>;
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

  createOrganisationMember(
    member: OrganisationMember<string>
  ): Promise<OrganisationMember<string>>;
  updateOrganisationMember(
    id: string,
    patch: Partial<OrganisationMember<string>>
  ): Promise<OrganisationMember<string> | null>;
  getOrganisationMember(
    organisationId: string,
    userId: string
  ): Promise<OrganisationMember<string> | null>;
  getOrganisationMemberById(id: string): Promise<OrganisationMember<string> | null>;
  listOrganisationMembers(organisationId: string): Promise<OrganisationMember<string>[]>;

  createInvitation(invitation: Invitation<string>): Promise<Invitation<string>>;
  updateInvitation(
    id: string,
    patch: Partial<Invitation<string>>
  ): Promise<Invitation<string> | null>;
  getInvitationById(id: string): Promise<Invitation<string> | null>;
  getInvitationByTokenId(tokenId: string): Promise<Invitation<string> | null>;
  listInvitationsByOrganisationId(organisationId: string): Promise<Invitation<string>[]>;
  getPendingInvitationByOrganisationAndEmail(
    organisationId: string,
    email: string
  ): Promise<Invitation<string> | null>;

  createAuditEvent(event: AuditEvent): Promise<AuditEvent>;
  listAuditEvents(filter?: AuditEventFilter): Promise<AuditEvent[]>;
  deleteAuditEventsBefore(olderThan: Date): Promise<number>;

  createOAuthTransaction(transaction: OAuthTransaction): Promise<OAuthTransaction>;
  consumeOAuthTransaction(
    stateHash: string,
    flowKind: OAuthTransaction["flowKind"],
    consumedAt: Date
  ): Promise<OAuthTransaction | null>;

  getOAuthCredentialByAccountId(accountId: string): Promise<OAuthCredential | null>;
  upsertOAuthCredential(credential: OAuthCredential): Promise<OAuthCredential>;
  rotateOAuthCredential(
    id: string,
    expectedCiphertext: string,
    patch: Partial<OAuthCredential>
  ): Promise<OAuthCredential | null>;
  deleteOAuthCredentialByAccountId(accountId: string): Promise<boolean>;

  createTotpFactor(factor: TotpFactor): Promise<TotpFactor>;
  getTotpFactorById(id: string): Promise<TotpFactor | null>;
  getActiveTotpFactorByUserId(userId: string): Promise<TotpFactor | null>;
  updateTotpFactor(id: string, patch: Partial<TotpFactor>): Promise<TotpFactor | null>;
  activateTotpFactor(id: string, timestep: number, activatedAt: Date): Promise<TotpFactor | null>;
  useTotpTimestep(id: string, timestep: number, usedAt: Date): Promise<TotpFactor | null>;

  replaceRecoveryCodes(userId: string, codes: RecoveryCode[]): Promise<void>;
  consumeRecoveryCode(
    userId: string,
    codeHash: string,
    consumedAt: Date
  ): Promise<RecoveryCode | null>;

  createMfaChallenge(challenge: MfaChallenge): Promise<MfaChallenge>;
  getMfaChallengeById(id: string): Promise<MfaChallenge | null>;
  getMfaChallengeByTokenHash(tokenHash: string): Promise<MfaChallenge | null>;
  incrementMfaChallengeAttempts(id: string, attemptedAt: Date): Promise<MfaChallenge | null>;
  consumeMfaChallenge(id: string, consumedAt: Date): Promise<MfaChallenge | null>;

  createPasskeyCredential(credential: PasskeyCredential): Promise<PasskeyCredential>;
  getPasskeyCredentialById(id: string): Promise<PasskeyCredential | null>;
  getPasskeyCredentialByCredentialId(credentialId: string): Promise<PasskeyCredential | null>;
  listPasskeyCredentialsByUserId(userId: string): Promise<PasskeyCredential[]>;
  updatePasskeyCredential(
    id: string,
    patch: Partial<PasskeyCredential>
  ): Promise<PasskeyCredential | null>;
  updatePasskeyCounter(
    id: string,
    expectedCounter: number,
    nextCounter: number,
    usedAt: Date
  ): Promise<PasskeyCredential | null>;
  deletePasskeyCredential(id: string): Promise<boolean>;

  createWebAuthnChallenge(challenge: WebAuthnChallenge): Promise<WebAuthnChallenge>;
  consumeWebAuthnChallenge(
    challengeHash: string,
    purpose: WebAuthnChallenge["purpose"],
    consumedAt: Date
  ): Promise<WebAuthnChallenge | null>;
}
