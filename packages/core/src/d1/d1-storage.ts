import type { AuditEventFilter, AuthStorage } from "../storage.js";
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
} from "../types.js";
import type { DatabaseRow } from "../database-types.js";
import {
  mapAccount,
  mapApiKey,
  mapAuditEvent,
  mapInvitation,
  mapOrganisation,
  mapOrganisationMember,
  mapSession,
  mapSmsOtp,
  mapToken,
  mapUser
} from "../database-mappers.js";
import {
  accountColumns,
  accountReturning,
  apiKeyColumns,
  apiKeyReturning,
  auditEventColumns,
  auditEventReturning,
  invitationColumns,
  invitationReturning,
  organisationColumns,
  organisationMemberColumns,
  organisationMemberReturning,
  organisationReturning,
  sessionColumns,
  sessionReturning,
  smsOtpColumns,
  smsOtpReturning,
  tokenColumns,
  tokenReturning,
  userColumns,
  userReturning
} from "../database-schema.js";
import {
  atomicConsumeD1SmsOtp,
  atomicConsumeD1Token,
  atomicIncrementD1SmsOtpAttempts
} from "./d1-atomic-operations.js";
import { rethrowD1IdentityError } from "./d1-errors.js";
import { D1IdentityStorage } from "./d1-identity-storage.js";
import type { D1DatabaseLike } from "./d1-types.js";
import { D1WebhookStorage } from "./d1-webhook-storage.js";

export class D1AuthStorage extends D1IdentityStorage implements AuthStorage {
  readonly webhookStorage = new D1WebhookStorage(this.db);
  async createUser(user: User): Promise<User> {
    try {
      return mapUser(await this.insertOne("own_auth_users", userColumns, user, userReturning));
    } catch (error) {
      rethrowD1IdentityError(error);
    }
  }

  async updateUser(id: string, patch: Partial<User>): Promise<User | null> {
    try {
      const row = await this.updateOne("own_auth_users", userColumns, id, patch, userReturning);
      return row ? mapUser(row) : null;
    } catch (error) {
      rethrowD1IdentityError(error);
    }
  }

  async getUserById(id: string): Promise<User | null> {
    const row = await this.selectOne(`${userReturning} from own_auth_users where id = ?1`, [id]);
    return row ? mapUser(row) : null;
  }

  async getUserByEmail(email: string): Promise<User | null> {
    const row = await this.selectOne(
      `${userReturning} from own_auth_users where lower(email) = lower(?1)`,
      [email]
    );
    return row ? mapUser(row) : null;
  }

  async getUserByPhone(phone: string): Promise<User | null> {
    const row = await this.selectOne(`${userReturning} from own_auth_users where phone = ?1`, [phone]);
    return row ? mapUser(row) : null;
  }

  async createAccount(account: Account): Promise<Account> {
    try {
      return mapAccount(await this.insertOne(
        "own_auth_accounts",
        accountColumns,
        account,
        accountReturning
      ));
    } catch (error) {
      rethrowD1IdentityError(error);
    }
  }

  async createUserAndAccount(user: User, account: Account): Promise<Account> {
    try {
      const results = await this.db.batch<DatabaseRow>([
        this.insertStatement("own_auth_users", userColumns, user, userReturning),
        this.insertStatement("own_auth_accounts", accountColumns, account, accountReturning)
      ]);
      const row = results[1]?.results?.[0];
      if (!row) {
        throw new Error("D1 identity creation returned no account");
      }
      return mapAccount(row);
    } catch (error) {
      rethrowD1IdentityError(error);
    }
  }

  async getAccountByProvider(provider: string, providerAccountId: string): Promise<Account | null> {
    const row = await this.selectOne(
      `${accountReturning} from own_auth_accounts ` +
      "where provider = ?1 and provider_account_id = ?2",
      [provider, providerAccountId]
    );
    return row ? mapAccount(row) : null;
  }

  async listAccountsByUserId(userId: string): Promise<Account[]> {
    const rows = await this.selectMany(
      `${accountReturning} from own_auth_accounts where user_id = ?1 order by created_at asc`,
      [userId]
    );
    return rows.map(mapAccount);
  }

  async deleteAccount(id: string): Promise<boolean> {
    return Boolean(await this.prepare(
      "delete from own_auth_accounts where id = ?1 returning id",
      [id]
    ).first<DatabaseRow>());
  }

  async createSession(session: Session): Promise<Session> {
    return mapSession(await this.insertOne(
      "own_auth_sessions",
      sessionColumns,
      session,
      sessionReturning
    ));
  }

  async getSessionByTokenHash(tokenHash: string): Promise<Session | null> {
    const row = await this.selectOne(
      `${sessionReturning} from own_auth_sessions where token_hash = ?1`,
      [tokenHash]
    );
    return row ? mapSession(row) : null;
  }

  async updateSession(id: string, patch: Partial<Session>): Promise<Session | null> {
    const row = await this.updateOne(
      "own_auth_sessions",
      sessionColumns,
      id,
      patch,
      sessionReturning
    );
    return row ? mapSession(row) : null;
  }

  async listSessionsByUserId(userId: string): Promise<Session[]> {
    const rows = await this.selectMany(
      `${sessionReturning} from own_auth_sessions where user_id = ?1 order by created_at desc`,
      [userId]
    );
    return rows.map(mapSession);
  }

  async createToken(token: AuthToken): Promise<AuthToken> {
    return mapToken(await this.insertOne("own_auth_tokens", tokenColumns, token, tokenReturning));
  }

  async getTokenByHash(tokenHash: string, type?: TokenType): Promise<AuthToken | null> {
    const row = type
      ? await this.selectOne(
          `${tokenReturning} from own_auth_tokens where token_hash = ?1 and type = ?2`,
          [tokenHash, type]
        )
      : await this.selectOne(
          `${tokenReturning} from own_auth_tokens where token_hash = ?1`,
          [tokenHash]
        );
    return row ? mapToken(row) : null;
  }

  consumeToken(tokenHash: string, type: TokenType, consumedAt: Date): Promise<AuthToken | null> {
    return atomicConsumeD1Token(this.db, tokenHash, type, consumedAt);
  }

  async updateToken(id: string, patch: Partial<AuthToken>): Promise<AuthToken | null> {
    const row = await this.updateOne("own_auth_tokens", tokenColumns, id, patch, tokenReturning);
    return row ? mapToken(row) : null;
  }

  async createSmsOtp(otp: SmsOtp): Promise<SmsOtp> {
    return mapSmsOtp(await this.insertOne("own_auth_sms_otps", smsOtpColumns, otp, smsOtpReturning));
  }

  async getLatestSmsOtp(phone: string, purpose: string): Promise<SmsOtp | null> {
    const row = await this.selectOne(
      `${smsOtpReturning} from own_auth_sms_otps ` +
      "where phone = ?1 and purpose = ?2 order by created_at desc limit 1",
      [phone, purpose]
    );
    return row ? mapSmsOtp(row) : null;
  }

  incrementSmsOtpAttempts(id: string, attemptedAt: Date): Promise<SmsOtp | null> {
    return atomicIncrementD1SmsOtpAttempts(this.db, id, attemptedAt);
  }

  consumeSmsOtp(id: string, consumedAt: Date): Promise<SmsOtp | null> {
    return atomicConsumeD1SmsOtp(this.db, id, consumedAt);
  }

  async updateSmsOtp(id: string, patch: Partial<SmsOtp>): Promise<SmsOtp | null> {
    const row = await this.updateOne("own_auth_sms_otps", smsOtpColumns, id, patch, smsOtpReturning);
    return row ? mapSmsOtp(row) : null;
  }

  async createApiKey(apiKey: ApiKey): Promise<ApiKey> {
    return mapApiKey(await this.insertOne(
      "own_auth_api_keys",
      apiKeyColumns,
      apiKey,
      apiKeyReturning
    ));
  }

  async getApiKeyByPrefix(keyPrefix: string): Promise<ApiKey | null> {
    const row = await this.selectOne(
      `${apiKeyReturning} from own_auth_api_keys where key_prefix = ?1`,
      [keyPrefix]
    );
    return row ? mapApiKey(row) : null;
  }

  async updateApiKey(id: string, patch: Partial<ApiKey>): Promise<ApiKey | null> {
    const row = await this.updateOne("own_auth_api_keys", apiKeyColumns, id, patch, apiKeyReturning);
    return row ? mapApiKey(row) : null;
  }

  async listApiKeysByOrganisationId(organisationId: string): Promise<ApiKey[]> {
    const rows = await this.selectMany(
      `${apiKeyReturning} from own_auth_api_keys ` +
      "where organisation_id = ?1 order by created_at desc",
      [organisationId]
    );
    return rows.map(mapApiKey);
  }

  async listApiKeysByUserId(userId: string): Promise<ApiKey[]> {
    const rows = await this.selectMany(
      `${apiKeyReturning} from own_auth_api_keys where user_id = ?1 order by created_at desc`,
      [userId]
    );
    return rows.map(mapApiKey);
  }

  async createOrganisation(organisation: Organisation): Promise<Organisation> {
    return mapOrganisation(await this.insertOne(
      "own_auth_organisations",
      organisationColumns,
      organisation,
      organisationReturning
    ));
  }

  async updateOrganisation(
    id: string,
    patch: Partial<Organisation>
  ): Promise<Organisation | null> {
    const row = await this.updateOne(
      "own_auth_organisations",
      organisationColumns,
      id,
      patch,
      organisationReturning
    );
    return row ? mapOrganisation(row) : null;
  }

  async deleteOrganisation(id: string): Promise<boolean> {
    const results = await this.db.batch<DatabaseRow>([
      this.prepare("delete from own_auth_tokens where organisation_id = ?1", [id]),
      this.prepare("delete from own_auth_organisations where id = ?1 returning id", [id])
    ]);
    return Boolean(results[1]?.results?.[0]);
  }

  async getOrganisationById(id: string): Promise<Organisation | null> {
    const row = await this.selectOne(
      `${organisationReturning} from own_auth_organisations where id = ?1`,
      [id]
    );
    return row ? mapOrganisation(row) : null;
  }

  async getOrganisationBySlug(slug: string): Promise<Organisation | null> {
    const row = await this.selectOne(
      `${organisationReturning} from own_auth_organisations where slug = ?1`,
      [slug]
    );
    return row ? mapOrganisation(row) : null;
  }

  async listOrganisationsByUserId(userId: string): Promise<Organisation[]> {
    const rows = await this.selectMany(
      `${organisationReturning} from own_auth_organisations where id in (` +
      "select organisation_id from own_auth_organisation_members " +
      "where user_id = ?1 and status = 'active') order by created_at desc",
      [userId]
    );
    return rows.map(mapOrganisation);
  }

  async createOrganisationMember(
    member: OrganisationMember<string>
  ): Promise<OrganisationMember<string>> {
    return mapOrganisationMember(await this.insertOne(
      "own_auth_organisation_members",
      organisationMemberColumns,
      member,
      organisationMemberReturning
    ));
  }

  async updateOrganisationMember(
    id: string,
    patch: Partial<OrganisationMember<string>>
  ): Promise<OrganisationMember<string> | null> {
    const row = await this.updateOne(
      "own_auth_organisation_members",
      organisationMemberColumns,
      id,
      patch,
      organisationMemberReturning
    );
    return row ? mapOrganisationMember(row) : null;
  }

  async getOrganisationMember(
    organisationId: string,
    userId: string
  ): Promise<OrganisationMember<string> | null> {
    const row = await this.selectOne(
      `${organisationMemberReturning} from own_auth_organisation_members ` +
      "where organisation_id = ?1 and user_id = ?2",
      [organisationId, userId]
    );
    return row ? mapOrganisationMember(row) : null;
  }

  async getOrganisationMemberById(id: string): Promise<OrganisationMember<string> | null> {
    const row = await this.selectOne(
      `${organisationMemberReturning} from own_auth_organisation_members where id = ?1`,
      [id]
    );
    return row ? mapOrganisationMember(row) : null;
  }

  async listOrganisationMembers(
    organisationId: string
  ): Promise<OrganisationMember<string>[]> {
    const rows = await this.selectMany(
      `${organisationMemberReturning} from own_auth_organisation_members ` +
      "where organisation_id = ?1 order by created_at asc",
      [organisationId]
    );
    return rows.map(mapOrganisationMember);
  }

  async createInvitation(invitation: Invitation<string>): Promise<Invitation<string>> {
    return mapInvitation(await this.insertOne(
      "own_auth_invitations",
      invitationColumns,
      invitation,
      invitationReturning
    ));
  }

  async updateInvitation(
    id: string,
    patch: Partial<Invitation<string>>
  ): Promise<Invitation<string> | null> {
    const row = await this.updateOne(
      "own_auth_invitations",
      invitationColumns,
      id,
      patch,
      invitationReturning
    );
    return row ? mapInvitation(row) : null;
  }

  async getInvitationById(id: string): Promise<Invitation<string> | null> {
    const row = await this.selectOne(
      `${invitationReturning} from own_auth_invitations where id = ?1`,
      [id]
    );
    return row ? mapInvitation(row) : null;
  }

  async getInvitationByTokenId(tokenId: string): Promise<Invitation<string> | null> {
    const row = await this.selectOne(
      `${invitationReturning} from own_auth_invitations where token_id = ?1`,
      [tokenId]
    );
    return row ? mapInvitation(row) : null;
  }

  async listInvitationsByOrganisationId(
    organisationId: string
  ): Promise<Invitation<string>[]> {
    const rows = await this.selectMany(
      `${invitationReturning} from own_auth_invitations ` +
      "where organisation_id = ?1 order by created_at desc",
      [organisationId]
    );
    return rows.map(mapInvitation);
  }

  async getPendingInvitationByOrganisationAndEmail(
    organisationId: string,
    email: string
  ): Promise<Invitation<string> | null> {
    const row = await this.selectOne(
      `${invitationReturning} from own_auth_invitations ` +
      "where organisation_id = ?1 and lower(email) = lower(?2) and status = 'pending' " +
      "order by created_at desc limit 1",
      [organisationId, email]
    );
    return row ? mapInvitation(row) : null;
  }

  async createAuditEvent(event: AuditEvent): Promise<AuditEvent> {
    return mapAuditEvent(await this.insertOne(
      "own_auth_audit_events",
      auditEventColumns,
      event,
      auditEventReturning
    ));
  }

  async listAuditEvents(filter?: AuditEventFilter): Promise<AuditEvent[]> {
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (filter?.userId) {
      params.push(filter.userId);
      clauses.push(`(actor_user_id = ?${params.length} or target_user_id = ?${params.length})`);
    }
    if (filter?.organisationId) {
      params.push(filter.organisationId);
      clauses.push(`organisation_id = ?${params.length}`);
    }
    if (filter?.apiKeyId) {
      params.push(filter.apiKeyId);
      clauses.push(`api_key_id = ?${params.length}`);
    }
    const where = clauses.length > 0 ? ` where ${clauses.join(" and ")}` : "";
    const rows = await this.selectMany(
      `${auditEventReturning} from own_auth_audit_events${where} order by created_at desc`,
      params
    );
    return rows.map(mapAuditEvent);
  }

  async deleteAuditEventsBefore(olderThan: Date): Promise<number> {
    const result = await this.prepare(
      "delete from own_auth_audit_events where created_at < ?1 returning id",
      [olderThan.getTime()]
    ).all<DatabaseRow>();
    return result.results?.length ?? 0;
  }
}

export function createD1AuthStorage(database: D1DatabaseLike): D1AuthStorage {
  return new D1AuthStorage(database);
}
