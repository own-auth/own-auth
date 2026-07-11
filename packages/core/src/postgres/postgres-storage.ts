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
import type { AuthStorage } from "../storage.js";
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
} from "./postgres-mappers.js";
import { expectOne, toPostgresValue } from "./postgres-row.js";
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
} from "./postgres-schema.js";
import type { ColumnMap, PostgresQueryable, Row } from "./postgres-types.js";

export type { PostgresQueryable, PostgresQueryResult } from "./postgres-types.js";

export class PostgresAuthStorage implements AuthStorage {
  constructor(private readonly db: PostgresQueryable) {}

  async createUser(user: User): Promise<User> {
    const row = await this.insertOne("own_auth_users", userColumns, user, userReturning);
    return mapUser(row);
  }

  async updateUser(id: string, patch: Partial<User>): Promise<User | null> {
    const row = await this.updateOne("own_auth_users", userColumns, id, patch, userReturning);
    return row ? mapUser(row) : null;
  }

  async getUserById(id: string): Promise<User | null> {
    const row = await this.selectOne(`${userReturning} from own_auth_users where id = $1`, [id]);
    return row ? mapUser(row) : null;
  }

  async getUserByEmail(email: string): Promise<User | null> {
    const row = await this.selectOne(`${userReturning} from own_auth_users where lower(email) = lower($1)`, [email]);
    return row ? mapUser(row) : null;
  }

  async getUserByPhone(phone: string): Promise<User | null> {
    const row = await this.selectOne(`${userReturning} from own_auth_users where phone = $1`, [phone]);
    return row ? mapUser(row) : null;
  }

  async createAccount(account: Account): Promise<Account> {
    const row = await this.insertOne("own_auth_accounts", accountColumns, account, accountReturning);
    return mapAccount(row);
  }

  async getAccountByProvider(
    provider: string,
    providerAccountId: string
  ): Promise<Account | null> {
    const row = await this.selectOne(
      `${accountReturning} from own_auth_accounts where provider = $1 and provider_account_id = $2`,
      [provider, providerAccountId]
    );
    return row ? mapAccount(row) : null;
  }

  async createSession(session: Session): Promise<Session> {
    const row = await this.insertOne("own_auth_sessions", sessionColumns, session, sessionReturning);
    return mapSession(row);
  }

  async getSessionByTokenHash(tokenHash: string): Promise<Session | null> {
    const row = await this.selectOne(
      `${sessionReturning} from own_auth_sessions where token_hash = $1`,
      [tokenHash]
    );
    return row ? mapSession(row) : null;
  }

  async updateSession(id: string, patch: Partial<Session>): Promise<Session | null> {
    const row = await this.updateOne("own_auth_sessions", sessionColumns, id, patch, sessionReturning);
    return row ? mapSession(row) : null;
  }

  async listSessionsByUserId(userId: string): Promise<Session[]> {
    const rows = await this.selectMany(
      `${sessionReturning} from own_auth_sessions where user_id = $1 order by created_at desc`,
      [userId]
    );
    return rows.map(mapSession);
  }

  async createToken(token: AuthToken): Promise<AuthToken> {
    const row = await this.insertOne("own_auth_tokens", tokenColumns, token, tokenReturning);
    return mapToken(row);
  }

  async getTokenByHash(tokenHash: string, type?: TokenType): Promise<AuthToken | null> {
    const row = type
      ? await this.selectOne(
          `${tokenReturning} from own_auth_tokens where token_hash = $1 and type = $2`,
          [tokenHash, type]
        )
      : await this.selectOne(`${tokenReturning} from own_auth_tokens where token_hash = $1`, [
          tokenHash
        ]);
    return row ? mapToken(row) : null;
  }

  async updateToken(id: string, patch: Partial<AuthToken>): Promise<AuthToken | null> {
    const row = await this.updateOne("own_auth_tokens", tokenColumns, id, patch, tokenReturning);
    return row ? mapToken(row) : null;
  }

  async createSmsOtp(otp: SmsOtp): Promise<SmsOtp> {
    const row = await this.insertOne("own_auth_sms_otps", smsOtpColumns, otp, smsOtpReturning);
    return mapSmsOtp(row);
  }

  async getLatestSmsOtp(phone: string, purpose: string): Promise<SmsOtp | null> {
    const row = await this.selectOne(
      `${smsOtpReturning} from own_auth_sms_otps where phone = $1 and purpose = $2 order by created_at desc limit 1`,
      [phone, purpose]
    );
    return row ? mapSmsOtp(row) : null;
  }

  async updateSmsOtp(id: string, patch: Partial<SmsOtp>): Promise<SmsOtp | null> {
    const row = await this.updateOne("own_auth_sms_otps", smsOtpColumns, id, patch, smsOtpReturning);
    return row ? mapSmsOtp(row) : null;
  }

  async createApiKey(apiKey: ApiKey): Promise<ApiKey> {
    const row = await this.insertOne("own_auth_api_keys", apiKeyColumns, apiKey, apiKeyReturning);
    return mapApiKey(row);
  }

  async getApiKeyByPrefix(keyPrefix: string): Promise<ApiKey | null> {
    const row = await this.selectOne(
      `${apiKeyReturning} from own_auth_api_keys where key_prefix = $1`,
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
      `${apiKeyReturning} from own_auth_api_keys where organisation_id = $1 order by created_at desc`,
      [organisationId]
    );
    return rows.map(mapApiKey);
  }

  async listApiKeysByUserId(userId: string): Promise<ApiKey[]> {
    const rows = await this.selectMany(
      `${apiKeyReturning} from own_auth_api_keys where user_id = $1 order by created_at desc`,
      [userId]
    );
    return rows.map(mapApiKey);
  }

  async createOrganisation(organisation: Organisation): Promise<Organisation> {
    const row = await this.insertOne(
      "own_auth_organisations",
      organisationColumns,
      organisation,
      organisationReturning
    );
    return mapOrganisation(row);
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
    const result = await this.db.query<{ id: string }>(
      `with deleted_tokens as (
        delete from own_auth_tokens where organisation_id = $1
      )
      delete from own_auth_organisations where id = $1 returning id`,
      [id]
    );
    return Boolean(result.rows[0]);
  }

  async getOrganisationById(id: string): Promise<Organisation | null> {
    const row = await this.selectOne(`${organisationReturning} from own_auth_organisations where id = $1`, [id]);
    return row ? mapOrganisation(row) : null;
  }

  async getOrganisationBySlug(slug: string): Promise<Organisation | null> {
    const row = await this.selectOne(`${organisationReturning} from own_auth_organisations where slug = $1`, [slug]);
    return row ? mapOrganisation(row) : null;
  }

  async listOrganisationsByUserId(userId: string): Promise<Organisation[]> {
    const rows = await this.selectMany(
      `${organisationReturning} from own_auth_organisations where id in (select organisation_id from own_auth_organisation_members where user_id = $1 and status = 'active') order by created_at desc`,
      [userId]
    );
    return rows.map(mapOrganisation);
  }

  async createOrganisationMember(
    member: OrganisationMember
  ): Promise<OrganisationMember> {
    const row = await this.insertOne(
      "own_auth_organisation_members",
      organisationMemberColumns,
      member,
      organisationMemberReturning
    );
    return mapOrganisationMember(row);
  }

  async updateOrganisationMember(
    id: string,
    patch: Partial<OrganisationMember>
  ): Promise<OrganisationMember | null> {
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
  ): Promise<OrganisationMember | null> {
    const row = await this.selectOne(
      `${organisationMemberReturning} from own_auth_organisation_members where organisation_id = $1 and user_id = $2`,
      [organisationId, userId]
    );
    return row ? mapOrganisationMember(row) : null;
  }

  async getOrganisationMemberById(id: string): Promise<OrganisationMember | null> {
    const row = await this.selectOne(
      `${organisationMemberReturning} from own_auth_organisation_members where id = $1`,
      [id]
    );
    return row ? mapOrganisationMember(row) : null;
  }

  async listOrganisationMembers(organisationId: string): Promise<OrganisationMember[]> {
    const rows = await this.selectMany(
      `${organisationMemberReturning} from own_auth_organisation_members where organisation_id = $1 order by created_at asc`,
      [organisationId]
    );
    return rows.map(mapOrganisationMember);
  }

  async createInvitation(invitation: Invitation): Promise<Invitation> {
    const row = await this.insertOne("own_auth_invitations", invitationColumns, invitation, invitationReturning);
    return mapInvitation(row);
  }

  async updateInvitation(id: string, patch: Partial<Invitation>): Promise<Invitation | null> {
    const row = await this.updateOne("own_auth_invitations", invitationColumns, id, patch, invitationReturning);
    return row ? mapInvitation(row) : null;
  }

  async getInvitationById(id: string): Promise<Invitation | null> {
    const row = await this.selectOne(`${invitationReturning} from own_auth_invitations where id = $1`, [id]);
    return row ? mapInvitation(row) : null;
  }

  async getInvitationByTokenId(tokenId: string): Promise<Invitation | null> {
    const row = await this.selectOne(
      `${invitationReturning} from own_auth_invitations where token_id = $1`,
      [tokenId]
    );
    return row ? mapInvitation(row) : null;
  }

  async listInvitationsByOrganisationId(organisationId: string): Promise<Invitation[]> {
    const rows = await this.selectMany(
      `${invitationReturning} from own_auth_invitations where organisation_id = $1 order by created_at desc`,
      [organisationId]
    );
    return rows.map(mapInvitation);
  }

  async getPendingInvitationByOrganisationAndEmail(
    organisationId: string,
    email: string
  ): Promise<Invitation | null> {
    const row = await this.selectOne(
      `${invitationReturning} from own_auth_invitations where organisation_id = $1 and lower(email) = lower($2) and status = 'pending' order by created_at desc limit 1`,
      [organisationId, email]
    );
    return row ? mapInvitation(row) : null;
  }

  async createAuditEvent(event: AuditEvent): Promise<AuditEvent> {
    const row = await this.insertOne("own_auth_audit_events", auditEventColumns, event, auditEventReturning);
    return mapAuditEvent(row);
  }

  async listAuditEvents(filter?: {
    userId?: string;
    organisationId?: string;
    apiKeyId?: string;
  }): Promise<AuditEvent[]> {
    const clauses: string[] = [];
    const params: unknown[] = [];

    if (filter?.userId) {
      params.push(filter.userId);
      clauses.push(`(actor_user_id = $${params.length} or target_user_id = $${params.length})`);
    }

    if (filter?.organisationId) {
      params.push(filter.organisationId);
      clauses.push(`organisation_id = $${params.length}`);
    }

    if (filter?.apiKeyId) {
      params.push(filter.apiKeyId);
      clauses.push(`api_key_id = $${params.length}`);
    }

    const where = clauses.length > 0 ? ` where ${clauses.join(" and ")}` : "";
    const rows = await this.selectMany(
      `${auditEventReturning} from own_auth_audit_events${where} order by created_at desc`,
      params
    );
    return rows.map(mapAuditEvent);
  }

  async deleteAuditEventsBefore(olderThan: Date): Promise<number> {
    const result = await this.db.query<{ id: string }>(
      "delete from own_auth_audit_events where created_at < $1 returning id",
      [olderThan]
    );
    return result.rows.length;
  }

  private async insertOne<Entity extends { id: string }>(
    table: string,
    columns: ColumnMap<Entity>,
    entity: Entity,
    returning: string
  ): Promise<Row> {
    const entries = Object.entries(columns).filter(([key]) => entity[key as keyof Entity] !== undefined);
    const columnNames = entries.map(([, column]) => column);
    const params = entries.map(([key]) => toPostgresValue(entity[key as keyof Entity]));
    const placeholders = params.map((_, index) => `$${index + 1}`);
    const result = await this.db.query<Row>(
      `insert into ${table} (${columnNames.join(", ")}) values (${placeholders.join(", ")}) returning ${returning}`,
      params
    );

    return expectOne(result.rows);
  }

  private async updateOne<Entity extends { id: string }>(
    table: string,
    columns: ColumnMap<Entity>,
    id: string,
    patch: Partial<Entity>,
    returning: string
  ): Promise<Row | null> {
    const entries = Object.entries(columns).filter(
      ([key]) => key !== "id" && patch[key as keyof Entity] !== undefined
    );

    if (entries.length === 0) {
      return this.selectOne(`${returning} from ${table} where id = $1`, [id]);
    }

    const params = entries.map(([key]) => toPostgresValue(patch[key as keyof Entity]));
    params.push(id);
    const assignments = entries.map(([, column], index) => `${column} = $${index + 1}`);
    const result = await this.db.query<Row>(
      `update ${table} set ${assignments.join(", ")} where id = $${params.length} returning ${returning}`,
      params
    );

    return result.rows[0] ?? null;
  }

  private async selectOne(sql: string, params: readonly unknown[]): Promise<Row | null> {
    const result = await this.db.query<Row>(`select ${sql}`, params);
    return result.rows[0] ?? null;
  }

  private async selectMany(sql: string, params: readonly unknown[]): Promise<Row[]> {
    const result = await this.db.query<Row>(`select ${sql}`, params);
    return result.rows;
  }
}

export function createPostgresAuthStorage(db: PostgresQueryable): PostgresAuthStorage {
  return new PostgresAuthStorage(db);
}
