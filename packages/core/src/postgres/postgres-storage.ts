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
import type { AuditEventFilter, AuthStorage, ListUsersFilter } from "../storage.js";
import {
  buildAuditEventListQuery,
  buildUserListQuery
} from "../database-administration-queries.js";
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
import { databaseColumnEntries } from "../database-types.js";
import {
  atomicConsumeSmsOtp,
  atomicConsumeToken,
  atomicIncrementSmsOtpAttempts
} from "./postgres-atomic-operations.js";
import { withPostgresIdentityErrors } from "./postgres-errors.js";
import { PostgresIdentityStorage } from "./postgres-identity-storage.js";
import { PostgresAuthorizationServerStorage } from "./postgres-authorization-server-storage.js";
import type { PostgresQueryable } from "./postgres-types.js";
import { PostgresWebhookStorage } from "./postgres-webhook-storage.js";

export class PostgresAuthStorage extends PostgresIdentityStorage implements AuthStorage {
  readonly authorizationServerStorage = new PostgresAuthorizationServerStorage(this.db);
  readonly webhookStorage = new PostgresWebhookStorage(this.db);

  async createUser(user: User): Promise<User> {
    return withPostgresIdentityErrors(async () =>
      mapUser(await this.insertOne("own_auth_users", userColumns, user, userReturning))
    );
  }

  async updateUser(id: string, patch: Partial<User>): Promise<User | null> {
    return withPostgresIdentityErrors(async () => {
      const row = await this.updateOne("own_auth_users", userColumns, id, patch, userReturning);
      return row ? mapUser(row) : null;
    });
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

  async listUsers(filter?: ListUsersFilter): Promise<User[]> {
    const query = buildUserListQuery(userReturning, filter, "postgres");
    const rows = await this.selectMany(query.sql, query.params);
    return rows.map(mapUser);
  }

  async createAccount(account: Account): Promise<Account> {
    return withPostgresIdentityErrors(async () =>
      mapAccount(await this.insertOne(
        "own_auth_accounts",
        accountColumns,
        account,
        accountReturning
      ))
    );
  }

  async createUserAndAccount(user: User, account: Account): Promise<Account> {
    return withPostgresIdentityErrors(async () => {
      const userEntries = databaseColumnEntries(userColumns, user);
      const accountEntries = databaseColumnEntries(accountColumns, account);
      const values = [
        ...userEntries.map(([key]) => user[key]),
        ...accountEntries.map(([key]) => account[key])
      ];
      const userPlaceholders = userEntries.map((_, index) => `$${index + 1}`);
      const accountOffset = userEntries.length;
      const accountPlaceholders = accountEntries.map(
        (_, index) => `$${accountOffset + index + 1}`
      );
      const result = await this.db.query<Record<string, unknown>>(
        `with inserted_user as (
           insert into own_auth_users (${userEntries.map(([, column]) => column).join(", ")})
           values (${userPlaceholders.join(", ")}) returning id
         )
         insert into own_auth_accounts (${accountEntries.map(([, column]) => column).join(", ")})
         select ${accountPlaceholders.join(", ")} from inserted_user
         returning ${accountReturning}`,
        values
      );
      const row = result.rows[0];
      if (!row) {
        throw new Error("Postgres identity creation returned no account");
      }
      return mapAccount(row);
    });
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

  async listAccountsByUserId(userId: string): Promise<Account[]> {
    const rows = await this.selectMany(
      `${accountReturning} from own_auth_accounts where user_id = $1 order by created_at asc`,
      [userId]
    );
    return rows.map(mapAccount);
  }

  async deleteAccount(id: string): Promise<boolean> {
    const result = await this.db.query<{ id: string }>(
      "delete from own_auth_accounts where id = $1 returning id",
      [id]
    );
    return result.rows.length > 0;
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

  async consumeToken(
    tokenHash: string,
    type: TokenType,
    consumedAt: Date
  ): Promise<AuthToken | null> {
    return atomicConsumeToken(this.db, tokenHash, type, consumedAt);
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

  async incrementSmsOtpAttempts(id: string, attemptedAt: Date): Promise<SmsOtp | null> {
    return atomicIncrementSmsOtpAttempts(this.db, id, attemptedAt);
  }

  async consumeSmsOtp(id: string, consumedAt: Date): Promise<SmsOtp | null> {
    return atomicConsumeSmsOtp(this.db, id, consumedAt);
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
    member: OrganisationMember<string>
  ): Promise<OrganisationMember<string>> {
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
      `${organisationMemberReturning} from own_auth_organisation_members where organisation_id = $1 and user_id = $2`,
      [organisationId, userId]
    );
    return row ? mapOrganisationMember(row) : null;
  }

  async getOrganisationMemberById(id: string): Promise<OrganisationMember<string> | null> {
    const row = await this.selectOne(
      `${organisationMemberReturning} from own_auth_organisation_members where id = $1`,
      [id]
    );
    return row ? mapOrganisationMember(row) : null;
  }

  async listOrganisationMembers(
    organisationId: string
  ): Promise<OrganisationMember<string>[]> {
    const rows = await this.selectMany(
      `${organisationMemberReturning} from own_auth_organisation_members where organisation_id = $1 order by created_at asc`,
      [organisationId]
    );
    return rows.map(mapOrganisationMember);
  }

  async createInvitation(invitation: Invitation<string>): Promise<Invitation<string>> {
    const row = await this.insertOne("own_auth_invitations", invitationColumns, invitation, invitationReturning);
    return mapInvitation(row);
  }

  async updateInvitation(
    id: string,
    patch: Partial<Invitation<string>>
  ): Promise<Invitation<string> | null> {
    const row = await this.updateOne("own_auth_invitations", invitationColumns, id, patch, invitationReturning);
    return row ? mapInvitation(row) : null;
  }

  async getInvitationById(id: string): Promise<Invitation<string> | null> {
    const row = await this.selectOne(`${invitationReturning} from own_auth_invitations where id = $1`, [id]);
    return row ? mapInvitation(row) : null;
  }

  async getInvitationByTokenId(tokenId: string): Promise<Invitation<string> | null> {
    const row = await this.selectOne(
      `${invitationReturning} from own_auth_invitations where token_id = $1`,
      [tokenId]
    );
    return row ? mapInvitation(row) : null;
  }

  async listInvitationsByOrganisationId(
    organisationId: string
  ): Promise<Invitation<string>[]> {
    const rows = await this.selectMany(
      `${invitationReturning} from own_auth_invitations where organisation_id = $1 order by created_at desc`,
      [organisationId]
    );
    return rows.map(mapInvitation);
  }

  async getPendingInvitationByOrganisationAndEmail(
    organisationId: string,
    email: string
  ): Promise<Invitation<string> | null> {
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

  async listAuditEvents(filter?: AuditEventFilter): Promise<AuditEvent[]> {
    const query = buildAuditEventListQuery(auditEventReturning, filter, "postgres");
    const rows = await this.selectMany(query.sql, query.params);
    return rows.map(mapAuditEvent);
  }

  async deleteAuditEventsBefore(olderThan: Date): Promise<number> {
    const result = await this.db.query<{ id: string }>(
      "delete from own_auth_audit_events where created_at < $1 returning id",
      [olderThan]
    );
    return result.rows.length;
  }

}

export function createPostgresAuthStorage(db: PostgresQueryable): PostgresAuthStorage {
  return new PostgresAuthStorage(db);
}
