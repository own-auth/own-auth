import {
  mapAuthorizationAccessToken,
  mapAuthorizationCode,
  mapAuthorizationRefreshToken,
  mapOidcSubject
} from "../authorization-server-database-mappers.js";
import {
  authorizationAccessTokenColumns,
  authorizationAccessTokenReturning,
  authorizationCodeColumns,
  authorizationCodeReturning,
  authorizationRefreshTokenColumns,
  authorizationRefreshTokenReturning,
  oidcSubjectReturning
} from "../authorization-server-database-schema.js";
import type {
  AuthorizationServerStorage,
  RotateAuthorizationRefreshTokenInput,
  RotateAuthorizationRefreshTokenResult
} from "../authorization-server-storage.js";
import type {
  AuthorizationAccessToken,
  AuthorizationCode,
  AuthorizationRefreshToken,
  OidcSubject
} from "../authorization-server-types.js";
import {
  authorizationAccessTokenValues,
  authorizationRefreshTokenValues
} from "../authorization-server-token-values.js";
import { expectDatabaseValue } from "../database-row.js";
import type { DatabaseRow } from "../database-types.js";
import { D1AuthorizationClientStorage } from "./d1-authorization-client-storage.js";
import type { D1DatabaseLike } from "./d1-types.js";

export class D1AuthorizationServerStorage
  extends D1AuthorizationClientStorage
  implements AuthorizationServerStorage {
  constructor(db: D1DatabaseLike) {
    super(db);
  }

  async createAuthorizationCode(code: AuthorizationCode): Promise<AuthorizationCode> {
    return mapAuthorizationCode(await this.insertOne(
      "own_auth_authorization_codes",
      authorizationCodeColumns,
      code,
      authorizationCodeReturning
    ));
  }

  async consumeAuthorizationCode(
    codeHash: string,
    authorizationClientId: string,
    redirectUri: string,
    codeChallenge: string,
    consumedAt: Date
  ): Promise<AuthorizationCode | null> {
    const row = await this.prepare(
      `update own_auth_authorization_codes set consumed_at = ?5
       where code_hash = ?1 and authorization_client_id = ?2
         and redirect_uri = ?3 and code_challenge = ?4
         and consumed_at is null and expires_at > ?5
       returning ${authorizationCodeReturning}`,
      [codeHash, authorizationClientId, redirectUri, codeChallenge, consumedAt]
    ).first<DatabaseRow>();
    return row ? mapAuthorizationCode(row) : null;
  }

  async createAuthorizationTokens(
    accessToken: AuthorizationAccessToken,
    refreshToken: AuthorizationRefreshToken | null
  ): Promise<void> {
    if (!refreshToken) {
      await this.insertOne(
        "own_auth_authorization_access_tokens",
        authorizationAccessTokenColumns,
        accessToken,
        authorizationAccessTokenReturning
      );
      return;
    }
    await this.db.batch([
      this.insertStatement(
        "own_auth_authorization_access_tokens",
        authorizationAccessTokenColumns,
        accessToken,
        authorizationAccessTokenReturning
      ),
      this.insertStatement(
        "own_auth_authorization_refresh_tokens",
        authorizationRefreshTokenColumns,
        refreshToken,
        authorizationRefreshTokenReturning
      )
    ]);
  }

  async getAuthorizationAccessTokenByHash(
    tokenHash: string
  ): Promise<AuthorizationAccessToken | null> {
    const row = await this.selectOne(
      `${authorizationAccessTokenReturning}
       from own_auth_authorization_access_tokens where token_hash = ?1`,
      [tokenHash]
    );
    return row ? mapAuthorizationAccessToken(row) : null;
  }

  async getAuthorizationRefreshTokenByHash(
    tokenHash: string
  ): Promise<AuthorizationRefreshToken | null> {
    const row = await this.selectOne(
      `${authorizationRefreshTokenReturning}
       from own_auth_authorization_refresh_tokens where token_hash = ?1`,
      [tokenHash]
    );
    return row ? mapAuthorizationRefreshToken(row) : null;
  }

  async rotateAuthorizationRefreshToken(
    input: RotateAuthorizationRefreshTokenInput
  ): Promise<RotateAuthorizationRefreshTokenResult> {
    const refresh = input.replacementRefreshToken;
    const access = input.accessToken;
    const rotated = await this.db.batch<DatabaseRow>([
      this.prepare(
        `update own_auth_authorization_refresh_tokens
         set consumed_at = ?3, replaced_by_token_id = ?4
         where token_hash = ?1 and authorization_client_id = ?2
           and revoked_at is null and expires_at > ?3
           and consumed_at is null and replaced_by_token_id is null
           and exists (
             select 1 from own_auth_authorization_grants grant_record
             where grant_record.id = own_auth_authorization_refresh_tokens.grant_id
               and grant_record.revoked_at is null
           )
         returning grant_id`,
        [
          input.tokenHash,
          input.authorizationClientId,
          input.rotatedAt,
          refresh.id
        ]
      ),
      this.prepare(
        `insert into own_auth_authorization_refresh_tokens
          (id, token_hash, prefix, grant_id, authorization_client_id, user_id,
           scopes, generation, replaced_by_token_id, expires_at, consumed_at,
           revoked_at, created_at)
         select ?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16
         from own_auth_authorization_refresh_tokens current_token
         where current_token.token_hash = ?1
           and current_token.authorization_client_id = ?2
           and current_token.consumed_at = ?3
           and current_token.replaced_by_token_id = ?4`,
        [
          input.tokenHash,
          input.authorizationClientId,
          input.rotatedAt,
          ...authorizationRefreshTokenValues(refresh)
        ]
      ),
      this.prepare(
        `insert into own_auth_authorization_access_tokens
          (id, token_hash, prefix, grant_id, authorization_client_id,
           user_id, scopes, expires_at, revoked_at, created_at)
         select ?4,?5,?6,?7,?8,?9,?10,?11,?12,?13
         from own_auth_authorization_refresh_tokens current_token
         where current_token.token_hash = ?1
           and current_token.authorization_client_id = ?2
           and current_token.consumed_at = ?3
           and current_token.replaced_by_token_id = ?14`,
        [
          input.tokenHash,
          input.authorizationClientId,
          input.rotatedAt,
          ...authorizationAccessTokenValues(access),
          refresh.id
        ]
      )
    ]);
    if (rotated[0]?.results?.[0]) return "rotated";

    const reused = await this.db.batch<DatabaseRow>([
      this.prepare(
        `update own_auth_authorization_grants
         set revoked_at = ?3, updated_at = ?3
         where id in (
           select grant_id from own_auth_authorization_refresh_tokens
           where token_hash = ?1 and authorization_client_id = ?2
             and revoked_at is null and expires_at > ?3
             and (consumed_at is not null or replaced_by_token_id is not null)
         ) and revoked_at is null
         returning id`,
        [input.tokenHash, input.authorizationClientId, input.rotatedAt]
      ),
      this.revokeTokenFamilyStatement(
        "own_auth_authorization_access_tokens",
        input
      ),
      this.revokeTokenFamilyStatement(
        "own_auth_authorization_refresh_tokens",
        input
      )
    ]);
    return reused[0]?.results?.[0] ? "reused" : "invalid";
  }

  async revokeAuthorizationToken(
    tokenHash: string,
    authorizationClientId: string,
    revokedAt: Date
  ): Promise<void> {
    const refreshGrant = `select grant_id from own_auth_authorization_refresh_tokens
      where token_hash = ?1 and authorization_client_id = ?2`;
    await this.db.batch([
      this.prepare(
        `update own_auth_authorization_grants
         set revoked_at = ?3, updated_at = ?3
         where id in (${refreshGrant}) and revoked_at is null`,
        [tokenHash, authorizationClientId, revokedAt]
      ),
      this.prepare(
        `update own_auth_authorization_refresh_tokens set revoked_at = ?3
         where grant_id in (${refreshGrant}) and revoked_at is null`,
        [tokenHash, authorizationClientId, revokedAt]
      ),
      this.prepare(
        `update own_auth_authorization_access_tokens set revoked_at = ?3
         where grant_id in (${refreshGrant}) and revoked_at is null`,
        [tokenHash, authorizationClientId, revokedAt]
      ),
      this.prepare(
        `update own_auth_authorization_access_tokens set revoked_at = ?3
         where token_hash = ?1 and authorization_client_id = ?2
           and revoked_at is null`,
        [tokenHash, authorizationClientId, revokedAt]
      )
    ]);
  }

  async getOidcSubjectByUserId(userId: string): Promise<OidcSubject | null> {
    const row = await this.selectOne(
      `${oidcSubjectReturning} from own_auth_oidc_subjects where user_id = ?1`,
      [userId]
    );
    return row ? mapOidcSubject(row) : null;
  }

  async createOidcSubject(subject: OidcSubject): Promise<OidcSubject> {
    const row = await this.prepare(
      `insert into own_auth_oidc_subjects (id, user_id, subject, created_at)
       values (?1,?2,?3,?4)
       on conflict (user_id) do update set user_id = excluded.user_id
       returning ${oidcSubjectReturning}`,
      [subject.id, subject.userId, subject.subject, subject.createdAt]
    ).first<DatabaseRow>();
    return mapOidcSubject(
      expectDatabaseValue(row, "D1 OIDC subject creation")
    );
  }

  private revokeTokenFamilyStatement(
    table: "own_auth_authorization_access_tokens" | "own_auth_authorization_refresh_tokens",
    input: RotateAuthorizationRefreshTokenInput
  ) {
    return this.prepare(
      `update ${table} set revoked_at = ?3
       where grant_id in (
         select grant_id from own_auth_authorization_refresh_tokens
         where token_hash = ?1 and authorization_client_id = ?2
           and expires_at > ?3
           and (consumed_at is not null or replaced_by_token_id is not null)
       ) and revoked_at is null`,
      [input.tokenHash, input.authorizationClientId, input.rotatedAt]
    );
  }
}
