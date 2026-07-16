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
  authorizationRefreshTokenReturning,
  oidcSubjectReturning
} from "../authorization-server-database-schema.js";
import type {
  AuthorizationAccessToken,
  AuthorizationCode,
  AuthorizationRefreshToken,
  OidcSubject
} from "../authorization-server-types.js";
import type {
  AuthorizationServerStorage,
  RotateAuthorizationRefreshTokenInput,
  RotateAuthorizationRefreshTokenResult
} from "../authorization-server-storage.js";
import {
  authorizationAccessTokenValues,
  authorizationRefreshTokenValues
} from "../authorization-server-token-values.js";
import { PostgresAuthorizationClientStorage } from "./postgres-authorization-client-storage.js";
import {
  rotatePostgresAuthorizationRefreshToken
} from "./postgres-authorization-refresh.js";
import { expectOne } from "./postgres-row.js";
import type { Row } from "./postgres-types.js";

export class PostgresAuthorizationServerStorage
  extends PostgresAuthorizationClientStorage
  implements AuthorizationServerStorage {
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
    const result = await this.db.query<Row>(
      `update own_auth_authorization_codes
       set consumed_at = $5
       where code_hash = $1 and authorization_client_id = $2
         and redirect_uri = $3 and code_challenge = $4
         and consumed_at is null and expires_at > $5
       returning ${authorizationCodeReturning}`,
      [codeHash, authorizationClientId, redirectUri, codeChallenge, consumedAt]
    );
    return result.rows[0] ? mapAuthorizationCode(result.rows[0]) : null;
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
    await this.db.query(
      `with access_token as (
         insert into own_auth_authorization_access_tokens
           (id, token_hash, prefix, grant_id, authorization_client_id,
            user_id, scopes, expires_at, revoked_at, created_at)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       )
       insert into own_auth_authorization_refresh_tokens
         (id, token_hash, prefix, grant_id, authorization_client_id, user_id,
          scopes, generation, replaced_by_token_id, expires_at, consumed_at,
          revoked_at, created_at)
       values ($11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,
      [
        ...authorizationAccessTokenValues(accessToken),
        ...authorizationRefreshTokenValues(refreshToken)
      ]
    );
  }

  async getAuthorizationAccessTokenByHash(
    tokenHash: string
  ): Promise<AuthorizationAccessToken | null> {
    const row = await this.selectOne(
      `${authorizationAccessTokenReturning}
       from own_auth_authorization_access_tokens where token_hash = $1`,
      [tokenHash]
    );
    return row ? mapAuthorizationAccessToken(row) : null;
  }

  async getAuthorizationRefreshTokenByHash(
    tokenHash: string
  ): Promise<AuthorizationRefreshToken | null> {
    const row = await this.selectOne(
      `${authorizationRefreshTokenReturning}
       from own_auth_authorization_refresh_tokens where token_hash = $1`,
      [tokenHash]
    );
    return row ? mapAuthorizationRefreshToken(row) : null;
  }

  async rotateAuthorizationRefreshToken(
    input: RotateAuthorizationRefreshTokenInput
  ): Promise<RotateAuthorizationRefreshTokenResult> {
    return rotatePostgresAuthorizationRefreshToken(this.db, input);
  }

  async revokeAuthorizationToken(
    tokenHash: string,
    authorizationClientId: string,
    revokedAt: Date
  ): Promise<void> {
    await this.db.query(
      `with refresh_grant as (
         select grant_id from own_auth_authorization_refresh_tokens
         where token_hash = $1 and authorization_client_id = $2
       ), revoked_grant as (
         update own_auth_authorization_grants
         set revoked_at = $3, updated_at = $3
         where id in (select grant_id from refresh_grant) and revoked_at is null
         returning id
       ), revoked_refresh as (
         update own_auth_authorization_refresh_tokens set revoked_at = $3
         where grant_id in (select id from revoked_grant) and revoked_at is null
       ), revoked_family_access as (
         update own_auth_authorization_access_tokens set revoked_at = $3
         where grant_id in (select id from revoked_grant) and revoked_at is null
       )
       update own_auth_authorization_access_tokens set revoked_at = $3
       where token_hash = $1 and authorization_client_id = $2 and revoked_at is null`,
      [tokenHash, authorizationClientId, revokedAt]
    );
  }

  async getOidcSubjectByUserId(userId: string): Promise<OidcSubject | null> {
    const row = await this.selectOne(
      `${oidcSubjectReturning} from own_auth_oidc_subjects where user_id = $1`,
      [userId]
    );
    return row ? mapOidcSubject(row) : null;
  }

  async createOidcSubject(subject: OidcSubject): Promise<OidcSubject> {
    const result = await this.db.query<Row>(
      `insert into own_auth_oidc_subjects (id, user_id, subject, created_at)
       values ($1,$2,$3,$4)
       on conflict (user_id) do update set user_id = excluded.user_id
       returning ${oidcSubjectReturning}`,
      [subject.id, subject.userId, subject.subject, subject.createdAt]
    );
    return mapOidcSubject(expectOne(result.rows));
  }
}
