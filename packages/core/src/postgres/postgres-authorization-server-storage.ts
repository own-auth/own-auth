import {
  mapAuthorizationAccessToken,
  mapAuthorizationCode,
  mapAuthorizationCodeDpopBinding,
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
  AuthorizationCodeDpopBinding,
  AuthorizationServerStorage,
  ConsumeDpopProofInput,
  DpopStorage,
  FindAuthorizationCodeDpopBindingInput,
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
import { PostgresDeviceAuthorizationStorage } from "./postgres-device-authorization-storage.js";

export class PostgresAuthorizationServerStorage
  extends PostgresAuthorizationClientStorage
  implements AuthorizationServerStorage, DpopStorage {
  readonly dpopStorage = this;
  readonly deviceAuthorizationStorage = new PostgresDeviceAuthorizationStorage(this.db);
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
    resourceIdentifier: string | null,
    consumedAt: Date
  ): Promise<AuthorizationCode | null> {
    return this.consumeAuthorizationCodeWithDpop(
      codeHash,
      authorizationClientId,
      redirectUri,
      codeChallenge,
      resourceIdentifier,
      null,
      consumedAt
    );
  }

  async consumeDpopAuthorizationCode(
    codeHash: string,
    authorizationClientId: string,
    redirectUri: string,
    codeChallenge: string,
    resourceIdentifier: string | null,
    dpopJkt: string | null,
    consumedAt: Date
  ): Promise<AuthorizationCode | null> {
    return this.consumeAuthorizationCodeWithDpop(
      codeHash,
      authorizationClientId,
      redirectUri,
      codeChallenge,
      resourceIdentifier,
      dpopJkt,
      consumedAt
    );
  }

  private async consumeAuthorizationCodeWithDpop(
    codeHash: string,
    authorizationClientId: string,
    redirectUri: string,
    codeChallenge: string,
    resourceIdentifier: string | null,
    dpopJkt: string | null,
    consumedAt: Date
  ): Promise<AuthorizationCode | null> {
    const result = await this.db.query<Row>(
      `update own_auth_authorization_codes
       set consumed_at = $7
       where code_hash = $1 and authorization_client_id = $2
         and redirect_uri = $3 and code_challenge = $4
         and (
           $5::text is null or protected_resource_id = (
             select id from own_auth_protected_resources
             where identifier = $5 and status = 'active' and revoked_at is null
           )
         )
         and dpop_jkt is not distinct from $6
         and consumed_at is null and expires_at > $7
       returning ${authorizationCodeReturning}`,
      [
        codeHash,
        authorizationClientId,
        redirectUri,
        codeChallenge,
        resourceIdentifier,
        dpopJkt,
        consumedAt
      ]
    );
    return result.rows[0] ? mapAuthorizationCode(result.rows[0]) : null;
  }

  async findAuthorizationCodeDpopBinding(
    input: FindAuthorizationCodeDpopBindingInput
  ): Promise<AuthorizationCodeDpopBinding | null> {
    const row = await this.selectOne(
      `code.dpop_jkt,
       (client.dpop_bound_access_tokens or coalesce(resource.require_dpop, false)) as dpop_required
       from own_auth_authorization_codes code
       join own_auth_authorization_clients client
         on client.id = code.authorization_client_id
       left join own_auth_protected_resources resource
         on resource.id = code.protected_resource_id
       where code.code_hash = $1 and code.authorization_client_id = $2
         and code.redirect_uri = $3 and code.code_challenge = $4
         and (
           $5::text is null or code.protected_resource_id = (
             select id from own_auth_protected_resources
             where identifier = $5 and status = 'active' and revoked_at is null
           )
         )
         and code.consumed_at is null and code.expires_at > $6`,
      [
        input.codeHash,
        input.authorizationClientId,
        input.redirectUri,
        input.codeChallenge,
        input.resourceIdentifier,
        input.now
      ]
    );
    return row ? mapAuthorizationCodeDpopBinding(row) : null;
  }

  async consumeDpopProof(input: ConsumeDpopProofInput): Promise<boolean> {
    const result = await this.db.query<Row>(
      `insert into own_auth_dpop_proofs (proof_hash, consumed_at, expires_at)
       values ($1,$2,$3) on conflict (proof_hash) do nothing returning proof_hash`,
      [input.proofHash, input.consumedAt, input.expiresAt]
    );
    return result.rows.length === 1;
  }

  async cleanupDpopProofs(expiredBefore: Date): Promise<number> {
    const result = await this.db.query<Row>(
      "delete from own_auth_dpop_proofs where expires_at <= $1 returning proof_hash",
      [expiredBefore]
    );
    return result.rows.length;
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
            user_id, protected_resource_id, scopes, dpop_jkt, expires_at,
            revoked_at, created_at)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       )
       insert into own_auth_authorization_refresh_tokens
         (id, token_hash, prefix, grant_id, authorization_client_id, user_id,
          protected_resource_id, scopes, generation, replaced_by_token_id, dpop_jkt,
          expires_at, consumed_at, revoked_at, created_at)
       values ($13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)`,
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
