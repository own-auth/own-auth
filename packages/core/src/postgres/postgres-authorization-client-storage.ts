import {
  mapAuthorizationClient,
  mapAuthorizationClientSecret,
  mapAuthorizationGrant,
  mapAuthorizationInteraction
} from "../authorization-server-database-mappers.js";
import {
  authorizationClientColumns,
  authorizationClientReturning,
  authorizationClientSecretReturning,
  authorizationGrantReturning,
  authorizationInteractionColumns,
  authorizationInteractionReturning
} from "../authorization-server-database-schema.js";
import type {
  AuthorizationClient,
  AuthorizationClientSecret,
  AuthorizationGrant,
  AuthorizationInteraction,
  AuthorizationInteractionStatus
} from "../authorization-server-types.js";
import { expectOne } from "./postgres-row.js";
import { PostgresStorageBase } from "./postgres-storage-base.js";
import type { PostgresQueryable, Row } from "./postgres-types.js";

export class PostgresAuthorizationClientStorage extends PostgresStorageBase {
  constructor(db: PostgresQueryable) {
    super(db);
  }

  async createAuthorizationClient(
    client: AuthorizationClient,
    secret: AuthorizationClientSecret | null
  ): Promise<AuthorizationClient> {
    if (!secret) {
      return mapAuthorizationClient(await this.insertOne(
        "own_auth_authorization_clients",
        authorizationClientColumns,
        client,
        authorizationClientReturning
      ));
    }
    const result = await this.db.query<Row>(
      `with inserted_client as (
         insert into own_auth_authorization_clients
           (id, client_id, name, client_type, application_type,
            token_endpoint_auth_method, redirect_uris, allowed_scopes, status,
            created_at, updated_at, revoked_at)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
         returning ${authorizationClientReturning}
       ), inserted_secret as (
         insert into own_auth_authorization_client_secrets
           (id, authorization_client_id, prefix, secret_hash, created_at, expires_at, revoked_at)
         values ($13,$14,$15,$16,$17,$18,$19)
       )
       select ${authorizationClientReturning} from inserted_client`,
      [
        client.id,
        client.clientId,
        client.name,
        client.clientType,
        client.applicationType,
        client.tokenEndpointAuthMethod,
        client.redirectUris,
        client.allowedScopes,
        client.status,
        client.createdAt,
        client.updatedAt,
        client.revokedAt,
        secret.id,
        secret.authorizationClientId,
        secret.prefix,
        secret.secretHash,
        secret.createdAt,
        secret.expiresAt,
        secret.revokedAt
      ]
    );
    return mapAuthorizationClient(expectOne(result.rows));
  }

  async getAuthorizationClientByClientId(
    clientId: string
  ): Promise<AuthorizationClient | null> {
    const row = await this.selectOne(
      `${authorizationClientReturning} from own_auth_authorization_clients where client_id = $1`,
      [clientId]
    );
    return row ? mapAuthorizationClient(row) : null;
  }

  async getAuthorizationClientById(id: string): Promise<AuthorizationClient | null> {
    const row = await this.selectOne(
      `${authorizationClientReturning} from own_auth_authorization_clients where id = $1`,
      [id]
    );
    return row ? mapAuthorizationClient(row) : null;
  }

  async listAuthorizationClients(): Promise<AuthorizationClient[]> {
    return (await this.selectMany(
      `${authorizationClientReturning} from own_auth_authorization_clients ` +
      "order by created_at desc, id desc",
      []
    )).map(mapAuthorizationClient);
  }

  async updateAuthorizationClient(
    id: string,
    patch: Partial<AuthorizationClient>
  ): Promise<AuthorizationClient | null> {
    const row = await this.updateOne(
      "own_auth_authorization_clients",
      authorizationClientColumns,
      id,
      patch,
      authorizationClientReturning
    );
    return row ? mapAuthorizationClient(row) : null;
  }

  async replaceAuthorizationClientSecret(
    authorizationClientId: string,
    secret: AuthorizationClientSecret,
    revokedAt: Date
  ): Promise<AuthorizationClientSecret> {
    const result = await this.db.query<Row>(
      `with revoked as (
         update own_auth_authorization_client_secrets
         set revoked_at = $2
         where authorization_client_id = $1 and revoked_at is null
       )
       insert into own_auth_authorization_client_secrets
         (id, authorization_client_id, prefix, secret_hash, created_at, expires_at, revoked_at)
       values ($3,$1,$4,$5,$6,$7,null)
       returning ${authorizationClientSecretReturning}`,
      [
        authorizationClientId,
        revokedAt,
        secret.id,
        secret.prefix,
        secret.secretHash,
        secret.createdAt,
        secret.expiresAt
      ]
    );
    return mapAuthorizationClientSecret(expectOne(result.rows));
  }

  async getAuthorizationClientSecretByPrefix(
    authorizationClientId: string,
    prefix: string
  ): Promise<AuthorizationClientSecret | null> {
    const row = await this.selectOne(
      `${authorizationClientSecretReturning}
       from own_auth_authorization_client_secrets
       where authorization_client_id = $1 and prefix = $2
         and revoked_at is null and (expires_at is null or expires_at > now())`,
      [authorizationClientId, prefix]
    );
    return row ? mapAuthorizationClientSecret(row) : null;
  }

  async revokeAuthorizationClient(
    id: string,
    revokedAt: Date
  ): Promise<AuthorizationClient | null> {
    const result = await this.db.query<Row>(
      `with revoked_client as (
         update own_auth_authorization_clients
         set status = 'revoked', revoked_at = $2, updated_at = $2
         where id = $1
         returning ${authorizationClientReturning}
       ), revoked_secrets as (
         update own_auth_authorization_client_secrets
         set revoked_at = $2
         where authorization_client_id = $1 and revoked_at is null
       ), revoked_grants as (
         update own_auth_authorization_grants
         set revoked_at = $2, updated_at = $2
         where authorization_client_id = $1 and revoked_at is null
         returning id
       ), revoked_access as (
         update own_auth_authorization_access_tokens
         set revoked_at = $2
         where authorization_client_id = $1 and revoked_at is null
       ), revoked_refresh as (
         update own_auth_authorization_refresh_tokens
         set revoked_at = $2
         where authorization_client_id = $1 and revoked_at is null
       )
       select ${authorizationClientReturning} from revoked_client`,
      [id, revokedAt]
    );
    const row = result.rows[0];
    return row ? mapAuthorizationClient(row) : null;
  }

  async createAuthorizationInteraction(
    interaction: AuthorizationInteraction
  ): Promise<AuthorizationInteraction> {
    return mapAuthorizationInteraction(await this.insertOne(
      "own_auth_authorization_interactions",
      authorizationInteractionColumns,
      interaction,
      authorizationInteractionReturning
    ));
  }

  async getAuthorizationInteractionByHash(
    interactionHash: string,
    now: Date
  ): Promise<AuthorizationInteraction | null> {
    const row = await this.selectOne(
      `${authorizationInteractionReturning}
       from own_auth_authorization_interactions
       where interaction_hash = $1 and status = 'pending'
         and consumed_at is null and expires_at > $2`,
      [interactionHash, now]
    );
    return row ? mapAuthorizationInteraction(row) : null;
  }

  async bindAuthorizationInteractionToUser(
    interactionHash: string,
    userId: string,
    now: Date
  ): Promise<AuthorizationInteraction | null> {
    const result = await this.db.query<Row>(
      `update own_auth_authorization_interactions
       set user_id = $2
       where interaction_hash = $1 and status = 'pending'
         and consumed_at is null and expires_at > $3
         and (user_id is null or user_id = $2)
       returning ${authorizationInteractionReturning}`,
      [interactionHash, userId, now]
    );
    return result.rows[0] ? mapAuthorizationInteraction(result.rows[0]) : null;
  }

  async consumeAuthorizationInteraction(
    interactionHash: string,
    userId: string,
    status: Exclude<AuthorizationInteractionStatus, "pending">,
    consumedAt: Date
  ): Promise<AuthorizationInteraction | null> {
    const result = await this.db.query<Row>(
      `update own_auth_authorization_interactions
       set status = $3, consumed_at = $4
       where interaction_hash = $1 and user_id = $2 and status = 'pending'
         and consumed_at is null and expires_at > $4
       returning ${authorizationInteractionReturning}`,
      [interactionHash, userId, status, consumedAt]
    );
    return result.rows[0] ? mapAuthorizationInteraction(result.rows[0]) : null;
  }

  async getAuthorizationGrant(
    authorizationClientId: string,
    userId: string
  ): Promise<AuthorizationGrant | null> {
    const row = await this.selectOne(
      `${authorizationGrantReturning} from own_auth_authorization_grants
       where authorization_client_id = $1 and user_id = $2`,
      [authorizationClientId, userId]
    );
    return row ? mapAuthorizationGrant(row) : null;
  }

  async upsertAuthorizationGrant(grant: AuthorizationGrant): Promise<AuthorizationGrant> {
    const result = await this.db.query<Row>(
      `insert into own_auth_authorization_grants
        (id, authorization_client_id, user_id, scopes, created_at, updated_at, revoked_at)
       values ($1,$2,$3,$4,$5,$6,$7)
       on conflict (authorization_client_id, user_id) do update set
         scopes = excluded.scopes,
         updated_at = excluded.updated_at,
         revoked_at = null
       returning ${authorizationGrantReturning}`,
      [
        grant.id,
        grant.authorizationClientId,
        grant.userId,
        grant.scopes,
        grant.createdAt,
        grant.updatedAt,
        grant.revokedAt
      ]
    );
    return mapAuthorizationGrant(expectOne(result.rows));
  }

  async listAuthorizationGrantsByUserId(userId: string): Promise<AuthorizationGrant[]> {
    return (await this.selectMany(
      `${authorizationGrantReturning} from own_auth_authorization_grants
       where user_id = $1 order by created_at desc`,
      [userId]
    )).map(mapAuthorizationGrant);
  }

  async revokeAuthorizationGrant(
    id: string,
    revokedAt: Date
  ): Promise<AuthorizationGrant | null> {
    const result = await this.db.query<Row>(
      `with revoked_grant as (
         update own_auth_authorization_grants
         set revoked_at = $2, updated_at = $2
         where id = $1
         returning ${authorizationGrantReturning}
       ), revoked_access as (
         update own_auth_authorization_access_tokens set revoked_at = $2
         where grant_id = $1 and revoked_at is null
       ), revoked_refresh as (
         update own_auth_authorization_refresh_tokens set revoked_at = $2
         where grant_id = $1 and revoked_at is null
       )
       select ${authorizationGrantReturning} from revoked_grant`,
      [id, revokedAt]
    );
    return result.rows[0] ? mapAuthorizationGrant(result.rows[0]) : null;
  }
}
