import {
  mapAuthorizationClient,
  mapAuthorizationClientSecret,
  mapAuthorizationGrant,
  mapAuthorizationInteraction
} from "../authorization-server-database-mappers.js";
import {
  authorizationClientColumns,
  authorizationClientReturning,
  authorizationClientSecretColumns,
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
import { expectDatabaseValue } from "../database-row.js";
import type { DatabaseRow } from "../database-types.js";
import { D1StorageBase } from "./d1-storage-base.js";
import type { D1DatabaseLike } from "./d1-types.js";

export class D1AuthorizationClientStorage extends D1StorageBase {
  constructor(db: D1DatabaseLike) {
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
    const results = await this.db.batch<DatabaseRow>([
      this.insertStatement(
        "own_auth_authorization_clients",
        authorizationClientColumns,
        client,
        authorizationClientReturning
      ),
      this.insertStatement(
        "own_auth_authorization_client_secrets",
        authorizationClientSecretColumns,
        secret,
        authorizationClientSecretReturning
      )
    ]);
    return mapAuthorizationClient(
      expectDatabaseValue(
        results[0]?.results?.[0],
        "D1 authorization client creation"
      )
    );
  }

  async getAuthorizationClientByClientId(
    clientId: string
  ): Promise<AuthorizationClient | null> {
    const row = await this.selectOne(
      `${authorizationClientReturning}
       from own_auth_authorization_clients where client_id = ?1`,
      [clientId]
    );
    return row ? mapAuthorizationClient(row) : null;
  }

  async getAuthorizationClientById(id: string): Promise<AuthorizationClient | null> {
    const row = await this.selectOne(
      `${authorizationClientReturning} from own_auth_authorization_clients where id = ?1`,
      [id]
    );
    return row ? mapAuthorizationClient(row) : null;
  }

  async listAuthorizationClients(): Promise<AuthorizationClient[]> {
    return (await this.selectMany(
      `${authorizationClientReturning} from own_auth_authorization_clients
       order by created_at desc, id desc`
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
    const results = await this.db.batch<DatabaseRow>([
      this.prepare(
        `update own_auth_authorization_client_secrets
         set revoked_at = ?2
         where authorization_client_id = ?1 and revoked_at is null`,
        [authorizationClientId, revokedAt]
      ),
      this.insertStatement(
        "own_auth_authorization_client_secrets",
        authorizationClientSecretColumns,
        secret,
        authorizationClientSecretReturning
      )
    ]);
    return mapAuthorizationClientSecret(
      expectDatabaseValue(
        results[1]?.results?.[0],
        "D1 authorization client secret rotation"
      )
    );
  }

  async getAuthorizationClientSecretByPrefix(
    authorizationClientId: string,
    prefix: string
  ): Promise<AuthorizationClientSecret | null> {
    const row = await this.selectOne(
      `${authorizationClientSecretReturning}
       from own_auth_authorization_client_secrets
       where authorization_client_id = ?1 and prefix = ?2
         and revoked_at is null and (expires_at is null or expires_at > ?3)`,
      [authorizationClientId, prefix, Date.now()]
    );
    return row ? mapAuthorizationClientSecret(row) : null;
  }

  async revokeAuthorizationClient(
    id: string,
    revokedAt: Date
  ): Promise<AuthorizationClient | null> {
    const results = await this.db.batch<DatabaseRow>([
      this.prepare(
        `update own_auth_authorization_clients
         set status = 'revoked', revoked_at = ?2, updated_at = ?2
         where id = ?1 returning ${authorizationClientReturning}`,
        [id, revokedAt]
      ),
      this.prepare(
        `update own_auth_authorization_client_secrets set revoked_at = ?2
         where authorization_client_id = ?1 and revoked_at is null`,
        [id, revokedAt]
      ),
      this.prepare(
        `update own_auth_authorization_grants set revoked_at = ?2, updated_at = ?2
         where authorization_client_id = ?1 and revoked_at is null`,
        [id, revokedAt]
      ),
      this.prepare(
        `update own_auth_authorization_access_tokens set revoked_at = ?2
         where authorization_client_id = ?1 and revoked_at is null`,
        [id, revokedAt]
      ),
      this.prepare(
        `update own_auth_authorization_refresh_tokens set revoked_at = ?2
         where authorization_client_id = ?1 and revoked_at is null`,
        [id, revokedAt]
      )
    ]);
    const row = results[0]?.results?.[0];
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
       where interaction_hash = ?1 and status = 'pending'
         and consumed_at is null and expires_at > ?2`,
      [interactionHash, now]
    );
    return row ? mapAuthorizationInteraction(row) : null;
  }

  async bindAuthorizationInteractionToUser(
    interactionHash: string,
    userId: string,
    now: Date
  ): Promise<AuthorizationInteraction | null> {
    const row = await this.prepare(
      `update own_auth_authorization_interactions set user_id = ?2
       where interaction_hash = ?1 and status = 'pending'
         and consumed_at is null and expires_at > ?3
         and (user_id is null or user_id = ?2)
       returning ${authorizationInteractionReturning}`,
      [interactionHash, userId, now]
    ).first<DatabaseRow>();
    return row ? mapAuthorizationInteraction(row) : null;
  }

  async consumeAuthorizationInteraction(
    interactionHash: string,
    userId: string,
    status: Exclude<AuthorizationInteractionStatus, "pending">,
    consumedAt: Date
  ): Promise<AuthorizationInteraction | null> {
    const row = await this.prepare(
      `update own_auth_authorization_interactions
       set status = ?3, consumed_at = ?4
       where interaction_hash = ?1 and user_id = ?2 and status = 'pending'
         and consumed_at is null and expires_at > ?4
       returning ${authorizationInteractionReturning}`,
      [interactionHash, userId, status, consumedAt]
    ).first<DatabaseRow>();
    return row ? mapAuthorizationInteraction(row) : null;
  }

  async getAuthorizationGrant(
    authorizationClientId: string,
    userId: string
  ): Promise<AuthorizationGrant | null> {
    const row = await this.selectOne(
      `${authorizationGrantReturning} from own_auth_authorization_grants
       where authorization_client_id = ?1 and user_id = ?2`,
      [authorizationClientId, userId]
    );
    return row ? mapAuthorizationGrant(row) : null;
  }

  async upsertAuthorizationGrant(grant: AuthorizationGrant): Promise<AuthorizationGrant> {
    const row = await this.prepare(
      `insert into own_auth_authorization_grants
        (id, authorization_client_id, user_id, scopes, created_at, updated_at, revoked_at)
       values (?1,?2,?3,?4,?5,?6,?7)
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
    ).first<DatabaseRow>();
    return mapAuthorizationGrant(
      expectDatabaseValue(row, "D1 authorization grant upsert")
    );
  }

  async listAuthorizationGrantsByUserId(userId: string): Promise<AuthorizationGrant[]> {
    return (await this.selectMany(
      `${authorizationGrantReturning} from own_auth_authorization_grants
       where user_id = ?1 order by created_at desc`,
      [userId]
    )).map(mapAuthorizationGrant);
  }

  async revokeAuthorizationGrant(
    id: string,
    revokedAt: Date
  ): Promise<AuthorizationGrant | null> {
    const results = await this.db.batch<DatabaseRow>([
      this.prepare(
        `update own_auth_authorization_grants
         set revoked_at = ?2, updated_at = ?2
         where id = ?1 returning ${authorizationGrantReturning}`,
        [id, revokedAt]
      ),
      this.prepare(
        `update own_auth_authorization_access_tokens set revoked_at = ?2
         where grant_id = ?1 and revoked_at is null`,
        [id, revokedAt]
      ),
      this.prepare(
        `update own_auth_authorization_refresh_tokens set revoked_at = ?2
         where grant_id = ?1 and revoked_at is null`,
        [id, revokedAt]
      )
    ]);
    const row = results[0]?.results?.[0];
    return row ? mapAuthorizationGrant(row) : null;
  }
}
