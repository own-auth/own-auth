import {
  mapAuthorizationGrant,
  mapDeviceAuthorization
} from "../authorization-server-database-mappers.js";
import {
  authorizationGrantReturning,
  deviceAuthorizationColumns,
  deviceAuthorizationReturning
} from "../authorization-server-database-schema.js";
import type {
  ConsumeDeviceAuthorizationInput,
  DeviceAuthorization,
  DeviceAuthorizationDecisionResult,
  DeviceAuthorizationPollResult
} from "../authorization-server-device-types.js";
import type {
  ApproveDeviceAuthorizationStorageInput,
  DenyDeviceAuthorizationStorageInput,
  DeviceAuthorizationStorage,
  PollDeviceAuthorizationInput
} from "../authorization-server-device-storage.js";
import {
  deviceDecisionState,
  nextDevicePollAt,
  slowedDevicePolling,
  terminalDevicePollState
} from "../authorization-server-device-state.js";
import {
  authorizationAccessTokenValues,
  authorizationRefreshTokenValues
} from "../authorization-server-token-values.js";
import type { DatabaseRow } from "../database-types.js";
import { D1StorageBase, placeholders } from "./d1-storage-base.js";
import type { D1DatabaseLike, D1PreparedStatementLike } from "./d1-types.js";

export class D1DeviceAuthorizationStorage
  extends D1StorageBase
  implements DeviceAuthorizationStorage {
  constructor(db: D1DatabaseLike) {
    super(db);
  }

  async createDeviceAuthorization(
    authorization: DeviceAuthorization
  ): Promise<DeviceAuthorization> {
    return mapDeviceAuthorization(await this.insertOne(
      "own_auth_device_authorizations",
      deviceAuthorizationColumns,
      authorization,
      deviceAuthorizationReturning
    ));
  }

  async getDeviceAuthorizationByUserCodeHash(
    userCodeHash: string
  ): Promise<DeviceAuthorization | null> {
    const row = await this.selectOne(
      `${deviceAuthorizationReturning} from own_auth_device_authorizations
       where user_code_hash = ?1`,
      [userCodeHash]
    );
    return row ? mapDeviceAuthorization(row) : null;
  }

  async getDeviceAuthorizationByDeviceCodeHash(
    deviceCodeHash: string
  ): Promise<DeviceAuthorization | null> {
    const row = await this.selectOne(
      `${deviceAuthorizationReturning} from own_auth_device_authorizations
       where device_code_hash = ?1`,
      [deviceCodeHash]
    );
    return row ? mapDeviceAuthorization(row) : null;
  }

  async approveDeviceAuthorization(
    input: ApproveDeviceAuthorizationStorageInput
  ): Promise<DeviceAuthorizationDecisionResult> {
    const grant = input.grant;
    const conflictTarget = grant.protectedResourceId === null
      ? "(authorization_client_id, user_id) where protected_resource_id is null"
      : "(authorization_client_id, user_id, protected_resource_id) " +
        "where protected_resource_id is not null";
    const results = await this.db.batch<DatabaseRow>([
      this.prepare(
        `insert into own_auth_authorization_grants
          (id, authorization_client_id, user_id, protected_resource_id,
           scopes, created_at, updated_at, revoked_at)
         select ?2,?3,?4,?5,?6,?7,?8,?9
         from own_auth_device_authorizations
         where user_code_hash = ?1 and status = 'pending'
           and expires_at > ?10 and authorization_client_id = ?3
           and protected_resource_id is ?5
         on conflict ${conflictTarget} do update set
           scopes = excluded.scopes,
           updated_at = excluded.updated_at,
           revoked_at = null
         returning id`,
        [
          input.userCodeHash,
          grant.id,
          grant.authorizationClientId,
          grant.userId,
          grant.protectedResourceId,
          grant.scopes,
          grant.createdAt,
          grant.updatedAt,
          grant.revokedAt,
          input.decidedAt
        ]
      ),
      this.prepare(
        `update own_auth_device_authorizations
         set status = 'approved', user_id = ?4, session_id = ?10,
             grant_id = (
               select id from own_auth_authorization_grants
               where authorization_client_id = ?3 and user_id = ?4
                 and protected_resource_id is ?5
             ),
             approved_scopes = ?12, approved_at = ?11
         where user_code_hash = ?1 and status = 'pending'
           and expires_at > ?11 and authorization_client_id = ?3
           and protected_resource_id is ?5
         returning ${deviceAuthorizationReturning}`,
        [
          input.userCodeHash,
          grant.id,
          grant.authorizationClientId,
          grant.userId,
          grant.protectedResourceId,
          grant.scopes,
          grant.createdAt,
          grant.updatedAt,
          grant.revokedAt,
          input.sessionId,
          input.decidedAt,
          input.approvedScopes
        ]
      )
    ]);
    const row = results[1]?.results?.[0];
    if (!row) return this.classifyDecisionFailure(input.userCodeHash, input.decidedAt);
    const authorization = mapDeviceAuthorization(row);
    if (!authorization.grantId) throw new Error("Approved device grant was not persisted");
    const grantRow = await this.selectOne(
      `${authorizationGrantReturning} from own_auth_authorization_grants where id = ?1`,
      [authorization.grantId]
    );
    if (!grantRow) throw new Error("Approved device grant was not persisted");
    return {
      status: "approved",
      authorization,
      grant: mapAuthorizationGrant(grantRow)
    };
  }

  async denyDeviceAuthorization(
    input: DenyDeviceAuthorizationStorageInput
  ): Promise<DeviceAuthorizationDecisionResult> {
    const row = await this.prepare(
      `update own_auth_device_authorizations
       set status = 'denied', user_id = ?2, session_id = ?3, denied_at = ?4
       where user_code_hash = ?1 and status = 'pending' and expires_at > ?4
       returning ${deviceAuthorizationReturning}`,
      [input.userCodeHash, input.userId, input.sessionId, input.decidedAt]
    ).first<DatabaseRow>();
    return row
      ? { status: "denied", authorization: mapDeviceAuthorization(row) }
      : this.classifyDecisionFailure(input.userCodeHash, input.decidedAt);
  }

  async pollDeviceAuthorization(
    input: PollDeviceAuthorizationInput
  ): Promise<DeviceAuthorizationPollResult> {
    const authorization = await this.findForPoll(input);
    if (!authorization) return { status: "invalid" };
    const terminal = terminalDevicePollState(authorization, input.polledAt);
    if (terminal) return terminal;
    const nextPollAt = nextDevicePollAt(authorization, input.polledAt);
    const accepted = await this.prepare(
      `update own_auth_device_authorizations set next_poll_at = ?4
       where device_code_hash = ?1 and authorization_client_id = ?2
         and status = 'pending' and expires_at > ?3 and next_poll_at <= ?3
       returning id`,
      [input.deviceCodeHash, input.authorizationClientId, input.polledAt, nextPollAt]
    ).first<DatabaseRow>();
    if (accepted) return { status: "authorization_pending" };
    const slowedState = slowedDevicePolling(authorization, input.polledAt);
    const slowed = await this.prepare(
      `update own_auth_device_authorizations
       set polling_interval_seconds = ?4, next_poll_at = ?5
       where device_code_hash = ?1 and authorization_client_id = ?2
         and status = 'pending' and expires_at > ?3 and next_poll_at > ?3
       returning id`,
      [
        input.deviceCodeHash,
        input.authorizationClientId,
        input.polledAt,
        slowedState.intervalSeconds,
        slowedState.nextPollAt
      ]
    ).first<DatabaseRow>();
    if (slowed) return { status: "slow_down" };
    const current = await this.findForPoll(input);
    return current
      ? terminalDevicePollState(current, input.polledAt) ?? { status: "invalid" }
      : { status: "invalid" };
  }

  async consumeDeviceAuthorization(
    input: ConsumeDeviceAuthorizationInput
  ): Promise<boolean> {
    const access = authorizationAccessTokenValues(input.accessToken);
    const statements: D1PreparedStatementLike[] = [
      this.prepare(
        `insert into own_auth_authorization_access_tokens
          (id, token_hash, prefix, grant_id, authorization_client_id, user_id,
           protected_resource_id, scopes, dpop_jkt, expires_at, revoked_at, created_at)
         select ${placeholders(12, 4)} from own_auth_device_authorizations
         where id = ?1 and device_code_hash = ?2 and authorization_client_id = ?3
           and status = 'approved' and consumed_at is null and expires_at > ?4`,
        [
          input.id,
          input.deviceCodeHash,
          input.authorizationClientId,
          input.consumedAt,
          ...access
        ]
      )
    ];
    if (input.refreshToken) {
      const refresh = authorizationRefreshTokenValues(input.refreshToken);
      statements.push(this.prepare(
        `insert into own_auth_authorization_refresh_tokens
          (id, token_hash, prefix, grant_id, authorization_client_id, user_id,
           protected_resource_id, scopes, generation, replaced_by_token_id,
           dpop_jkt, expires_at, consumed_at, revoked_at, created_at)
         select ${placeholders(15, 1)}
         from own_auth_authorization_access_tokens where id = ?1`,
        [input.accessToken.id, ...refresh]
      ));
    }
    statements.push(this.prepare(
      `update own_auth_device_authorizations
       set status = 'consumed', consumed_at = ?4
       where id = ?1 and device_code_hash = ?2 and authorization_client_id = ?3
         and status = 'approved' and consumed_at is null and expires_at > ?4
         and exists (
           select 1 from own_auth_authorization_access_tokens where id = ?5
         )
       returning id`,
      [
        input.id,
        input.deviceCodeHash,
        input.authorizationClientId,
        input.consumedAt,
        input.accessToken.id
      ]
    ));
    const results = await this.db.batch<DatabaseRow>(statements);
    return Boolean(results.at(-1)?.results?.[0]);
  }

  async cleanupDeviceAuthorizations(olderThan: Date): Promise<number> {
    const result = await this.prepare(
      "delete from own_auth_device_authorizations where expires_at <= ?1",
      [olderThan]
    ).run();
    return typeof result.meta?.changes === "number" ? result.meta.changes : 0;
  }

  private async findForPoll(
    input: PollDeviceAuthorizationInput
  ): Promise<DeviceAuthorization | null> {
    const row = await this.selectOne(
      `${deviceAuthorizationReturning} from own_auth_device_authorizations
       where device_code_hash = ?1 and authorization_client_id = ?2`,
      [input.deviceCodeHash, input.authorizationClientId]
    );
    return row ? mapDeviceAuthorization(row) : null;
  }

  private async classifyDecisionFailure(
    userCodeHash: string,
    at: Date
  ): Promise<Extract<DeviceAuthorizationDecisionResult, { status: "already_decided" | "invalid" }>> {
    const authorization = await this.getDeviceAuthorizationByUserCodeHash(userCodeHash);
    return deviceDecisionState(authorization, at) ?? { status: "invalid" };
  }
}
