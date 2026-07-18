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
  terminalDevicePollState
} from "../authorization-server-device-state.js";
import {
  authorizationAccessTokenValues,
  authorizationRefreshTokenValues
} from "../authorization-server-token-values.js";
import { PostgresStorageBase } from "./postgres-storage-base.js";
import type { Row } from "./postgres-types.js";

export class PostgresDeviceAuthorizationStorage
  extends PostgresStorageBase
  implements DeviceAuthorizationStorage {
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
       where user_code_hash = $1`,
      [userCodeHash]
    );
    return row ? mapDeviceAuthorization(row) : null;
  }

  async getDeviceAuthorizationByDeviceCodeHash(
    deviceCodeHash: string
  ): Promise<DeviceAuthorization | null> {
    const row = await this.selectOne(
      `${deviceAuthorizationReturning} from own_auth_device_authorizations
       where device_code_hash = $1`,
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
    const result = await this.db.query<Row>(
      `with target as (
         select id from own_auth_device_authorizations
         where user_code_hash = $1 and status = 'pending'
           and expires_at > $11
           and authorization_client_id = $3
           and protected_resource_id is not distinct from $5
         for update
       ), saved_grant as (
         insert into own_auth_authorization_grants
           (id, authorization_client_id, user_id, protected_resource_id,
            scopes, created_at, updated_at, revoked_at)
         select $2,$3,$4,$5,$6,$7,$8,$9 from target
         on conflict ${conflictTarget} do update set
           scopes = excluded.scopes,
           updated_at = excluded.updated_at,
           revoked_at = null
         returning id
       )
       update own_auth_device_authorizations as device_authorization
       set status = 'approved', user_id = $4, session_id = $10,
           grant_id = (select id from saved_grant), approved_scopes = $12,
           approved_at = $11
       where device_authorization.id in (select id from target)
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
    );
    const authorization = result.rows[0]
      ? mapDeviceAuthorization(result.rows[0])
      : null;
    if (!authorization?.grantId) {
      return this.classifyDecisionFailure(input.userCodeHash, input.decidedAt);
    }
    const grantRow = await this.selectOne(
      `${authorizationGrantReturning} from own_auth_authorization_grants
       where id = $1`,
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
    const result = await this.db.query<Row>(
      `update own_auth_device_authorizations
       set status = 'denied', user_id = $2, session_id = $3, denied_at = $4
       where user_code_hash = $1 and status = 'pending' and expires_at > $4
       returning ${deviceAuthorizationReturning}`,
      [input.userCodeHash, input.userId, input.sessionId, input.decidedAt]
    );
    return result.rows[0]
      ? { status: "denied", authorization: mapDeviceAuthorization(result.rows[0]) }
      : this.classifyDecisionFailure(input.userCodeHash, input.decidedAt);
  }

  async pollDeviceAuthorization(
    input: PollDeviceAuthorizationInput
  ): Promise<DeviceAuthorizationPollResult> {
    const authorization = await this.findForPoll(input);
    if (!authorization) return { status: "invalid" };
    const terminal = terminalDevicePollState(authorization, input.polledAt);
    if (terminal) return terminal;
    const accepted = await this.db.query<Row>(
      `update own_auth_device_authorizations
       set next_poll_at = least(expires_at, $3 + polling_interval_seconds * interval '1 second')
       where device_code_hash = $1 and authorization_client_id = $2
         and status = 'pending' and expires_at > $3 and next_poll_at <= $3
       returning id`,
      [input.deviceCodeHash, input.authorizationClientId, input.polledAt]
    );
    if (accepted.rows[0]) return { status: "authorization_pending" };
    const slowed = await this.db.query<Row>(
      `update own_auth_device_authorizations
       set polling_interval_seconds = least(
             polling_interval_seconds + 5,
             greatest(1, ceil(extract(epoch from (expires_at - $3)))::integer)
           ),
           next_poll_at = least(
             expires_at,
             $3 + least(
               polling_interval_seconds + 5,
               greatest(1, ceil(extract(epoch from (expires_at - $3)))::integer)
             ) * interval '1 second'
           )
       where device_code_hash = $1 and authorization_client_id = $2
         and status = 'pending' and expires_at > $3 and next_poll_at > $3
       returning id`,
      [input.deviceCodeHash, input.authorizationClientId, input.polledAt]
    );
    if (slowed.rows[0]) return { status: "slow_down" };
    const current = await this.findForPoll(input);
    return current
      ? terminalDevicePollState(current, input.polledAt) ?? { status: "invalid" }
      : { status: "invalid" };
  }

  async consumeDeviceAuthorization(
    input: ConsumeDeviceAuthorizationInput
  ): Promise<boolean> {
    const access = authorizationAccessTokenValues(input.accessToken);
    const refresh = input.refreshToken
      ? authorizationRefreshTokenValues(input.refreshToken)
      : null;
    const refreshSql = refresh
      ? `, refresh_token as (
           insert into own_auth_authorization_refresh_tokens
             (id, token_hash, prefix, grant_id, authorization_client_id, user_id,
              protected_resource_id, scopes, generation, replaced_by_token_id,
              dpop_jkt, expires_at, consumed_at, revoked_at, created_at)
           select ${placeholders(15, 16)} from consumed
         )`
      : "";
    const result = await this.db.query<Row>(
      `with consumed as (
         update own_auth_device_authorizations
         set status = 'consumed', consumed_at = $4
         where id = $1 and device_code_hash = $2 and authorization_client_id = $3
           and status = 'approved' and consumed_at is null and expires_at > $4
         returning id
       ), access_token as (
         insert into own_auth_authorization_access_tokens
           (id, token_hash, prefix, grant_id, authorization_client_id, user_id,
            protected_resource_id, scopes, dpop_jkt, expires_at, revoked_at, created_at)
         select ${placeholders(12, 4)} from consumed
       )${refreshSql}
       select id from consumed`,
      [
        input.id,
        input.deviceCodeHash,
        input.authorizationClientId,
        input.consumedAt,
        ...access,
        ...(refresh ?? [])
      ]
    );
    return Boolean(result.rows[0]);
  }

  async cleanupDeviceAuthorizations(olderThan: Date): Promise<number> {
    const result = await this.db.query<Row>(
      "delete from own_auth_device_authorizations where expires_at <= $1 returning id",
      [olderThan]
    );
    return result.rows.length;
  }

  private async findForPoll(
    input: PollDeviceAuthorizationInput
  ): Promise<DeviceAuthorization | null> {
    const row = await this.selectOne(
      `${deviceAuthorizationReturning} from own_auth_device_authorizations
       where device_code_hash = $1 and authorization_client_id = $2`,
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

function placeholders(count: number, offset: number): string {
  return Array.from({ length: count }, (_, index) => `$${offset + index + 1}`).join(",");
}
