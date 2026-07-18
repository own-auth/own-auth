import type {
  ConsumeDeviceAuthorizationInput,
  DeviceAuthorization,
  DeviceAuthorizationDecisionResult,
  DeviceAuthorizationPollResult
} from "./authorization-server-device-types.js";
import type {
  ApproveDeviceAuthorizationStorageInput,
  DenyDeviceAuthorizationStorageInput,
  DeviceAuthorizationStorage,
  PollDeviceAuthorizationInput
} from "./authorization-server-device-storage.js";
import {
  deviceDecisionState,
  nextDevicePollAt,
  slowedDevicePolling,
  terminalDevicePollState
} from "./authorization-server-device-state.js";
import type {
  AuthorizationAccessToken,
  AuthorizationGrant,
  AuthorizationRefreshToken
} from "./authorization-server-types.js";
import { cloneStored } from "./memory-storage-helpers.js";

interface MemoryDeviceAuthorizationDependencies {
  grants: Map<string, AuthorizationGrant>;
  accessTokens: Map<string, AuthorizationAccessToken>;
  refreshTokens: Map<string, AuthorizationRefreshToken>;
}

export class MemoryDeviceAuthorizationStorage
  implements DeviceAuthorizationStorage {
  private readonly authorizations = new Map<string, DeviceAuthorization>();

  constructor(private readonly dependencies: MemoryDeviceAuthorizationDependencies) {}

  async createDeviceAuthorization(
    authorization: DeviceAuthorization
  ): Promise<DeviceAuthorization> {
    this.authorizations.set(authorization.id, cloneStored(authorization));
    return cloneStored(authorization);
  }

  async getDeviceAuthorizationByUserCodeHash(
    userCodeHash: string
  ): Promise<DeviceAuthorization | null> {
    return this.findByUserCodeHash(userCodeHash);
  }

  async getDeviceAuthorizationByDeviceCodeHash(
    deviceCodeHash: string
  ): Promise<DeviceAuthorization | null> {
    const authorization = [...this.authorizations.values()].find(
      (candidate) => candidate.deviceCodeHash === deviceCodeHash
    );
    return authorization ? cloneStored(authorization) : null;
  }

  async approveDeviceAuthorization(
    input: ApproveDeviceAuthorizationStorageInput
  ): Promise<DeviceAuthorizationDecisionResult> {
    const authorization = this.findMutableByUserCodeHash(input.userCodeHash);
    const decision = deviceDecisionState(authorization, input.decidedAt);
    if (decision) return decision;
    const grant = this.upsertGrant(input.grant);
    Object.assign(authorization!, {
      status: "approved",
      userId: input.userId,
      sessionId: input.sessionId,
      grantId: grant.id,
      approvedScopes: [...input.approvedScopes],
      approvedAt: input.decidedAt
    } satisfies Partial<DeviceAuthorization>);
    return {
      status: "approved",
      authorization: cloneStored(authorization!),
      grant
    };
  }

  async denyDeviceAuthorization(
    input: DenyDeviceAuthorizationStorageInput
  ): Promise<DeviceAuthorizationDecisionResult> {
    const authorization = this.findMutableByUserCodeHash(input.userCodeHash);
    const decision = deviceDecisionState(authorization, input.decidedAt);
    if (decision) return decision;
    Object.assign(authorization!, {
      status: "denied",
      userId: input.userId,
      sessionId: input.sessionId,
      deniedAt: input.decidedAt
    } satisfies Partial<DeviceAuthorization>);
    return { status: "denied", authorization: cloneStored(authorization!) };
  }

  async pollDeviceAuthorization(
    input: PollDeviceAuthorizationInput
  ): Promise<DeviceAuthorizationPollResult> {
    const authorization = [...this.authorizations.values()].find(
      (candidate) => candidate.deviceCodeHash === input.deviceCodeHash
    );
    if (!authorization || authorization.authorizationClientId !== input.authorizationClientId) {
      return { status: "invalid" };
    }
    const terminal = terminalDevicePollState(authorization, input.polledAt);
    if (terminal) return cloneStored(terminal);
    if (authorization.nextPollAt.getTime() > input.polledAt.getTime()) {
      const slowed = slowedDevicePolling(authorization, input.polledAt);
      authorization.pollingIntervalSeconds = slowed.intervalSeconds;
      authorization.nextPollAt = slowed.nextPollAt;
      return { status: "slow_down" };
    }
    authorization.nextPollAt = nextDevicePollAt(authorization, input.polledAt);
    return { status: "authorization_pending" };
  }

  async consumeDeviceAuthorization(
    input: ConsumeDeviceAuthorizationInput
  ): Promise<boolean> {
    const authorization = this.authorizations.get(input.id);
    if (
      !authorization ||
      authorization.deviceCodeHash !== input.deviceCodeHash ||
      authorization.authorizationClientId !== input.authorizationClientId ||
      authorization.status !== "approved" ||
      authorization.consumedAt ||
      authorization.expiresAt.getTime() <= input.consumedAt.getTime()
    ) {
      return false;
    }
    authorization.status = "consumed";
    authorization.consumedAt = input.consumedAt;
    this.dependencies.accessTokens.set(
      input.accessToken.id,
      cloneStored(input.accessToken)
    );
    if (input.refreshToken) {
      this.dependencies.refreshTokens.set(
        input.refreshToken.id,
        cloneStored(input.refreshToken)
      );
    }
    return true;
  }

  async cleanupDeviceAuthorizations(olderThan: Date): Promise<number> {
    let deleted = 0;
    for (const [id, authorization] of this.authorizations) {
      if (authorization.expiresAt.getTime() <= olderThan.getTime()) {
        this.authorizations.delete(id);
        deleted += 1;
      }
    }
    return deleted;
  }

  private findByUserCodeHash(userCodeHash: string): DeviceAuthorization | null {
    const authorization = this.findMutableByUserCodeHash(userCodeHash);
    return authorization ? cloneStored(authorization) : null;
  }

  private findMutableByUserCodeHash(userCodeHash: string): DeviceAuthorization | null {
    return [...this.authorizations.values()].find(
      (candidate) => candidate.userCodeHash === userCodeHash
    ) ?? null;
  }

  private upsertGrant(grant: AuthorizationGrant): AuthorizationGrant {
    const existing = [...this.dependencies.grants.values()].find(
      (candidate) =>
        candidate.authorizationClientId === grant.authorizationClientId &&
        candidate.userId === grant.userId &&
        candidate.protectedResourceId === grant.protectedResourceId
    );
    if (existing) {
      Object.assign(existing, {
        scopes: [...grant.scopes],
        updatedAt: grant.updatedAt,
        revokedAt: null
      });
      return cloneStored(existing);
    }
    this.dependencies.grants.set(grant.id, cloneStored(grant));
    return cloneStored(grant);
  }
}
