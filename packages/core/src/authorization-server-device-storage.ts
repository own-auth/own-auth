import type {
  ConsumeDeviceAuthorizationInput,
  DeviceAuthorization,
  DeviceAuthorizationDecisionResult,
  DeviceAuthorizationPollResult
} from "./authorization-server-device-types.js";
import type { AuthorizationGrant } from "./authorization-server-types.js";
import type { AuthorizationServerStorage } from "./authorization-server-storage.js";

export interface ApproveDeviceAuthorizationStorageInput extends DenyDeviceAuthorizationStorageInput {
  approvedScopes: string[];
  grant: AuthorizationGrant;
}

export interface DenyDeviceAuthorizationStorageInput {
  userCodeHash: string;
  userId: string;
  sessionId: string;
  decidedAt: Date;
}

export interface ClaimDeviceAuthorizationStorageInput
  extends Omit<DenyDeviceAuthorizationStorageInput, "decidedAt"> {
  claimedAt: Date;
}

export interface PollDeviceAuthorizationInput {
  deviceCodeHash: string;
  authorizationClientId: string;
  polledAt: Date;
}

export interface DeviceAuthorizationStorage {
  createDeviceAuthorization(
    authorization: DeviceAuthorization
  ): Promise<DeviceAuthorization>;
  getDeviceAuthorizationByUserCodeHash(
    userCodeHash: string
  ): Promise<DeviceAuthorization | null>;
  getDeviceAuthorizationByDeviceCodeHash(
    deviceCodeHash: string
  ): Promise<DeviceAuthorization | null>;
  claimDeviceAuthorization(
    input: ClaimDeviceAuthorizationStorageInput
  ): Promise<boolean>;
  approveDeviceAuthorization(
    input: ApproveDeviceAuthorizationStorageInput
  ): Promise<DeviceAuthorizationDecisionResult>;
  denyDeviceAuthorization(
    input: DenyDeviceAuthorizationStorageInput
  ): Promise<DeviceAuthorizationDecisionResult>;
  pollDeviceAuthorization(
    input: PollDeviceAuthorizationInput
  ): Promise<DeviceAuthorizationPollResult>;
  consumeDeviceAuthorization(
    input: ConsumeDeviceAuthorizationInput
  ): Promise<boolean>;
  cleanupDeviceAuthorizations(olderThan: Date): Promise<number>;
}

export interface DeviceAuthorizationCapableAuthorizationServerStorage
  extends AuthorizationServerStorage {
  readonly deviceAuthorizationStorage: DeviceAuthorizationStorage;
}

export function isDeviceAuthorizationCapableStorage(
  storage: AuthorizationServerStorage
): storage is DeviceAuthorizationCapableAuthorizationServerStorage {
  const candidate = storage as Partial<DeviceAuthorizationCapableAuthorizationServerStorage>;
  const deviceStorage = candidate.deviceAuthorizationStorage;
  return Boolean(deviceStorage) && [
    "createDeviceAuthorization",
    "getDeviceAuthorizationByUserCodeHash",
    "getDeviceAuthorizationByDeviceCodeHash",
    "claimDeviceAuthorization",
    "approveDeviceAuthorization",
    "denyDeviceAuthorization",
    "pollDeviceAuthorization",
    "consumeDeviceAuthorization",
    "cleanupDeviceAuthorizations"
  ].every(
    (method) =>
      typeof deviceStorage?.[method as keyof DeviceAuthorizationStorage] === "function"
  );
}
