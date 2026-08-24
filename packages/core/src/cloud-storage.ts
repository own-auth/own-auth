import type { AuthStorage } from "./storage.js";
import type {
  CloudCommandPayload,
  CloudCommandResult,
  CloudEvent,
  CloudEventEntity
} from "./cloud-types.js";

export interface CloudOutboxRecord {
  id: string;
  event: CloudEvent;
  priority: boolean;
  createdAt: Date;
  sentAt: Date | null;
  ackAt: Date | null;
  attempts: number;
  nextRetryAt: Date;
  leaseUntil: Date | null;
}

export interface CloudSnapshotRecord {
  type: "user" | "org" | "member" | "session";
  entityVersion: number;
  data: Record<string, unknown>;
}

export type CloudCommandReservation =
  | { status: "execute" }
  | { status: "in_progress" }
  | { status: "replay" }
  | { status: "resolved"; result: CloudCommandResult };

export interface CloudStorage {
  readonly durable: boolean;
  enqueueCloudEvent(
    event: CloudEvent,
    entity: CloudEventEntity | null,
    priority: boolean,
    maximumPending?: number
  ): Promise<CloudEvent | null>;
  claimCloudOutbox(limit: number, now: Date, leaseUntil: Date): Promise<CloudOutboxRecord[]>;
  acknowledgeCloudOutbox(ids: readonly string[], acknowledgedAt: Date): Promise<void>;
  retryCloudOutbox(id: string, attempts: number, nextRetryAt: Date): Promise<void>;
  countCloudOutbox(includePriority?: boolean): Promise<number>;
  clearCloudOutbox(includePriority: boolean): Promise<number>;
  purgeCloudOutboxForUser(userId: string, email?: string | null): Promise<number>;
  listCloudSnapshot(cursor: string | null, limit: number): Promise<{
    records: CloudSnapshotRecord[];
    cursor: string | null;
  }>;
  getCloudConfig(key: string): Promise<string | null>;
  getOrCreateCloudConfig(key: string, value: string): Promise<string>;
  setCloudConfig(key: string, value: string): Promise<void>;
  consumeCloudChallengeNonce(nonce: string, expiresAt: Date): Promise<boolean>;
  reserveCloudCommand(input: {
    idempotencyKey: string;
    nonce: string;
    action: CloudCommandPayload["action"];
    payloadHash: string;
    payload: CloudCommandPayload;
    now: Date;
    leaseUntil: Date;
  }): Promise<CloudCommandReservation>;
  completeCloudCommand(
    idempotencyKey: string,
    status: "completed" | "failed",
    result: CloudCommandResult,
    completedAt: Date
  ): Promise<void>;
  cleanupCloudState(olderThan: Date): Promise<number>;
}

export interface CloudCapableStorage extends AuthStorage {
  readonly cloudStorage: CloudStorage;
}

export function isCloudCapableStorage(storage: AuthStorage): storage is CloudCapableStorage {
  const cloudStorage = (storage as Partial<CloudCapableStorage>).cloudStorage;
  return Boolean(cloudStorage) && typeof cloudStorage?.durable === "boolean" && [
    "enqueueCloudEvent",
    "claimCloudOutbox",
    "acknowledgeCloudOutbox",
    "retryCloudOutbox",
    "countCloudOutbox",
    "clearCloudOutbox",
    "purgeCloudOutboxForUser",
    "listCloudSnapshot",
    "getCloudConfig",
    "getOrCreateCloudConfig",
    "setCloudConfig",
    "consumeCloudChallengeNonce",
    "reserveCloudCommand",
    "completeCloudCommand",
    "cleanupCloudState"
  ].every((method) => typeof cloudStorage?.[method as keyof CloudStorage] === "function");
}
