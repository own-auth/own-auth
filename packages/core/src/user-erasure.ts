import type { AuthStorage } from "./storage.js";
import type { RequestContext } from "./types.js";
import type { CloudEvent } from "./cloud-types.js";
import { AuthError } from "./errors.js";

export type UserErasureOrganisationResolution =
  | { organisationId: string; action: "transfer"; newOwnerUserId: string }
  | { organisationId: string; action: "delete"; confirmation: "delete_organisation" };

export interface EraseUserInput {
  sessionToken: string;
  confirmation: "erase";
  operationId: string;
  organisations?: readonly UserErasureOrganisationResolution[];
  request?: RequestContext;
}

export interface AdministrationEraseUserInput {
  actorUserId: string;
  userId: string;
  reason: string;
  operationId: string;
  organisations?: readonly UserErasureOrganisationResolution[];
  request?: RequestContext;
}

export interface UserErasureOperationInput { operationId: string }

export interface AdministrationUserErasureOperationInput extends UserErasureOperationInput {
  actorUserId: string;
  request?: RequestContext;
}

export interface UserErasureResult {
  operationId: string;
  status: "pending" | "complete";
  local: "pending" | "complete";
  cloud: "not_configured" | "pending" | "complete";
  pendingLocalStores: string[];
}

/** Only identifiers needed to remove records. Never include authentication secrets. */
export interface UserErasureSubject {
  userId: string;
  email: string | null;
  phone: string | null;
  references: string[];
  identities: { provider: string; providerAccountId: string }[];
}

export type UserErasureParticipation =
  | { personalData: false }
  | { personalData: true; erase(subject: Readonly<UserErasureSubject>): Promise<void> };

/** Internal recovery state. Public results must never expose the subject. */
export interface StoredUserErasure {
  operationId: string;
  subject: UserErasureSubject | null;
  pendingStores: string[];
  protectedUntil: number;
  cloudEventId: string | null;
  pendingCloudEvents: string[];
  cloudComplete: boolean;
  createdAt: number;
  completedAt: number | null;
}

export interface AtomicUserErasureInput {
  operationId: string;
  userId: string;
  expectedUpdatedAt: Date;
  sessionTokenHash?: string;
  authenticatedAfter?: Date;
  requireMfa?: boolean;
  organisations: readonly UserErasureOrganisationResolution[];
  pendingStores: string[];
  protectedUntil: number;
  now: number;
  cloudEvent: CloudEvent | null;
}

export interface UserErasureStorage {
  eraseAtomically(input: AtomicUserErasureInput): Promise<StoredUserErasure>;
  get(operationId: string): Promise<StoredUserErasure | null>;
  findByUser(userId: string): Promise<StoredUserErasure | null>;
  settleStore(operationId: string, store: string): Promise<void>;
  settleCloud(eventId: string): Promise<void>;
  isCloudErasure(eventId: string): Promise<boolean>;
  finish(operationId: string, now: number): Promise<StoredUserErasure | null>;
  assertIdentityAllowed(identity: {
    userId?: string; email?: string | null; phone?: string | null;
    provider?: string; providerAccountId?: string;
  }): Promise<void>;
  authorizeWebhookSend(deliveryId: string, leaseToken: string): Promise<boolean>;
}

export interface UserErasureCapableStorage extends AuthStorage {
  readonly userErasureStorage: UserErasureStorage;
}

export function isUserErasureCapableStorage(storage: AuthStorage): storage is UserErasureCapableStorage {
  const candidate = (storage as Partial<UserErasureCapableStorage>).userErasureStorage;
  return Boolean(candidate) && [
    "eraseAtomically", "get", "findByUser", "settleStore", "settleCloud",
    "isCloudErasure", "finish", "assertIdentityAllowed", "authorizeWebhookSend"
  ].every((name) => typeof candidate?.[name as keyof UserErasureStorage] === "function");
}

export function requireResumableUserErasure(record: StoredUserErasure, userId: string): StoredUserErasure {
  if (!record.subject || record.completedAt !== null) {
    throw new AuthError("erasure_operation_closed", "This erasure operation is closed", 409);
  }
  if (record.subject.userId !== userId) {
    throw new AuthError("erasure_operation_conflict", "Operation ID already belongs to another erasure", 409);
  }
  return record;
}

export function isUserErasureProtected(
  record: StoredUserErasure, now = Date.now()
): record is StoredUserErasure & { subject: UserErasureSubject } {
  return record.subject !== null && (record.protectedUntil > now || record.pendingStores.length > 0);
}

export function cloudErasureSubject(userId: string): UserErasureSubject {
  return { userId, email: null, phone: null, references: [userId], identities: [] };
}

export function userErasureResult(record: StoredUserErasure, now = Date.now()): UserErasureResult {
  const pendingLocalStores = [...record.pendingStores];
  if (record.subject && record.protectedUntil > now) pendingLocalStores.push("pending_identity_requests");
  if (record.subject && !pendingLocalStores.length && (!record.cloudEventId || record.subject.email ||
    record.subject.phone || record.subject.identities.length || record.subject.references.length > 1)) {
    pendingLocalStores.push("erasure_receipt");
  }
  const local = record.subject && pendingLocalStores.length ? "pending" : "complete";
  const cloud = !record.cloudEventId ? "not_configured" : record.cloudComplete ? "complete" : "pending";
  return {
    operationId: record.operationId,
    status: local === "complete" && cloud !== "pending" ? "complete" : "pending",
    local, cloud, pendingLocalStores
  };
}
