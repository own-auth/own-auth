import type {
  AuditEvent,
  JsonRecord,
  RequestContext,
  SessionAssuranceLevel,
  User
} from "./types.js";
import type { AuthStorage, ListUsersFilter } from "./storage.js";

export const administrationActions = [
  "users:list",
  "users:read",
  "users:disable",
  "users:enable",
  "users:erase",
  "erasures:read",
  "erasures:resume",
  "organisations:resolve-erasure",
  "sessions:list",
  "sessions:revoke",
  "audit:list"
] as const;

export type AdministrationAction = (typeof administrationActions)[number];
export type AdministrationUserStatus = "active" | "disabled" | "all";
export type AdministrationSessionStatus =
  | "active"
  | "disabled_user"
  | "expired"
  | "revoked";

export interface AdministrationUser {
  id: string;
  email: string | null;
  emailVerifiedAt: Date | null;
  phone: string | null;
  phoneVerifiedAt: Date | null;
  name: string | null;
  imageUrl: string | null;
  disabledAt: Date | null;
  metadata: JsonRecord;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt: Date | null;
}

export interface AdministrationSession {
  id: string;
  userId: string;
  createdAt: Date;
  lastActiveAt: Date;
  expiresAt: Date;
  idleExpiresAt: Date;
  ipAddress: string | null;
  userAgent: string | null;
  revokedAt: Date | null;
  revokeReason: string | null;
  authenticationMethods: string[];
  assuranceLevel: SessionAssuranceLevel;
  authenticatedAt: Date;
  effectiveStatus: AdministrationSessionStatus;
}

export interface AdministrationPage<Item> {
  items: Item[];
  nextCursor: string | null;
}

export interface AdministrationAuthorizationContext {
  operationId?: string;
  organisationId?: string;
  actor: Readonly<AdministrationUser>;
  action: AdministrationAction;
  targetUserId: string | undefined;
}

export interface AdministrationOptions {
  authorize(
    context: AdministrationAuthorizationContext
  ): boolean | Promise<boolean>;
}

export interface AdministrationCapableStorage extends AuthStorage {
  listUsers(filter?: ListUsersFilter): Promise<User[]>;
}

export function isAdministrationCapableStorage(
  storage: AuthStorage
): storage is AdministrationCapableStorage {
  return typeof (storage as Partial<AdministrationCapableStorage>).listUsers === "function";
}

interface AdministrationActorInput {
  actorUserId: string;
  request?: RequestContext;
}

export interface ListAdministrationUsersInput extends AdministrationActorInput {
  query?: string;
  status?: AdministrationUserStatus;
  cursor?: string;
  limit?: number;
}

export interface GetAdministrationUserInput extends AdministrationActorInput {
  userId: string;
}

export type ListAdministrationUserSessionsInput = GetAdministrationUserInput;

export interface ListAdministrationUserAuditEventsInput
  extends GetAdministrationUserInput {
  cursor?: string;
  limit?: number;
}

export interface AdministrationUserMutationInput extends GetAdministrationUserInput {
  reason: string;
}

export type AdministrationAuditEventPage = AdministrationPage<AuditEvent>;
