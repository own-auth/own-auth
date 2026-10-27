import type { StoredWebhookEvent } from "./webhook-types.js";
import type {
  Account,
  AuditEvent,
  Invitation,
  OrganisationMember,
  Session,
  User
} from "./types.js";

export interface AtomicPasswordUpdateInput {
  userId: string;
  expectedPasswordHash: string | null;
  passwordHash: string;
  updatedAt: Date;
  purpose: "replacement" | "rehash";
}

export interface AtomicEmailOwnershipInput {
  operationId: string;
  sourceUserId: string | null;
  email: string;
  verifiedAt: Date;
  replacementUser: User;
  replacementAccount: Account;
  proof:
    | { kind: "token"; tokenHash: string; type: "magic_link" | "email_verification" | "password_reset"; expiresAt?: Date }
    | { kind: "provider"; originalActorUserId?: string; samlOrganisationId?: string; expiresAt?: Date };
  sessionTokenHash: string | null;
  /** Only the provider identity independently verified by this request may move. */
  verifiedAccountId?: string;
  passwordHash?: string;
}

export interface AtomicEmailOwnershipResult {
  user: User;
  created: boolean;
  verified: boolean;
  revokedSessions: Session[];
  reassignedMemberships: OrganisationMember<string>[];
}

export interface AtomicWebhookDeliverySeed {
  id: string;
  endpointId: string;
  url: string;
  createdAt: Date;
}

export interface AtomicAuthEventWrite {
  auditEvent: AuditEvent;
  webhookEvent: StoredWebhookEvent | null;
  webhookDeliveries: readonly AtomicWebhookDeliverySeed[];
}

export interface AtomicInvitationAcceptanceInput {
  operationId: string;
  tokenId: string;
  tokenHash: string;
  invitationId: string;
  userId: string;
  memberId: string;
  acceptedAt: Date;
  event: AtomicAuthEventWrite;
}

export interface AtomicInvitationAcceptanceResult {
  invitation: Invitation<string>;
  member: OrganisationMember<string>;
}

export interface AtomicInvitationRevocationInput {
  operationId: string;
  invitationId: string;
  revokedAt: Date;
  event: AtomicAuthEventWrite;
}

export type AuthenticationMethodReference =
  | { kind: "account"; id: string }
  | { kind: "passkey"; id: string };

export interface AtomicAuthenticationMethodRemovalInput {
  operationId: string;
  userId: string;
  method: AuthenticationMethodReference;
  event: AtomicAuthEventWrite;
}

export type AtomicAuthenticationMethodRemovalResult =
  | "last_method"
  | "not_found"
  | "removed";
