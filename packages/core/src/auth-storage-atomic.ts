import type { StoredWebhookEvent } from "./webhook-types.js";
import type {
  AuditEvent,
  Invitation,
  OrganisationMember
} from "./types.js";

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
