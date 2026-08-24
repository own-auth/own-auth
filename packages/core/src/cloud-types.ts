import type { OwnAuthPluginClientManifest, OwnAuthPluginDefinition } from "./plugin-types.js";
import type { RequestContext } from "./types.js";
import { cloudEventContract } from "./cloud-event-contract.js";

export type CloudEventType = keyof typeof cloudEventContract.events;
export const cloudEventTypes = Object.freeze(
  Object.keys(cloudEventContract.events) as CloudEventType[]
);
export type CloudEntityType = "user" | "session" | "org";

export interface CloudEvent {
  id: string;
  type: CloudEventType;
  timestamp: string;
  appId: string;
  version: 1;
  entityVersion?: number;
  data: Record<string, unknown>;
  meta: {
    ip?: string;
    userAgent?: string;
    userId?: string;
  };
}

export interface CloudEventEntity {
  type: CloudEntityType;
  id: string;
}

export interface CloudDeliveryError {
  code: "quota_exhausted" | "provider_rejected" | "transient_error" | "invalid_request";
  channel: "email" | "sms";
  status: number;
}

export interface CloudSecurityOptions {
  localOnly?: boolean;
  credentialStuffing?: {
    enabled?: boolean;
    thresholds?: { challenge?: number; deny?: number };
  };
  impossibleTravel?: {
    enabled?: boolean;
    action?: "flag" | "challenge" | "deny";
  };
  botDetection?: {
    enabled?: boolean;
    minimumDifficulty?: number;
  };
}

export interface CloudPluginOptions {
  key: string;
  endpoint?: string | URL;
  webhookSigningSecret?: string;
  webhookPreviousSigningSecret?: string;
  webhookPreviousValidUntil?: string | Date;
  webhookKeyId?: string;
  webhookPreviousKeyId?: string;
  webhookPath?: string;
  challengeSecret?: string;
  flushMode?: "request" | "background" | "manual";
  schedule?: (task: Promise<void>) => void;
  security?: CloudSecurityOptions;
  fetch?: typeof globalThis.fetch;
  onDeliveryError?: (error: CloudDeliveryError) => void | Promise<void>;
  onWarning?: (message: string) => void;
}

export interface CloudPluginDefinition extends OwnAuthPluginDefinition {
  readonly __ownAuthCloud: Readonly<CloudPluginOptions>;
}

export interface CloudClientOptions {
  autoSolveChallenge?: boolean;
  maximumSolveMs?: number;
}

export interface CloudClientManifest extends OwnAuthPluginClientManifest {
  readonly __ownAuthCloudClient: Readonly<Required<CloudClientOptions>>;
}

export interface FlushCloudOutboxInput {
  limit?: number;
  signal?: AbortSignal;
}

export interface FlushCloudOutboxResult {
  sent: number;
  failed: number;
  remaining: number;
}

export interface ClearCloudOutboxInput {
  includePriority?: boolean;
}

export interface CloudBackfillInput {
  batchSize?: number;
  cursor?: string;
  signal?: AbortSignal;
  onProgress?: (progress: { sent: number; total: number | null; cursor: string | null }) => void;
}

export interface CloudBackfillResult {
  sent: number;
  cursor: string | null;
  complete: boolean;
}

export interface CloudChallenge {
  algorithm: "sha256-preimage";
  difficulty: number;
  expiresAt: number;
  bindingHash: string;
  nonce: string;
}

export interface CloudChallengePayload {
  token: string;
  algorithm: CloudChallenge["algorithm"];
  difficulty: number;
  expiresAt: number;
}

export interface CloudSecurityDecision {
  decision: "allow" | "challenge" | "deny";
  reason?: "credential_stuffing" | "bot" | "impossible_travel" | "ip_reputation";
  difficulty?: number;
  recommendedDifficulty?: number;
  cacheTtlMs?: number;
}

export interface CloudOperationContext {
  operation: string;
  input: unknown;
  userId?: string;
  result?: unknown;
  error?: unknown;
  request: RequestContext;
}

export interface CloudCommandPayload {
  action: "user.disable" | "user.enable" | "user.revoke-sessions";
  userId: string;
  initiatedBy: string;
  reason: string;
}

export interface CloudCommandResult {
  success: boolean;
  action: CloudCommandPayload["action"];
  userId: string;
  errorCode?: string;
  statusCode?: number;
}

export interface CloudChallengeResponsePayload {
  error: {
    code: "cloud_challenge_required";
    message: string;
  };
  challenge: CloudChallengePayload;
}
