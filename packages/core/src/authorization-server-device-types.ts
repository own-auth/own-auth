import type {
  AuthorizationAccessToken,
  AuthorizationClient,
  AuthorizationGrant,
  AuthorizationRefreshToken,
  ProtectedResource
} from "./authorization-server-types.js";
import type { RequestContext, SessionAssuranceLevel } from "./types.js";

export const deviceAuthorizationGrantType =
  "urn:ietf:params:oauth:grant-type:device_code" as const;

export type DeviceAuthorizationStatus =
  | "pending"
  | "approved"
  | "denied"
  | "consumed";

export interface DeviceAuthorization {
  id: string;
  deviceCodeHash: string;
  userCodeHash: string;
  authorizationClientId: string;
  protectedResourceId: string | null;
  requestCiphertext: string;
  requestNonce: string;
  encryptionKeyId: string;
  dpopJkt: string | null;
  status: DeviceAuthorizationStatus;
  userId: string | null;
  sessionId: string | null;
  grantId: string | null;
  approvedScopes: string[];
  pollingIntervalSeconds: number;
  nextPollAt: Date;
  expiresAt: Date;
  approvedAt: Date | null;
  deniedAt: Date | null;
  consumedAt: Date | null;
  createdAt: Date;
}

export interface StoredDeviceAuthorizationRequest {
  scopes: string[];
  resource: string | null;
}

export interface DeviceAuthorizationRequestInput {
  clientId?: string;
  clientSecret?: string;
  clientAuthenticationMethod?: AuthorizationClient["tokenEndpointAuthMethod"];
  scope?: string;
  resource?: string;
  dpopJkt?: string;
  request?: RequestContext;
}

export interface DeviceAuthorizationResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

export interface GetDeviceAuthorizationInput {
  userCode: string;
  sessionToken?: string | null;
  request?: RequestContext;
}

export interface CompleteDeviceAuthorizationInput {
  userCode: string;
  sessionToken: string;
  approvedScopes?: string[];
  request?: RequestContext;
}

export interface DenyDeviceAuthorizationInput {
  userCode: string;
  sessionToken: string;
  request?: RequestContext;
}

export interface PublicDeviceAuthorization {
  action: "sign_in" | "consent" | "continue";
  userCode: string;
  client: Pick<AuthorizationClient, "name" | "applicationType">;
  resource: Pick<ProtectedResource, "name"> | null;
  scopes: Array<{ name: string; label: string; description: string | null }>;
  requiredAssuranceLevel: SessionAssuranceLevel | null;
  expiresAt: Date;
}

export interface CleanupDeviceAuthorizationsInput {
  olderThan: Date;
}

export type DeviceAuthorizationPollResult =
  | { status: "invalid" }
  | { status: "expired" }
  | { status: "denied" }
  | { status: "consumed" }
  | { status: "authorization_pending" }
  | { status: "slow_down" }
  | { status: "approved"; authorization: DeviceAuthorization };

export type DeviceAuthorizationDecisionResult =
  | { status: "approved"; authorization: DeviceAuthorization; grant: AuthorizationGrant }
  | { status: "denied"; authorization: DeviceAuthorization }
  | { status: "already_decided" }
  | { status: "invalid" };

export interface ConsumeDeviceAuthorizationInput {
  id: string;
  deviceCodeHash: string;
  authorizationClientId: string;
  consumedAt: Date;
  accessToken: AuthorizationAccessToken;
  refreshToken: AuthorizationRefreshToken | null;
}
