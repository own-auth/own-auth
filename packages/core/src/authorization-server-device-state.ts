import type {
  DeviceAuthorization,
  DeviceAuthorizationDecisionResult,
  DeviceAuthorizationPollResult
} from "./authorization-server-device-types.js";

type DeviceDecisionFailure = Extract<
  DeviceAuthorizationDecisionResult,
  { status: "already_decided" | "invalid" }
>;

export function deviceDecisionState(
  authorization: DeviceAuthorization | null,
  at: Date
): DeviceDecisionFailure | null {
  if (!authorization || authorization.expiresAt.getTime() <= at.getTime()) {
    return { status: "invalid" };
  }
  return authorization.status === "pending"
    ? null
    : { status: "already_decided" };
}

export function terminalDevicePollState(
  authorization: DeviceAuthorization,
  at: Date
): DeviceAuthorizationPollResult | null {
  if (authorization.expiresAt.getTime() <= at.getTime()) return { status: "expired" };
  if (authorization.status === "denied") return { status: "denied" };
  if (authorization.status === "consumed") return { status: "consumed" };
  if (authorization.status === "approved") {
    return { status: "approved", authorization };
  }
  return null;
}

export function nextDevicePollAt(
  authorization: DeviceAuthorization,
  polledAt: Date,
  intervalSeconds = authorization.pollingIntervalSeconds
): Date {
  return new Date(Math.min(
    authorization.expiresAt.getTime(),
    polledAt.getTime() + intervalSeconds * 1000
  ));
}

export function slowedDevicePolling(
  authorization: DeviceAuthorization,
  polledAt: Date
): { intervalSeconds: number; nextPollAt: Date } {
  const remainingSeconds = Math.max(
    1,
    Math.ceil((authorization.expiresAt.getTime() - polledAt.getTime()) / 1000)
  );
  const intervalSeconds = Math.min(
    authorization.pollingIntervalSeconds + 5,
    remainingSeconds
  );
  return {
    intervalSeconds,
    nextPollAt: nextDevicePollAt(authorization, polledAt, intervalSeconds)
  };
}
