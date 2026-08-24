import { AuthError } from "./errors.js";
import type { CloudChallengePayload, CloudDeliveryError } from "./cloud-types.js";

export class CloudChallengeError extends AuthError {
  readonly challenge: CloudChallengePayload;

  constructor(challenge: CloudChallengePayload) {
    super("cloud_challenge_required", "Additional verification is required", 423);
    this.name = "CloudChallengeError";
    this.challenge = challenge;
  }
}

export class CloudDeliveryFailure extends Error {
  constructor(readonly delivery: CloudDeliveryError) {
    super(`Own Auth Cloud ${delivery.channel} delivery failed: ${delivery.code}`);
    this.name = "CloudDeliveryFailure";
  }
}

export class CloudHttpError extends Error {
  constructor(readonly status: number, readonly code?: string) {
    super(`Own Auth Cloud returned status ${status}`);
    this.name = "CloudHttpError";
  }
}
