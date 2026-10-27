import { AuthError } from "./errors.js";

export function assertIdentityAuthority(expiresAt?: Date): void {
  if (expiresAt && (!Number.isFinite(expiresAt.getTime()) || expiresAt.getTime() <= Date.now())) {
    throw new AuthError("invalid_credentials", "Authentication request is invalid or expired", 401);
  }
}
