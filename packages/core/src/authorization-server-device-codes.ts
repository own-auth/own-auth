import type { AuthEngineContext } from "./auth-engine-context.js";
import { hashAuthorizationSecret } from "./authorization-server-helpers.js";
import { AuthError } from "./errors.js";

export const deviceUserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ";

const deviceCodeHashDomain = "own-auth:device-code:v1";
const userCodeHashDomain = "own-auth:user-code:v1";

export function createDeviceUserCode(): string {
  const characters: string[] = [];
  while (characters.length < 8) {
    const bytes = new Uint8Array(8);
    crypto.getRandomValues(bytes);
    for (const byte of bytes) {
      if (byte >= 240) continue;
      characters.push(deviceUserCodeAlphabet[byte % deviceUserCodeAlphabet.length]!);
      if (characters.length === 8) break;
    }
  }
  return characters.join("");
}

export function normalizeDeviceUserCode(value: string): string {
  if (typeof value !== "string" || value.length > 64) {
    throw invalidDeviceAuthorization();
  }
  const normalized = value.trim().toUpperCase().replace(/[\t\n\v\f\r -]+/g, "");
  if (
    normalized.length !== 8 ||
    [...normalized].some((character) => !deviceUserCodeAlphabet.includes(character))
  ) {
    throw invalidDeviceAuthorization();
  }
  return normalized;
}

export function formatDeviceUserCode(value: string): string {
  return `${value.slice(0, 4)}-${value.slice(4)}`;
}

export function hashDeviceCode(ctx: AuthEngineContext, value: string): string {
  return hashAuthorizationSecret(ctx, `${deviceCodeHashDomain}:${value}`);
}

export function hashDeviceUserCode(ctx: AuthEngineContext, value: string): string {
  return hashAuthorizationSecret(ctx, `${userCodeHashDomain}:${value}`);
}

export function invalidDeviceAuthorization(): AuthError {
  return new AuthError(
    "device_authorization_invalid",
    "Device authorization is invalid or expired",
    400
  );
}
