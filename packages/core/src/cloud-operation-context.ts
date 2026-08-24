import { normalizeEmail, normalizePhone } from "./normalise.js";
import type { AuthStorage } from "./storage.js";
import { isRecord } from "./value-guards.js";

export async function resolveCloudOperationUserId(
  storage: AuthStorage,
  operation: string,
  input: unknown
): Promise<string | undefined> {
  if (!isRecord(input)) return undefined;
  if (typeof input.userId === "string") return input.userId;
  if (typeof input.actorUserId === "string") return input.actorUserId;
  if (operation === "signInEmailPassword" && typeof input.email === "string") {
    return (await storage.getUserByEmail(normalizeEmail(input.email)))?.id;
  }
  if (operation === "verifySmsOtp" && typeof input.phone === "string") {
    return (await storage.getUserByPhone(normalizePhone(input.phone)))?.id;
  }
  return undefined;
}
