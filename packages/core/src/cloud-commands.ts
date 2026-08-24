import type { OwnAuth } from "./auth-engine.js";
import { hashSecret, safeEqual } from "./crypto.js";
import { AuthError, isAuthError } from "./errors.js";
import type { CloudStorage } from "./cloud-storage.js";
import type { CloudCommandPayload, CloudCommandResult } from "./cloud-types.js";
import { isRecord } from "./value-guards.js";

const timestampToleranceMs = 5 * 60_000;
const commandLeaseMs = 30_000;
const commandFields = new Set(["action", "userId", "initiatedBy", "reason"]);
const uuidV4Pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface CloudCommandResponse {
  status: number;
  body: CloudCommandResult | { error: string };
  retryAfter?: number;
}

export class CloudCommandHandler {
  constructor(
    private readonly storage: CloudStorage,
    private readonly signingKeys: readonly {
      id: string;
      secret?: string;
      validUntil?: string | Date;
    }[]
  ) {}

  async handle(
    auth: OwnAuth<string, string>,
    request: Request,
    body: string
  ): Promise<CloudCommandResponse> {
    if (!this.signingKeys.some(({ secret }) => Boolean(secret))) {
      return { status: 404, body: { error: "Cloud remote mutations are not configured" } };
    }
    const timestamp = requireHeader(request.headers, "x-ownauth-timestamp");
    const nonce = requireHeader(request.headers, "x-ownauth-nonce");
    const idempotencyKey = requireHeader(request.headers, "x-ownauth-idempotency-key");
    const keyId = requireHeader(request.headers, "x-ownauth-key-id");
    const signature = requireHeader(request.headers, "x-ownauth-signature");
    if (!uuidV4Pattern.test(nonce) || !uuidV4Pattern.test(idempotencyKey)) {
      return { status: 400, body: { error: "Cloud command identifiers are invalid" } };
    }
    const timestampMs = Number(timestamp) * 1_000;
    if (!Number.isFinite(timestampMs) || Math.abs(Date.now() - timestampMs) > timestampToleranceMs) {
      return { status: 401, body: { error: "Cloud command timestamp is invalid" } };
    }
    const canonical = [
      request.method,
      new URL(request.url).pathname,
      timestamp,
      nonce,
      keyId,
      hashSecret(body)
    ].join("\n");
    const signingKey = this.signingKeys.find(({ id, secret, validUntil }) =>
      id === keyId && secret && (!validUntil || new Date(validUntil).getTime() >= Date.now())
    );
    const valid = signingKey?.secret
      ? safeEqual(hashSecret(canonical, signingKey.secret), signature)
      : false;
    if (!valid) return { status: 401, body: { error: "Cloud command signature is invalid" } };

    const payload = parseCommand(body);
    const now = new Date();
    const reservation = await this.storage.reserveCloudCommand({
      idempotencyKey,
      nonce,
      action: payload.action,
      payloadHash: hashSecret(body),
      payload,
      now,
      leaseUntil: new Date(now.getTime() + commandLeaseMs)
    });
    if (reservation.status === "replay") {
      return { status: 400, body: { error: "Cloud command replay was rejected" } };
    }
    if (reservation.status === "in_progress") {
      return {
        status: 503,
        body: { error: "Cloud command is already running" },
        retryAfter: 5
      };
    }
    if (reservation.status === "resolved") {
      return {
        status: reservation.result.statusCode ?? 200,
        body: reservation.result
      };
    }

    try {
      await executeCommand(auth, payload);
      const result = commandResult(payload, true);
      await this.storage.completeCloudCommand(idempotencyKey, "completed", result, new Date());
      return { status: 200, body: result };
    } catch (error) {
      const authError = isAuthError(error) ? error : null;
      const result = commandResult(
        payload,
        false,
        authError?.code,
        authError?.statusCode
      );
      if (authError && authError.statusCode < 500) {
        await this.storage.completeCloudCommand(idempotencyKey, "failed", result, new Date());
        return { status: authError.statusCode, body: result };
      }
      throw error;
    }
  }
}

async function executeCommand(auth: OwnAuth<string, string>, payload: CloudCommandPayload) {
  await auth.executeCloudCommand(payload);
}

function commandResult(
  payload: CloudCommandPayload,
  success: boolean,
  errorCode?: string,
  statusCode?: number
): CloudCommandResult {
  return { success, action: payload.action, userId: payload.userId, errorCode, statusCode };
}

function parseCommand(body: string): CloudCommandPayload {
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch {
    throw invalidCommand();
  }
  if (!isRecord(value)) throw invalidCommand();
  if (Object.keys(value).some((field) => !commandFields.has(field))) throw invalidCommand();
  if (
    !["user.disable", "user.enable", "user.revoke-sessions"].includes(String(value.action)) ||
    !safeCommandValue(value.userId) ||
    !safeCommandValue(value.initiatedBy) ||
    !safeCommandValue(value.reason) ||
    !(value.reason === "manual" || value.reason.startsWith("security:"))
  ) throw invalidCommand();
  return value as unknown as CloudCommandPayload;
}

function safeCommandValue(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 256;
}

function requireHeader(headers: Headers, name: string): string {
  const value = headers.get(name);
  if (!value) throw new AuthError("validation_error", `Missing ${name} header`, 400);
  return value;
}

function invalidCommand(): AuthError {
  return new AuthError("cloud_command_invalid", "Invalid Cloud command", 400);
}
