import type { OwnAuthErrorPayload, OwnAuthHttpErrorCode } from "./http/contract.js";

export class OwnAuthClientError extends Error {
  readonly code: OwnAuthHttpErrorCode;
  readonly status: number;

  constructor(code: OwnAuthHttpErrorCode, message: string, status: number) {
    super(message);
    this.name = "OwnAuthClientError";
    this.code = code;
    this.status = status;
  }
}

export async function readJsonResponse(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    throw new OwnAuthClientError(
      "internal_error",
      "Own Auth returned an invalid response",
      response.status
    );
  }
}

export function clientErrorFromResponse(body: unknown, status: number): OwnAuthClientError {
  if (isErrorPayload(body)) {
    return new OwnAuthClientError(body.error.code, body.error.message, status);
  }
  return new OwnAuthClientError("internal_error", "Authentication request failed", status);
}

export function clientErrorFromUnknown(error: unknown): OwnAuthClientError {
  return error instanceof OwnAuthClientError
    ? error
    : new OwnAuthClientError(
        "internal_error",
        "Authentication request failed",
        0
      );
}

export async function requestJson(
  fetchImpl: typeof globalThis.fetch,
  input: string | URL | Request,
  init?: RequestInit
): Promise<{ body: unknown; response: Response }> {
  let response: Response;
  try {
    response = await fetchImpl(input, init);
  } catch (error) {
    throw clientErrorFromUnknown(error);
  }

  const body = await readJsonResponse(response);
  if (!response.ok) {
    throw clientErrorFromResponse(body, response.status);
  }
  return { body, response };
}

function isErrorPayload(value: unknown): value is OwnAuthErrorPayload {
  if (!value || typeof value !== "object" || !("error" in value)) {
    return false;
  }
  const error = (value as { error?: unknown }).error;
  return Boolean(
    error &&
    typeof error === "object" &&
    "code" in error &&
    typeof error.code === "string" &&
    "message" in error &&
    typeof error.message === "string"
  );
}
