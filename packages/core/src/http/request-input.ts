import type { JsonSchema, OwnAuthEndpointDefinition } from "./contract.js";
import { OwnAuthHttpError } from "./errors.js";
import { validateEndpointInput } from "./validation.js";

export async function readEndpointInput(
  request: Request,
  endpoint: Pick<OwnAuthEndpointDefinition, "request" | "requestTransport">,
  maxRequestBodyBytes: number
): Promise<Record<string, unknown> | undefined> {
  if (!endpoint.request) return undefined;

  const transport = endpoint.requestTransport ?? "json";
  if (transport === "query") {
    return validateEndpointInput(endpoint, paramsToRecord(new URL(request.url).searchParams));
  }

  const expectedContentType = transport === "form"
    ? "application/x-www-form-urlencoded"
    : "application/json";
  const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim();
  if (contentType !== expectedContentType) {
    throw new OwnAuthHttpError(
      "invalid_request",
      `Content-Type must be ${expectedContentType}`,
      415
    );
  }

  const text = await readLimitedBody(request, maxRequestBodyBytes);
  if (transport === "form") {
    return validateEndpointInput(endpoint, paramsToRecord(new URLSearchParams(text)));
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new OwnAuthHttpError("invalid_request", "Request body must be valid JSON", 400);
  }
  return validateEndpointInput(endpoint, parsed);
}

export function pluginInputContract(input: JsonSchema | undefined, method: string) {
  return {
    request: input,
    requestTransport: method === "GET" ? "query" as const : "json" as const
  };
}

export async function readLimitedBody(
  request: Request,
  maxBytes: number
): Promise<string> {
  const contentLength = Number(request.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    throw tooLarge();
  }

  if (!request.body) {
    return "";
  }

  const reader = request.body.getReader();
  const decoder = new TextDecoder();
  const chunks: string[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw tooLarge();
      }
      chunks.push(decoder.decode(value, { stream: true }));
    }
    chunks.push(decoder.decode());
    return chunks.join("");
  } finally {
    reader.releaseLock();
  }
}

function paramsToRecord(params: URLSearchParams): Record<string, string | string[]> {
  const value: Record<string, string | string[]> = {};
  for (const [name, entry] of params) {
    const current = value[name];
    if (current === undefined) {
      value[name] = entry;
    } else if (Array.isArray(current)) {
      current.push(entry);
    } else {
      value[name] = [current, entry];
    }
  }
  return value;
}

function tooLarge(): OwnAuthHttpError {
  return new OwnAuthHttpError("invalid_request", "Request body is too large", 413);
}
