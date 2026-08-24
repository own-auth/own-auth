import { sha256 } from "@noble/hashes/sha256.js";
import {
  clientErrorFromResponse,
  clientErrorFromUnknown,
  OwnAuthClientError,
  readJsonResponse
} from "./client-error.js";
import { decodeBase64Url } from "./encoding.js";
import type {
  CloudChallenge,
  CloudChallengePayload,
  CloudChallengeResponsePayload,
  CloudClientOptions
} from "./cloud-types.js";
import { hasLeadingZeroBits } from "./cloud-challenge-algorithm.js";
import { isRecord } from "./value-guards.js";

interface WorkerLike {
  onmessage: ((event: { data: { solution?: string; timedOut?: true } }) => void) | null;
  onerror: ((event: unknown) => void) | null;
  postMessage(value: unknown): void;
  terminate(): void;
}

type WorkerConstructor = new (url: URL, options: { type: "module" }) => WorkerLike;

export class CloudChallengeTimeoutError extends OwnAuthClientError {
  readonly challengeTimeout = true;

  constructor() {
    super("cloud_challenge_required", "Cloud challenge solving timed out", 423);
    this.name = "CloudChallengeTimeoutError";
  }
}

export async function solveCloudChallenge(
  challenge: CloudChallengePayload,
  options: Pick<CloudClientOptions, "maximumSolveMs"> = {}
): Promise<string> {
  const decoded = decodeChallenge(challenge);
  const maximumSolveMs = options.maximumSolveMs ?? 5_000;
  const deadline = Math.min(challenge.expiresAt, Date.now() + maximumSolveMs);
  const solution = await solveInWorker(decoded, deadline)
    ?? await solveCooperatively(decoded, deadline);
  if (!solution) throw new CloudChallengeTimeoutError();
  return `${challenge.token}:${solution}`;
}

export async function requestJsonWithCloudChallenge(
  fetchImpl: typeof globalThis.fetch,
  input: string | URL | Request,
  init: RequestInit,
  options: Required<CloudClientOptions> | null
): Promise<{ body: unknown; response: Response }> {
  const first = await fetchResponse(fetchImpl, input, init);
  const firstBody = await readJsonResponse(first);
  if (!first.ok && options?.autoSolveChallenge) {
    let challengedResponse = first;
    let challengedBody = firstBody;
    let challengedInit = init;
    if (isCloudAccessDenied(firstBody, first.status)) {
      const headers = new Headers(init.headers);
      headers.set("x-ownauth-appeal", "1");
      challengedInit = { ...init, headers };
      challengedResponse = await fetchResponse(fetchImpl, input, challengedInit);
      challengedBody = await readJsonResponse(challengedResponse);
    }
    const challenge = challengedResponse.status === 423
      ? challengeFromResponse(challengedBody)
      : null;
    if (challenge) {
      const headers = new Headers(challengedInit.headers);
      headers.set(
        "x-ownauth-challenge-response",
        await solveCloudChallenge(challenge, options)
      );
      const retry = await fetchResponse(fetchImpl, input, { ...init, headers });
      const retryBody = await readJsonResponse(retry);
      if (!retry.ok) throw clientErrorFromResponse(retryBody, retry.status);
      return { body: retryBody, response: retry };
    }
    if (challengedResponse !== first) {
      throw clientErrorFromResponse(challengedBody, challengedResponse.status);
    }
  }
  if (!first.ok) throw clientErrorFromResponse(firstBody, first.status);
  return { body: firstBody, response: first };
}

function isCloudAccessDenied(value: unknown, status: number): boolean {
  return status === 403 && isRecord(value) && isRecord(value.error) &&
    value.error.code === "cloud_access_denied";
}

async function fetchResponse(
  fetchImpl: typeof globalThis.fetch,
  input: string | URL | Request,
  init: RequestInit
): Promise<Response> {
  try {
    return await fetchImpl(input, init);
  } catch (error) {
    throw clientErrorFromUnknown(error);
  }
}

function challengeFromResponse(value: unknown): CloudChallengePayload | null {
  if (!isRecord(value) || !isRecord(value.error) || !isRecord(value.challenge)) return null;
  if (value.error.code !== "cloud_challenge_required") return null;
  const challenge = value.challenge as unknown as Partial<CloudChallengePayload>;
  return typeof challenge.token === "string" &&
    challenge.algorithm === "sha256-preimage" &&
    typeof challenge.difficulty === "number" &&
    typeof challenge.expiresAt === "number"
    ? challenge as CloudChallengePayload
    : null;
}

function decodeChallenge(challenge: CloudChallengePayload): CloudChallenge {
  const encoded = challenge.token.split(".", 1)[0];
  if (!encoded) throw new OwnAuthClientError("cloud_challenge_invalid", "Invalid Cloud challenge", 423);
  try {
    const decoded = JSON.parse(new TextDecoder().decode(decodeBase64Url(encoded))) as CloudChallenge;
    if (
      decoded.algorithm !== challenge.algorithm ||
      decoded.difficulty !== challenge.difficulty ||
      decoded.expiresAt !== challenge.expiresAt ||
      typeof decoded.nonce !== "string"
    ) throw new Error("mismatch");
    return decoded;
  } catch {
    throw new OwnAuthClientError("cloud_challenge_invalid", "Invalid Cloud challenge", 423);
  }
}

function solveInWorker(challenge: CloudChallenge, deadline: number): Promise<string | null> | null {
  const WorkerClass = (globalThis as { Worker?: WorkerConstructor }).Worker;
  if (!WorkerClass) return null;
  let worker: WorkerLike;
  try {
    worker = new WorkerClass(
      new URL("./cloud-challenge-worker.js", import.meta.url),
      { type: "module" }
    );
  } catch {
    return null;
  }
  return new Promise((resolve) => {
    let settled = false;
    const timeout = setTimeout(() => finish(null), Math.max(0, deadline - Date.now()));
    const finish = (solution: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      worker.terminate();
      resolve(solution);
    };
    worker.onmessage = ({ data }) => finish(data.solution ?? null);
    worker.onerror = () => finish(null);
    worker.postMessage({
      nonce: challenge.nonce,
      difficulty: challenge.difficulty,
      deadline
    });
  });
}

async function solveCooperatively(
  challenge: CloudChallenge,
  deadline: number
): Promise<string | null> {
  const encoder = new TextEncoder();
  for (let candidate = 0; Date.now() < deadline; candidate += 1) {
    const solution = candidate.toString(36);
    if (hasLeadingZeroBits(
      sha256(encoder.encode(`${challenge.nonce}${solution}`)),
      challenge.difficulty
    )) return solution;
    if (candidate % 2_048 === 0) await new Promise((resolve) => setTimeout(resolve, 0));
  }
  return null;
}

export type { CloudChallengeResponsePayload };
