import { sha256 } from "@noble/hashes/sha256.js";
import { hasLeadingZeroBits } from "./cloud-challenge-algorithm.js";

interface SolveRequest {
  nonce: string;
  difficulty: number;
  deadline: number;
}

interface WorkerScope {
  onmessage: ((event: { data: SolveRequest }) => void) | null;
  postMessage(value: { solution?: string; timedOut?: true }): void;
}

const scope = globalThis as unknown as WorkerScope;

scope.onmessage = ({ data }) => {
  const encoder = new TextEncoder();
  for (let candidate = 0; Date.now() < data.deadline; candidate += 1) {
    const solution = candidate.toString(36);
    if (hasLeadingZeroBits(sha256(encoder.encode(`${data.nonce}${solution}`)), data.difficulty)) {
      scope.postMessage({ solution });
      return;
    }
  }
  scope.postMessage({ timedOut: true });
};
