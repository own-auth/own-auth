import { hashSecret, randomBase64Url, safeEqual } from "./crypto.js";
import { decodeBase64Url, encodeBase64Url } from "./encoding.js";
import { AuthError } from "./errors.js";
import { CloudChallengeError, CloudHttpError } from "./cloud-errors.js";
import { hasLeadingZeroBits } from "./cloud-challenge-algorithm.js";
import type { CloudEventDraft } from "./cloud-events.js";
import type { CloudStorage } from "./cloud-storage.js";
import type {
  CloudChallenge,
  CloudChallengePayload,
  CloudOperationContext,
  CloudPluginOptions,
  CloudSecurityDecision
} from "./cloud-types.js";
import { isRecord } from "./value-guards.js";
import {
  clampCloudDifficulty,
  cloudSignInOperations,
  invalidCloudChallenge,
  isCloudSecurityDecision,
  maximumCloudSecurityCacheAgeMs,
  safeCloudError
} from "./cloud-runtime-helpers.js";

const requestTimeoutMs = 200;
const circuitFailureThreshold = 5;
const circuitResetMs = 30_000;
const challengeLifetimeMs = 30_000;
const previousKeyLifetimeMs = 60_000;

interface ChallengeKeys {
  current: string;
  previous: string | null;
  previousUntil: number | null;
}

interface CloudSecurityDependencies {
  options: Readonly<CloudPluginOptions>;
  storage: CloudStorage;
  appId: string;
  request(path: string, init: RequestInit, timeoutMs: number): Promise<Response>;
  enqueue(draft: CloudEventDraft): Promise<void>;
  warn(message: string): void;
}

export class CloudSecurity {
  private readonly decisionCache = new Map<
    string,
    { decision: CloudSecurityDecision; expiresAt: number }
  >();
  private circuitFailures = 0;
  private circuitOpenUntil = 0;
  private circuitProbe: Promise<CloudSecurityDecision> | null = null;

  constructor(private readonly dependencies: CloudSecurityDependencies) {}

  async beforeOperation(context: CloudOperationContext): Promise<void> {
    if (!cloudSignInOperations.has(context.operation) || !this.enabled()) return;
    if (context.request.cloudChallengeResponse) {
      await this.verifyChallengeResponse(
        context.request.cloudChallengeResponse,
        context.request.ipAddress ?? "",
        context.request.path ?? ""
      );
      return;
    }
    const decision = await this.getDecision(context);
    if (decision.decision === "allow") return;
    const reason = decision.reason ?? "bot";
    if (decision.decision === "deny" && !context.request.cloudAppeal) {
      await this.dependencies.enqueue({
        type: "login.blocked",
        data: { reason },
        context: context.request,
        userId: context.userId
      });
      throw new AuthError("cloud_access_denied", "Authentication request was blocked", 403);
    }
    const difficulty = clampCloudDifficulty(
      Math.max(
        (decision.recommendedDifficulty ?? decision.difficulty ?? 18) +
          (context.request.cloudAppeal ? 4 : 0),
        this.dependencies.options.security?.botDetection?.minimumDifficulty ?? 1
      )
    );
    const challenge = await this.createChallenge(
      difficulty,
      context.request.ipAddress ?? "",
      context.request.path ?? ""
    );
    await this.dependencies.enqueue({
      type: "login.challenged",
      data: { reason, difficulty },
      context: context.request,
      userId: context.userId
    });
    throw new CloudChallengeError(challenge);
  }

  async afterOperation(context: CloudOperationContext): Promise<void> {
    if (!cloudSignInOperations.has(context.operation) || !this.enabled() || context.error) return;
    const ip = context.request.ipAddress;
    const result = isRecord(context.result) ? context.result : null;
    if (!ip || result?.status === "mfa_required") return;
    const user = isRecord(result?.user) ? result.user : null;
    const session = isRecord(result?.session) ? result.session : null;
    const userId = context.userId
      ?? (typeof user?.id === "string" ? user.id : undefined)
      ?? (typeof session?.userId === "string" ? session.userId : undefined);
    if (!userId) return;
    try {
      await this.dependencies.request("/security/observe", {
        method: "POST",
        body: JSON.stringify({ appId: this.dependencies.appId, ip, userId })
      }, requestTimeoutMs);
    } catch (error) {
      this.dependencies.warn(`Own Auth Cloud security observation failed: ${safeCloudError(error)}`);
    }
  }

  async rotateChallengeSecret(): Promise<void> {
    const keys = await this.challengeKeys();
    await this.dependencies.storage.setCloudConfig("challenge_keys", JSON.stringify({
      current: randomBase64Url(32),
      previous: keys.current,
      previousUntil: Date.now() + previousKeyLifetimeMs
    } satisfies ChallengeKeys));
  }

  eraseUser(userId: string): void {
    const marker = `:${userId}:`;
    for (const key of this.decisionCache.keys()) {
      if (key.includes(marker)) this.decisionCache.delete(key);
    }
  }

  private async getDecision(context: CloudOperationContext): Promise<CloudSecurityDecision> {
    const userId = context.userId;
    const ip = context.request.ipAddress;
    const key = ip ? userId ? `${ip}:${userId}:login` : `${ip}:login` : null;
    const cached = key ? this.decisionCache.get(key) : undefined;
    const validCached = cached && cached.expiresAt > Date.now() ? cached : undefined;
    if (cached && !validCached && key) this.decisionCache.delete(key);
    if (this.circuitOpenUntil > Date.now()) {
      return validCached?.decision ?? { decision: "allow" };
    }
    if (this.circuitFailures >= circuitFailureThreshold) {
      if (this.circuitProbe) return validCached?.decision ?? { decision: "allow" };
      this.circuitProbe = this.requestDecision(context, key, validCached);
      try {
        return await this.circuitProbe;
      } finally {
        this.circuitProbe = null;
      }
    }
    return this.requestDecision(context, key, validCached);
  }

  private async requestDecision(
    context: CloudOperationContext,
    key: string | null,
    cached: { decision: CloudSecurityDecision; expiresAt: number } | undefined
  ): Promise<CloudSecurityDecision> {
    const userId = context.userId;
    const requestedAt = Date.now();
    try {
      const response = await this.dependencies.request("/security/check", {
        method: "POST",
        body: JSON.stringify({
          action: "login",
          appId: this.dependencies.appId,
          ip: context.request.ipAddress,
          userAgent: context.request.userAgent,
          userId,
          config: this.dependencies.options.security
        })
      }, requestTimeoutMs);
      const decision = await response.json() as CloudSecurityDecision;
      if (!isCloudSecurityDecision(decision)) {
        throw new Error("Cloud returned an invalid security decision");
      }
      this.circuitFailures = 0;
      this.circuitOpenUntil = 0;
      if (key && decision.decision !== "allow" && (userId || decision.decision !== "deny")) {
        const entry = {
          decision,
          expiresAt: requestedAt + Math.max(0, Math.min(
            decision.cacheTtlMs ?? maximumCloudSecurityCacheAgeMs, maximumCloudSecurityCacheAgeMs
          ))
        };
        if (entry.expiresAt <= Date.now()) return decision;
        this.decisionCache.set(key, entry);
        const timer = setTimeout(() => {
          if (this.decisionCache.get(key) === entry) this.decisionCache.delete(key);
        }, Math.max(0, entry.expiresAt - Date.now()));
        timer.unref?.();
      }
      return decision;
    } catch (error) {
      if (error instanceof CloudHttpError && error.status < 500) throw error;
      if (!(error instanceof CloudHttpError) || error.status >= 500) {
        this.circuitFailures += 1;
        if (this.circuitFailures >= circuitFailureThreshold) {
          this.circuitOpenUntil = Date.now() + circuitResetMs;
        }
      }
      this.dependencies.warn(`Own Auth Cloud security check failed open: ${safeCloudError(error)}`);
      return cached?.decision ?? { decision: "allow" };
    }
  }

  private async createChallenge(
    difficulty: number,
    ip: string,
    path: string
  ): Promise<CloudChallengePayload> {
    const payload: CloudChallenge = {
      algorithm: "sha256-preimage",
      difficulty,
      expiresAt: Date.now() + challengeLifetimeMs,
      bindingHash: hashSecret(`${ip}:${path}`),
      nonce: randomBase64Url(16)
    };
    const encoded = encodeBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
    const keys = await this.challengeKeys();
    return {
      token: `${encoded}.${hashSecret(encoded, keys.current)}`,
      algorithm: payload.algorithm,
      difficulty,
      expiresAt: payload.expiresAt
    };
  }

  private async verifyChallengeResponse(response: string, ip: string, path: string): Promise<void> {
    const separator = response.lastIndexOf(":");
    if (separator < 1) throw invalidCloudChallenge();
    const token = response.slice(0, separator);
    const solution = response.slice(separator + 1);
    const signatureSeparator = token.lastIndexOf(".");
    if (signatureSeparator < 1 || !solution) throw invalidCloudChallenge();
    const encoded = token.slice(0, signatureSeparator);
    const signature = token.slice(signatureSeparator + 1);
    const keys = await this.challengeKeys();
    const secrets = [keys.current];
    if (keys.previous && (keys.previousUntil ?? 0) > Date.now()) secrets.push(keys.previous);
    if (!secrets.some((secret) => safeEqual(hashSecret(encoded, secret), signature))) {
      throw invalidCloudChallenge();
    }
    let challenge: CloudChallenge;
    try {
      challenge = JSON.parse(new TextDecoder().decode(decodeBase64Url(encoded))) as CloudChallenge;
    } catch {
      throw invalidCloudChallenge();
    }
    if (
      challenge.algorithm !== "sha256-preimage" ||
      challenge.expiresAt <= Date.now() ||
      challenge.bindingHash !== hashSecret(`${ip}:${path}`) ||
      !hasLeadingZeroBits(hashSecret(`${challenge.nonce}${solution}`), challenge.difficulty)
    ) throw invalidCloudChallenge();
    if (!await this.dependencies.storage.consumeCloudChallengeNonce(
      challenge.nonce,
      new Date(challenge.expiresAt)
    )) throw invalidCloudChallenge();
  }

  private async challengeKeys(): Promise<ChallengeKeys> {
    if (this.dependencies.options.challengeSecret) {
      return {
        current: this.dependencies.options.challengeSecret,
        previous: null,
        previousUntil: null
      };
    }
    const created: ChallengeKeys = {
      current: randomBase64Url(32),
      previous: null,
      previousUntil: null
    };
    const stored = await this.dependencies.storage.getOrCreateCloudConfig(
      "challenge_keys",
      JSON.stringify(created)
    );
    return JSON.parse(stored) as ChallengeKeys;
  }

  private enabled(): boolean {
    const security = this.dependencies.options.security;
    return Boolean(
      !security?.localOnly && (
        security?.botDetection?.enabled ||
        security?.credentialStuffing?.enabled ||
        security?.impossibleTravel?.enabled
      )
    );
  }
}
