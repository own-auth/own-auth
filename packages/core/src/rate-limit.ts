import { AuthError } from "./errors.js";
import { recordRateLimitDenial } from "./telemetry.js";
import type { UserErasureSubject } from "./user-erasure.js";
import { erasureLookupIdentifiers } from "./user-erasure-subject.js";

export interface RateLimitResult {
  count: number;
  resetAt: Date;
  allowed: boolean;
}

export interface RateLimitStore {
  eraseUser?(subject: Readonly<UserErasureSubject>): Promise<void>;
  /** Atomically increments a bucket and returns the count after this hit. */
  hit(key: string, windowMs: number, limit: number, ownerUserId?: string): Promise<RateLimitResult>;
  reset(key: string): Promise<void>;
}

interface Bucket {
  ownerUserId?: string;
  count: number;
  resetAt: Date;
}

export class InMemoryRateLimitStore implements RateLimitStore {
  constructor(private readonly ownerExists?: (userId: string) => boolean) {}
  async eraseUser(subject: Readonly<UserErasureSubject>): Promise<void> {
    const identifiers = erasureLookupIdentifiers(subject);
    for (const key of this.buckets.keys()) {
      const owner = this.buckets.get(key)?.ownerUserId;
      if (owner === subject.userId || (!owner && identifiers.some((id) => key.endsWith(`:${id}`)))) this.buckets.delete(key);
    }
  }
  private readonly buckets = new Map<string, Bucket>();

  async hit(key: string, windowMs: number, limit: number, ownerUserId?: string): Promise<RateLimitResult> {
    if (ownerUserId && this.ownerExists && !this.ownerExists(ownerUserId)) {
      throw new AuthError("invalid_credentials", "Authentication request is no longer valid", 401);
    }
    const now = Date.now();
    const existing = this.buckets.get(key);

    if (!existing || existing.resetAt.getTime() <= now) {
      const bucket = {
        ownerUserId,
        count: 1,
        resetAt: new Date(now + windowMs)
      };
      this.buckets.set(key, bucket);
      const timer = setTimeout(() => {
        if (this.buckets.get(key) === bucket) this.buckets.delete(key);
      }, windowMs);
      timer.unref?.();
      return {
        count: bucket.count,
        resetAt: new Date(bucket.resetAt.getTime()),
        allowed: true
      };
    }

    existing.count += 1;
    this.buckets.set(key, existing);

    return {
      count: existing.count,
      resetAt: new Date(existing.resetAt.getTime()),
      allowed: existing.count <= limit
    };
  }

  async reset(key: string): Promise<void> {
    this.buckets.delete(key);
  }
}

export async function enforceRateLimit(
  store: RateLimitStore,
  options: {
    key: string;
    limit: number;
    windowMs: number;
    ownerUserId?: string;
  }
): Promise<void> {
  const result = await store.hit(options.key, options.windowMs, options.limit, options.ownerUserId);

  if (!result.allowed) {
    recordRateLimitDenial(options.key);
    throw new AuthError("rate_limited", "Too many attempts. Try again later.", 429);
  }
}
