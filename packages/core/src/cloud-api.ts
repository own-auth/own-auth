import type { OwnAuth } from "./auth-engine.js";
import { AuthError } from "./errors.js";
import type { CloudRuntime } from "./cloud-runtime.js";
import type {
  ClearCloudOutboxInput,
  CloudBackfillInput,
  CloudBackfillResult,
  FlushCloudOutboxInput,
  FlushCloudOutboxResult
} from "./cloud-types.js";

export class OwnAuthCloud {
  constructor(
    private readonly runtime: CloudRuntime | null,
    private readonly auth: () => OwnAuth<string, string>
  ) {}

  isConfigured(): boolean { return this.runtime !== null; }
  backfill(input?: CloudBackfillInput): Promise<CloudBackfillResult> {
    return this.requireRuntime().backfill(input);
  }
  flushOutbox(input?: FlushCloudOutboxInput): Promise<FlushCloudOutboxResult> {
    return this.requireRuntime().flushOutbox(input);
  }
  clearOutbox(input?: ClearCloudOutboxInput): Promise<number> {
    return this.requireRuntime().clearOutbox(input);
  }
  eraseUser(userId: string): Promise<{ eventId: string; removedPendingEvents: number }> {
    return this.requireRuntime().eraseUser(userId);
  }
  rotateChallengeSecret(): Promise<void> {
    return this.requireRuntime().rotateChallengeSecret();
  }
  cleanup(olderThan: Date): Promise<number> {
    return this.requireRuntime().cleanup(olderThan);
  }
  /** @internal */
  handleCommand(request: Request, body: string) {
    return this.requireRuntime().handleCommand(this.auth(), request, body);
  }
  /** @internal */
  get webhookPath(): string | null { return this.runtime?.webhookPath ?? null; }

  private requireRuntime(): CloudRuntime {
    if (!this.runtime) {
      throw new AuthError("cloud_not_configured", "Own Auth Cloud is not configured", 404);
    }
    return this.runtime;
  }
}
