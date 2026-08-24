import {
  metrics,
  SpanKind,
  SpanStatusCode,
  trace,
  type Attributes,
  type Span
} from "@opentelemetry/api";
import { isAuthError } from "./errors.js";
import { OWN_AUTH_VERSION } from "./version.js";

const instrumentationName = "own-auth";
const tracer = trace.getTracer(instrumentationName, OWN_AUTH_VERSION);
const meter = metrics.getMeter(instrumentationName, OWN_AUTH_VERSION);

const operationCount = meter.createCounter("own_auth.operation.count", {
  description: "Completed Own Auth operations",
  unit: "{operation}"
});
const operationDuration = meter.createHistogram("own_auth.operation.duration", {
  description: "Duration of Own Auth operations",
  unit: "s"
});
const deliveryCount = meter.createCounter("own_auth.delivery.count", {
  description: "Completed Own Auth email and SMS deliveries",
  unit: "{delivery}"
});
const deliveryDuration = meter.createHistogram("own_auth.delivery.duration", {
  description: "Duration of Own Auth email and SMS deliveries",
  unit: "s"
});
const rateLimitDenialCount = meter.createCounter("own_auth.rate_limit.denial.count", {
  description: "Own Auth operations denied by rate limiting",
  unit: "{denial}"
});
const webhookDeliveryCount = meter.createCounter("own_auth.webhook.delivery.count", {
  description: "Completed Own Auth webhook delivery attempts",
  unit: "{attempt}"
});
const webhookDeliveryDuration = meter.createHistogram("own_auth.webhook.delivery.duration", {
  description: "Duration of Own Auth webhook delivery attempts",
  unit: "s"
});
const webhookRetryDelay = meter.createHistogram("own_auth.webhook.retry.delay", {
  description: "Scheduled delay before an Own Auth webhook retry",
  unit: "s"
});
const dpopVerificationFailureCount = meter.createCounter(
  "own_auth.dpop.verification.failure.count",
  {
    description: "Rejected Own Auth DPoP proofs",
    unit: "{failure}"
  }
);

const emailDeliveryTypes = new Set([
  "email_verification",
  "magic_link",
  "organisation_invite",
  "password_reset"
]);
const smsDeliveryTypes = new Set([
  "account_recovery",
  "phone_login",
  "phone_verification"
]);
const rateLimitBuckets = new Set([
  "administration",
  "api-key-create",
  "change-password",
  "email-verification",
  "magic-link",
  "oauth-callback",
  "oauth-start",
  "one-tap-start",
  "one-tap-verify",
  "organisation-invite",
  "password-reset",
  "saml-acs",
  "saml-start",
  "signin",
  "signup"
]);

type DeliveryChannel = "email" | "sms";
type OAuthProviderOperation =
  | "authorization"
  | "exchange"
  | "refresh"
  | "revoke"
  | "verify_credential";

export function traceAuthOperation<Result>(
  operation: string,
  work: () => Promise<Result>
): Promise<Result> {
  const attributes = { "own_auth.operation.name": operation };
  return runSpan(
    `own-auth.operation ${operation}`,
    attributes,
    work,
    (outcome, durationSeconds) => {
      const metricAttributes = { ...attributes, "own_auth.operation.outcome": outcome };
      safely(() => operationCount.add(1, metricAttributes));
      safely(() => operationDuration.record(durationSeconds, metricAttributes));
    }
  );
}

export function traceHttpEndpoint<Result extends { status: number }>(
  input: { endpointId: string; method: string; route: string },
  work: () => Promise<Result>
): Promise<Result> {
  return runSpan(
    `own-auth.http ${input.endpointId}`,
    {
      "http.request.method": input.method,
      "http.route": input.route,
      "own_auth.endpoint.id": input.endpointId
    },
    work,
    (_outcome, _durationSeconds, span, result) => {
      if (!result) return;
      safely(() => span.setAttribute("http.response.status_code", result.status));
      safely(() => span.setAttribute("own_auth.http.outcome", httpOutcome(result.status)));
      if (result.status >= 500) markSpanError(span, "internal_error");
    }
  );
}

export function tracePluginOperation<Result>(
  input: { pluginId: string; operation: string; kind: "endpoint" | "method" },
  work: () => Promise<Result>
): Promise<Result> {
  return runSpan("own-auth.plugin", {
    "own_auth.plugin.id": input.pluginId,
    "own_auth.plugin.kind": input.kind,
    "own_auth.plugin.operation": input.operation
  }, work);
}

export function traceDelivery<Result>(
  channel: DeliveryChannel,
  type: string,
  work: () => Promise<Result>
): Promise<Result> {
  const attributes = {
    "own_auth.delivery.channel": channel,
    "own_auth.delivery.type": safeDeliveryType(channel, type)
  };
  return runSpan(
    `own-auth.delivery ${channel}`,
    attributes,
    work,
    (outcome, durationSeconds) => {
      const metricAttributes = { ...attributes, "own_auth.delivery.outcome": outcome };
      safely(() => deliveryCount.add(1, metricAttributes));
      safely(() => deliveryDuration.record(durationSeconds, metricAttributes));
    }
  );
}

export function traceOAuthProvider<Result>(
  provider: "apple" | "github" | "google",
  operation: OAuthProviderOperation,
  work: () => Promise<Result>
): Promise<Result> {
  return runSpan("own-auth.oauth.provider", {
    "own_auth.oauth.provider": provider,
    "own_auth.oauth.operation": operation
  }, work);
}

export function traceWebhookDelivery<Result extends {
  status: "delivered" | "failed" | "pending";
  errorCode: string | null;
  finishedAt: Date;
  nextAttemptAt: Date;
}>(
  endpointId: string,
  eventType: string,
  attempt: number,
  work: () => Promise<Result>
): Promise<Result> {
  const attributes = {
    "own_auth.webhook.endpoint.id": endpointId,
    "own_auth.webhook.event.type": eventType,
    "own_auth.webhook.attempt": attempt
  };
  return runSpan(
    "own-auth.webhook.deliver",
    attributes,
    work,
    (_outcome, durationSeconds, span, result) => {
      if (!result) return;
      const outcome = result.status === "pending" ? "retry_scheduled" : result.status;
      const metricAttributes = { ...attributes, "own_auth.webhook.outcome": outcome };
      safely(() => span.setAttribute("own_auth.webhook.outcome", outcome));
      safely(() => webhookDeliveryCount.add(1, metricAttributes));
      safely(() => webhookDeliveryDuration.record(durationSeconds, metricAttributes));
      if (result.status === "pending") {
        const delay = Math.max(0, result.nextAttemptAt.getTime() - result.finishedAt.getTime()) / 1_000;
        safely(() => webhookRetryDelay.record(delay, metricAttributes));
      }
      if (result.status === "failed") markSpanError(span, result.errorCode ?? "webhook_failed");
    },
    SpanKind.CLIENT
  );
}

export function recordRateLimitDenial(key: string): void {
  safely(() => rateLimitDenialCount.add(1, {
    "own_auth.rate_limit.bucket": safeRateLimitBucket(key)
  }));
}

export function recordDpopVerificationFailure(
  reason:
    | "algorithm_unsupported"
    | "disabled"
    | "expired"
    | "malformed"
    | "method_mismatch"
    | "missing"
    | "replayed"
    | "signature_invalid"
    | "thumbprint_mismatch"
    | "token_hash_mismatch"
    | "unexpected"
    | "url_mismatch"
): void {
  safely(() => dpopVerificationFailureCount.add(1, {
    "own_auth.dpop.failure.reason": reason
  }));
}

function runSpan<Result>(
  name: string,
  attributes: Attributes,
  work: () => Promise<Result>,
  completed?: (
    outcome: "error" | "success",
    durationSeconds: number,
    span: Span,
    result?: Result
  ) => void,
  kind: SpanKind = SpanKind.INTERNAL
): Promise<Result> {
  let callbackStarted = false;
  try {
    return tracer.startActiveSpan(
      name,
      { kind, attributes },
      async (span) => {
        callbackStarted = true;
        const startedAt = Date.now();
        try {
          const result = await work();
          safely(() => completed?.("success", elapsedSeconds(startedAt), span, result));
          return result;
        } catch (error) {
          markSpanError(span, safeErrorType(error));
          safely(() => completed?.("error", elapsedSeconds(startedAt), span));
          throw error;
        } finally {
          safely(() => span.end());
        }
      }
    );
  } catch (error) {
    if (!callbackStarted) return work();
    throw error;
  }
}

function markSpanError(span: Span, type: string): void {
  safely(() => span.setAttribute("error.type", type));
  safely(() => span.setStatus({ code: SpanStatusCode.ERROR }));
}

function safeErrorType(error: unknown): string {
  return isAuthError(error) ? error.code : "internal_error";
}

function safeDeliveryType(channel: DeliveryChannel, type: string): string {
  const allowed = channel === "email" ? emailDeliveryTypes : smsDeliveryTypes;
  return allowed.has(type) ? type : "other";
}

function safeRateLimitBucket(key: string): string {
  const bucket = key.split(":", 1)[0] ?? "";
  if (rateLimitBuckets.has(bucket)) return bucket;
  if (/^external-(apple|github|google)$/.test(bucket)) return bucket;
  if (/^sms-(verify-)?(account_recovery|phone_login|phone_verification)$/.test(bucket)) {
    return bucket;
  }
  return bucket === "plugin" ? bucket : "other";
}

function httpOutcome(status: number): "client_error" | "server_error" | "success" {
  if (status >= 500) return "server_error";
  if (status >= 400) return "client_error";
  return "success";
}

function elapsedSeconds(startedAt: number): number {
  return Math.max(0, Date.now() - startedAt) / 1_000;
}

function safely(work: () => void): void {
  try {
    work();
  } catch {
    // Telemetry must never change authentication behavior.
  }
}
