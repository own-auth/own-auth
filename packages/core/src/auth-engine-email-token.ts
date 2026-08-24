import { randomBase64Url } from "./crypto.js";
import type { AuditEventType, RequestContext, TokenType } from "./types.js";
import type { DeliveryResult } from "./auth-engine-types.js";
import {
  captureCloudDeliveryFailure,
  createDeliveryResult,
  sendEmail
} from "./auth-engine-delivery.js";
import {
  audit,
  buildUrl,
  delivery,
  issueToken,
  rateLimit,
  requireValidEmail,
  type AuthEngineContext
} from "./auth-engine-internals.js";

export async function requestEmailToken(
  ctx: AuthEngineContext,
  input: {
    email: string;
    tokenType: TokenType;
    emailType: Exclude<TokenType, "phone_verification">;
    urlPath: string;
    auditEvent: AuditEventType;
    rateLimitKey: string;
    rateLimitMax: number;
    rateLimitWindowMs: number;
    extraUrlParams?: Record<string, string | undefined>;
    allowMissing?: boolean;
    request?: RequestContext;
  }
): Promise<DeliveryResult> {
  const email = requireValidEmail(input.email);
  await rateLimit(ctx, input.rateLimitKey, email, input.rateLimitMax, input.rateLimitWindowMs);

  const user = await ctx.storage.getUserByEmail(email);
  if (!user && !input.allowMissing) {
    const rawToken = randomBase64Url(32);
    const expiresAt = new Date(Date.now() + ctx.tokenTtls[input.tokenType]);
    const url = buildUrl(ctx, input.urlPath, {
      token: rawToken,
      ...input.extraUrlParams
    });
    return delivery(ctx, rawToken, url, expiresAt);
  }

  const issued = await issueToken(ctx, input.tokenType, {
    userId: user?.id ?? null,
    email,
    ttlMs: ctx.tokenTtls[input.tokenType]
  });
  const url = buildUrl(ctx, input.urlPath, {
    token: issued.rawToken,
    ...input.extraUrlParams
  });

  const deliveryFailure = await captureCloudDeliveryFailure(() =>
    sendEmail(ctx, {
      to: email,
      recipientUserId: user?.id,
      type: input.emailType,
      token: issued.rawToken,
      url,
      expiresAt: issued.token.expiresAt
    })
  );

  await audit(ctx, {
    eventType: input.auditEvent,
    actorUserId: user?.id ?? null,
    targetUserId: user?.id ?? null,
    context: input.request
  });

  if (!deliveryFailure) {
    return delivery(ctx, issued.rawToken, url, issued.token.expiresAt);
  }
  const result = createDeliveryResult(issued.token.expiresAt, deliveryFailure);
  if (ctx.exposeRawTokens) {
    result.token = issued.rawToken;
    result.url = url;
  }
  return result;
}
