import type { AuthEngineContext } from "./auth-engine-context.js";
import type { DeliveryResult } from "./auth-engine-types.js";
import { CloudDeliveryFailure } from "./cloud-errors.js";
import type { EmailMessage, SmsMessage } from "./providers.js";
import { traceDelivery } from "./telemetry.js";

export function sendEmail(ctx: AuthEngineContext, message: EmailMessage): Promise<void> {
  return traceDelivery("email", message.type, () => ctx.emailProvider.send(message));
}

export function sendSms(ctx: AuthEngineContext, message: SmsMessage): Promise<void> {
  return traceDelivery("sms", message.purpose, () => ctx.smsProvider.send(message));
}

export async function captureCloudDeliveryFailure(
  deliver: () => Promise<void>
): Promise<DeliveryResult["delivery"]["reason"] | undefined> {
  try {
    await deliver();
    return undefined;
  } catch (error) {
    if (!(error instanceof CloudDeliveryFailure)) throw error;
    return error.delivery.code;
  }
}

export function createDeliveryResult(
  expiresAt: Date,
  failureReason?: DeliveryResult["delivery"]["reason"]
): DeliveryResult {
  return failureReason
    ? {
        sent: false,
        expiresAt,
        delivery: { status: "failed", reason: failureReason }
      }
    : { sent: true, expiresAt, delivery: { status: "sent" } };
}
