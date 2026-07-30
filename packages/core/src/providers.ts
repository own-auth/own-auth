import { resolveFetchImplementation } from "./fetch-implementation.js";
import type { TokenType } from "./types.js";
import { isRecord } from "./value-guards.js";

export interface EmailMessage {
  to: string;
  type: Exclude<TokenType, "phone_verification">;
  token: string;
  url: string;
  expiresAt: Date;
}

export interface EmailProvider {
  send(message: EmailMessage): Promise<void>;
}

export interface OwnAuthManagedEmailProviderOptions {
  deliveryKey: string;
  endpoint?: string | URL;
  fetch?: typeof fetch;
}

export interface SmsMessage {
  to: string;
  purpose: string;
  code: string;
  expiresAt: Date;
}

export interface SmsProvider {
  send(message: SmsMessage): Promise<void>;
}

export class MemoryEmailProvider implements EmailProvider {
  readonly messages: EmailMessage[] = [];

  async send(message: EmailMessage): Promise<void> {
    this.messages.push(structuredClone(message));
  }
}

export class MemorySmsProvider implements SmsProvider {
  readonly messages: SmsMessage[] = [];

  async send(message: SmsMessage): Promise<void> {
    this.messages.push(structuredClone(message));
  }
}

export class OwnAuthManagedEmailProvider implements EmailProvider {
  private readonly deliveryKey: string;
  private readonly endpoint: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: OwnAuthManagedEmailProviderOptions) {
    if (!options.deliveryKey) {
      throw new Error("Own Auth managed email delivery requires a delivery key.");
    }

    this.deliveryKey = options.deliveryKey;
    this.endpoint = (options.endpoint ?? "https://api.own-auth.com/v1/email").toString();
    const fetchImpl = resolveFetchImplementation(options.fetch);
    if (!fetchImpl) {
      throw new Error("Own Auth managed email delivery requires a Fetch API implementation.");
    }
    this.fetchImpl = fetchImpl;
  }

  async send(message: EmailMessage): Promise<void> {
    const response = await this.fetchImpl(this.endpoint, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.deliveryKey}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        to: message.to,
        type: message.type,
        url: message.url,
        expiresAt: message.expiresAt.toISOString()
      })
    });

    if (!response.ok) {
      const details = await managedDeliveryErrorDetails(response);
      throw new Error(
        `Own Auth managed email delivery failed with status ${response.status}${details}.`
      );
    }
  }
}

async function managedDeliveryErrorDetails(response: Response): Promise<string> {
  const body = await readManagedDeliveryErrorBody(response);
  const error = isRecord(body) ? body.error : undefined;

  if (!isRecord(error)) {
    return "";
  }

  const code = safeManagedDeliveryErrorText(error.code);
  const message = safeManagedDeliveryErrorText(error.message);

  if (code && message) {
    return `: ${code} - ${message}`;
  }

  if (message) {
    return `: ${message}`;
  }

  if (code) {
    return `: ${code}`;
  }

  return "";
}

async function readManagedDeliveryErrorBody(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function safeManagedDeliveryErrorText(value: unknown): string {
  if (typeof value !== "string") {
    return "";
  }

  return value.replace(/[\r\n\t]/g, " ").replace(/\s+/g, " ").trim().slice(0, 240);
}

export class ConsoleEmailProvider implements EmailProvider {
  async send(message: EmailMessage): Promise<void> {
    if (process.env.NODE_ENV === "production") {
      throw new Error("Email delivery must be configured in production.");
    }

    console.info("[own-auth email]", {
      to: message.to,
      type: message.type,
      expiresAt: message.expiresAt.toISOString()
    });
  }
}

export class ConsoleSmsProvider implements SmsProvider {
  async send(message: SmsMessage): Promise<void> {
    if (process.env.NODE_ENV === "production") {
      throw new Error("SMS delivery must be configured in production.");
    }

    console.info("[own-auth sms]", {
      to: message.to,
      purpose: message.purpose,
      expiresAt: message.expiresAt.toISOString()
    });
  }
}
