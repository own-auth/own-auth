import type { TokenType } from "./types.js";

export interface EmailMessage {
  to: string;
  recipientUserId?: string;
  type: Exclude<TokenType, "phone_verification">;
  token: string;
  url: string;
  expiresAt: Date;
}

export interface EmailProvider {
  send(message: EmailMessage): Promise<void>;
}

export interface SmsMessage {
  to: string;
  recipientUserId?: string;
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
