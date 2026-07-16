import type { EmailProvider, SmsProvider } from "./providers.js";
import type { RateLimitStore } from "./rate-limit.js";
import type { AuthStorage } from "./storage.js";
import type { TokenType } from "./types.js";
import type { EncryptionKeyRingOptions } from "./encryption.js";
import type { OAuthOptions } from "./oauth-types.js";
import type {
  OwnAuthPluginDefinition,
  OwnAuthPluginRuntimeOptions
} from "./plugin-types.js";
import type { WebhookOptions } from "./webhook-types.js";
import type { AnyOwnAuthAuthorizationDefinition } from "./authorization.js";
import type { AdministrationOptions } from "./administration.js";
import type { AuthorizationServerOptions } from "./authorization-server-types.js";

export const minute = 60 * 1000;
export const hour = 60 * minute;
export const day = 24 * hour;

export type TokenTtlConfig = Partial<Record<TokenType, number>>;

export interface PasskeyOptions {
  rpId: string;
  rpName: string;
  origins: string[];
  timeoutMs?: number;
}

export interface OwnAuthOptions<
  Authorization extends AnyOwnAuthAuthorizationDefinition = AnyOwnAuthAuthorizationDefinition
> {
  storage?: AuthStorage;
  rateLimitStore?: RateLimitStore;
  emailProvider?: EmailProvider;
  smsProvider?: SmsProvider;
  baseUrl?: string;
  tokenPepper?: string;
  exposeRawTokens?: boolean;
  allowMagicLinkSignup?: boolean;
  allowPhoneSignup?: boolean;
  redirectAllowlist?: readonly string[];
  session?: {
    ttlMs?: number;
    idleTtlMs?: number;
  };
  tokenTtlMs?: TokenTtlConfig;
  sms?: {
    otpTtlMs?: number;
    maxAttempts?: number;
    codeLength?: number;
  };
  password?: {
    minLength?: number;
  };
  encryption?: EncryptionKeyRingOptions;
  oauth?: OAuthOptions;
  mfa?: {
    issuer?: string;
    challengeTtlMs?: number;
    maxAttempts?: number;
    recoveryCodeCount?: number;
  };
  passkeys?: PasskeyOptions;
  webhooks?: WebhookOptions;
  administration?: AdministrationOptions;
  authorizationServer?: AuthorizationServerOptions;
  authorization?: Authorization;
  plugins?: readonly OwnAuthPluginDefinition[];
  pluginRuntime?: OwnAuthPluginRuntimeOptions;
}

export const defaultTokenTtls: Required<TokenTtlConfig> = {
  email_verification: day,
  password_reset: hour,
  magic_link: 15 * minute,
  organisation_invite: 7 * day,
  phone_verification: 10 * minute
};
