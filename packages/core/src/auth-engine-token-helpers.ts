import { AuthError } from "./errors.js";
import {
  createId,
  hashPassword,
  hashSecret,
  randomBase64Url
} from "./crypto.js";
import { isExpired } from "./normalise.js";
import type { AuthToken, TokenType } from "./types.js";
import type { DeliveryResult } from "./auth-engine-types.js";
import type { AuthEngineContext } from "./auth-engine-context.js";

export async function issueToken(
  ctx: AuthEngineContext,
  type: TokenType,
  input: {
    userId: string | null;
    email?: string | null;
    phone?: string | null;
    organisationId?: string | null;
    ttlMs: number;
  }
): Promise<{ rawToken: string; token: AuthToken }> {
  const rawToken = randomBase64Url(32);
  const now = new Date();
  const token = await ctx.storage.createToken({
    id: createId("tok"),
    tokenHash: hash(ctx, rawToken),
    type,
    userId: input.userId,
    email: input.email ?? null,
    phone: input.phone ?? null,
    organisationId: input.organisationId ?? null,
    expiresAt: new Date(now.getTime() + input.ttlMs),
    usedAt: null,
    createdAt: now
  });

  return { rawToken, token };
}

export async function consumeToken(
  ctx: AuthEngineContext,
  rawToken: string,
  type: TokenType
): Promise<AuthToken> {
  const token = await getUsableToken(ctx, rawToken, type);

  const updatedToken = await ctx.storage.updateToken(token.id, {
    usedAt: new Date()
  });

  return updatedToken ?? token;
}

export async function getUsableToken(
  ctx: AuthEngineContext,
  rawToken: string,
  type: TokenType
): Promise<AuthToken> {
  const token = await ctx.storage.getTokenByHash(hash(ctx, rawToken), type);

  if (!token) {
    throw new AuthError("invalid_token", "Invalid token", 401);
  }

  if (token.usedAt) {
    throw new AuthError("token_already_used", "Token has already been used", 401);
  }

  if (isExpired(token.expiresAt)) {
    throw new AuthError("expired_token", "Token has expired", 401);
  }

  return token;
}

export async function hashPasswordInput(
  ctx: AuthEngineContext,
  password: string
): Promise<string> {
  if (password.length < ctx.passwordMinLength) {
    throw new AuthError(
      "weak_password",
      `Password must be at least ${ctx.passwordMinLength} characters`,
      400
    );
  }

  return hashPassword(password);
}

export function hash(ctx: AuthEngineContext, value: string): string {
  return hashSecret(value, ctx.tokenPepper);
}

export function delivery(
  ctx: AuthEngineContext,
  token: string,
  url: string,
  expiresAt: Date
): DeliveryResult {
  const result: DeliveryResult = { sent: true, expiresAt };
  if (ctx.exposeRawTokens) {
    result.token = token;
    result.url = url;
  }

  return result;
}

export function buildUrl(
  ctx: AuthEngineContext,
  pathname: string,
  params: Record<string, string | undefined>
): string {
  const url = new URL(pathname, ctx.baseUrl);

  for (const [key, value] of Object.entries(params)) {
    if (value) {
      url.searchParams.set(key, value);
    }
  }

  return url.toString();
}

export function assertRedirectAllowed(ctx: AuthEngineContext, redirectUrl?: string): void {
  if (!redirectUrl) {
    return;
  }

  if (redirectUrl.startsWith("/")) {
    return;
  }

  const parsed = new URL(redirectUrl);
  const allowed = ctx.redirectAllowlist.some((allowedUrl) => {
    const allowedParsed = new URL(allowedUrl);
    return parsed.origin === allowedParsed.origin;
  });

  if (!allowed) {
    throw new AuthError("redirect_not_allowed", "Redirect URL is not allowed", 400);
  }
}

export function extractApiKeyPrefix(rawKey: string): string | null {
  const [namespace, prefix] = rawKey.split("_");

  if (namespace !== "oa" || !prefix) {
    return null;
  }

  return prefix;
}
