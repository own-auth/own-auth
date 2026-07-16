import type { AuthEngineContext } from "./auth-engine-context.js";
import {
  assuranceLevelAcr,
  epochSeconds,
  requireAuthorizationServer
} from "./authorization-server-helpers.js";
import { calculateAccessTokenHash } from "./authorization-server-signing.js";
import type {
  AuthorizationClient,
  AuthorizationUserInfo,
  OidcSubject
} from "./authorization-server-types.js";
import { createId, randomBase64Url } from "./crypto.js";
import type { Session, User } from "./types.js";

export async function createAuthorizationIdToken(
  ctx: AuthEngineContext,
  input: {
    client: AuthorizationClient;
    user: User;
    session: Session;
    scopes: readonly string[];
    accessToken: string;
    accessTokenExpiresAt: Date;
    nonce: string | null;
  }
): Promise<string> {
  const { config } = requireAuthorizationServer(ctx);
  const subject = await getOrCreateOidcSubject(ctx, input.user.id);
  const payload = {
    iss: config.issuer,
    sub: subject.subject,
    aud: input.client.clientId,
    iat: epochSeconds(new Date()),
    exp: epochSeconds(input.accessTokenExpiresAt),
    auth_time: epochSeconds(input.session.authenticatedAt),
    acr: assuranceLevelAcr(input.session.assuranceLevel),
    amr: [...input.session.authenticationMethods],
    at_hash: await calculateAccessTokenHash(input.accessToken),
    ...(input.nonce ? { nonce: input.nonce } : {}),
    ...scopedUserClaims(input.user, input.scopes)
  };
  return config.signer.signIdToken(payload);
}

export async function createAuthorizationUserInfo(
  ctx: AuthEngineContext,
  user: User,
  scopes: readonly string[]
): Promise<AuthorizationUserInfo> {
  const subject = await getOrCreateOidcSubject(ctx, user.id);
  return {
    sub: subject.subject,
    ...scopedUserClaims(user, scopes)
  };
}

export async function getOrCreateOidcSubject(
  ctx: AuthEngineContext,
  userId: string
): Promise<OidcSubject> {
  const { storage } = requireAuthorizationServer(ctx);
  const existing = await storage.getOidcSubjectByUserId(userId);
  if (existing) return existing;
  return storage.createOidcSubject({
    id: createId("osub"),
    userId,
    subject: `oa_sub_${randomBase64Url(24)}`,
    createdAt: new Date()
  });
}

function scopedUserClaims(
  user: User,
  scopes: readonly string[]
): Record<string, string | boolean> {
  const claims: Record<string, string | boolean> = {};
  if (scopes.includes("profile")) {
    if (user.name) claims.name = user.name;
    if (user.imageUrl) claims.picture = user.imageUrl;
  }
  if (scopes.includes("email") && user.email) {
    claims.email = user.email;
    claims.email_verified = Boolean(user.emailVerifiedAt);
  }
  if (scopes.includes("phone") && user.phone) {
    claims.phone_number = user.phone;
    claims.phone_number_verified = Boolean(user.phoneVerifiedAt);
  }
  return claims;
}
