import { AuthError } from "./errors.js";
import { normalizeEmail } from "./normalise.js";
import type { ExternalAccountProvider, User } from "./types.js";
import {
  minute,
  type SessionResult,
  type SignInWithExternalProviderInput
} from "./auth-engine-types.js";
import {
  accountFor,
  assertUserEnabled,
  audit,
  createSession,
  markUserLoggedIn,
  rateLimit,
  userFor,
  type AuthEngineContext
} from "./auth-engine-internals.js";

const externalProviders = new Set<ExternalAccountProvider>(["apple", "google"]);

export async function signInWithExternalProvider(
  ctx: AuthEngineContext,
  input: SignInWithExternalProviderInput
): Promise<SessionResult> {
  const provider = normalizeExternalProvider(input.provider);
  const providerAccountId = input.providerAccountId.trim();
  if (!providerAccountId) {
    throw new AuthError("validation_error", "providerAccountId is required", 400);
  }

  await rateLimit(ctx, `external-${provider}`, providerAccountId, 20, 10 * minute);

  const account = await ctx.storage.getAccountByProvider(provider, providerAccountId);
  if (account) {
    const user = await ctx.storage.getUserById(account.userId);
    if (!user) {
      throw new AuthError("invalid_credentials", "Invalid external provider account", 401);
    }

    return createExternalProviderSession(ctx, user, input);
  }

  const email = input.email ? normalizeEmail(input.email) : null;
  if (email && input.emailVerified !== true) {
    throw new AuthError("validation_error", "External provider email must be verified", 400);
  }

  const user = email
    ? await findOrCreateExternalUser(ctx, input, email)
    : await createExternalUser(ctx, input, null);
  assertUserEnabled(user);

  await ctx.storage.createAccount(
    accountFor(user.id, provider, providerAccountId, email, null, new Date())
  );
  await audit(ctx, {
    eventType: "external_provider.linked",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request,
    metadata: { provider }
  });

  return createExternalProviderSession(ctx, user, input);
}

function normalizeExternalProvider(provider: string): ExternalAccountProvider {
  if (externalProviders.has(provider as ExternalAccountProvider)) {
    return provider as ExternalAccountProvider;
  }

  throw new AuthError("validation_error", "Unsupported external provider", 400);
}

async function findOrCreateExternalUser(
  ctx: AuthEngineContext,
  input: SignInWithExternalProviderInput,
  email: string
): Promise<User> {
  const existingUser = await ctx.storage.getUserByEmail(email);
  if (existingUser) {
    assertUserEnabled(existingUser);
    if (!existingUser.emailVerifiedAt) {
      return (await ctx.storage.updateUser(existingUser.id, {
        emailVerifiedAt: new Date(),
        updatedAt: new Date()
      })) ?? existingUser;
    }

    return existingUser;
  }

  return createExternalUser(ctx, input, email);
}

async function createExternalUser(
  ctx: AuthEngineContext,
  input: SignInWithExternalProviderInput,
  email: string | null
): Promise<User> {
  const now = new Date();
  const user = await ctx.storage.createUser(
    userFor({
      email,
      emailVerifiedAt: email ? now : null,
      phone: null,
      phoneVerifiedAt: null,
      passwordHash: null,
      name: input.name,
      imageUrl: input.imageUrl,
      metadata: input.metadata
    },
    now
    )
  );

  await audit(ctx, {
    eventType: "user.signed_up",
    actorUserId: user.id,
    targetUserId: user.id,
    context: input.request,
    metadata: { provider: input.provider }
  });

  return user;
}

async function createExternalProviderSession(
  ctx: AuthEngineContext,
  user: User,
  input: SignInWithExternalProviderInput
): Promise<SessionResult> {
  assertUserEnabled(user);
  const activeUser = await markUserLoggedIn(ctx, user);
  const result = await createSession(ctx, activeUser, input.request);

  await audit(ctx, {
    eventType: "user.signed_in",
    actorUserId: activeUser.id,
    targetUserId: activeUser.id,
    context: input.request,
    metadata: { provider: input.provider }
  });

  return result;
}
