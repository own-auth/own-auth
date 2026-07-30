import { AuthError } from "./errors.js";
import {
  AppleOAuthAdapter,
  GitHubOAuthAdapter,
  GoogleOAuthAdapter
} from "./oauth-providers.js";
import type { OAuthOptions, OAuthProviderAdapter } from "./oauth-types.js";
import type { ExternalAccountProvider } from "./types.js";

export function createOAuthProviderRegistry(
  options?: OAuthOptions
): ReadonlyMap<ExternalAccountProvider, OAuthProviderAdapter> {
  const providers = new Map<ExternalAccountProvider, OAuthProviderAdapter>();
  const fetchImpl = options?.fetch;
  const configured = options?.providers;
  if (configured?.google) {
    providers.set("google", new GoogleOAuthAdapter(configured.google, fetchImpl));
  }
  if (configured?.github) {
    providers.set("github", new GitHubOAuthAdapter(configured.github, fetchImpl));
  }
  if (configured?.apple) {
    providers.set("apple", new AppleOAuthAdapter(configured.apple, fetchImpl));
  }
  for (const adapter of options?.adapters ?? []) {
    if (providers.has(adapter.provider)) {
      throw new Error(`OAuth provider is configured more than once: ${adapter.provider}`);
    }
    providers.set(adapter.provider, adapter);
  }
  return providers;
}

export function requireOAuthProvider(
  providers: ReadonlyMap<ExternalAccountProvider, OAuthProviderAdapter>,
  provider: ExternalAccountProvider
): OAuthProviderAdapter {
  const adapter = providers.get(provider);
  if (!adapter) {
    throw new AuthError("validation_error", `OAuth provider is not configured: ${provider}`, 400);
  }
  return adapter;
}
