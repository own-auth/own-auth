import * as oauth from "oauth4webapi";
import { decodeBase64Url, encodeBase64Url } from "./encoding.js";
import { AuthError, isAuthError } from "./errors.js";
import { resolveFetchImplementation } from "./fetch-implementation.js";
import { verifyRs256Jwt } from "./oauth-jwt.js";
import type {
  AppleOAuthOptions,
  GitHubOAuthOptions,
  GoogleOAuthOptions,
  OAuthAuthorizationRequest,
  OAuthExchangeResult,
  OAuthProviderAdapter,
  OAuthRefreshResult,
  VerifiedProviderIdentity
} from "./oauth-types.js";

type RequestOptions = { [oauth.customFetch]: typeof globalThis.fetch };

const googleServer: oauth.AuthorizationServer = {
  issuer: "https://accounts.google.com",
  authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
  token_endpoint: "https://oauth2.googleapis.com/token",
  revocation_endpoint: "https://oauth2.googleapis.com/revoke",
  jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
  id_token_signing_alg_values_supported: ["RS256"]
};

const githubServer: oauth.AuthorizationServer = {
  issuer: "https://github.com",
  authorization_endpoint: "https://github.com/login/oauth/authorize",
  token_endpoint: "https://github.com/login/oauth/access_token"
};

const appleServer: oauth.AuthorizationServer = {
  issuer: "https://appleid.apple.com",
  authorization_endpoint: "https://appleid.apple.com/auth/authorize",
  token_endpoint: "https://appleid.apple.com/auth/token",
  revocation_endpoint: "https://appleid.apple.com/auth/revoke",
  jwks_uri: "https://appleid.apple.com/auth/keys",
  id_token_signing_alg_values_supported: ["RS256"]
};

abstract class OAuthAdapterBase implements OAuthProviderAdapter {
  abstract readonly provider: OAuthProviderAdapter["provider"];
  abstract readonly redirectUri: string;
  abstract readonly offlineAccess: boolean;
  protected readonly fetchImpl: typeof globalThis.fetch;

  constructor(fetchImpl?: typeof globalThis.fetch) {
    const resolved = resolveFetchImplementation(fetchImpl);
    if (!resolved) {
      throw new Error("OAuth providers require a Fetch API implementation");
    }
    this.fetchImpl = resolved;
  }

  abstract createAuthorizationUrl(input: OAuthAuthorizationRequest): Promise<URL>;
  abstract exchangeCode(input: {
    callbackParameters: URLSearchParams;
    state: string;
    codeVerifier: string;
    nonce: string;
  }): Promise<OAuthExchangeResult>;

  protected requestOptions(): RequestOptions {
    return { [oauth.customFetch]: this.fetchImpl };
  }
}

export class GoogleOAuthAdapter extends OAuthAdapterBase {
  readonly provider = "google" as const;
  readonly redirectUri: string;
  readonly offlineAccess: boolean;
  private readonly options: GoogleOAuthOptions;
  private readonly client: oauth.Client;

  constructor(options: GoogleOAuthOptions, fetchImpl?: typeof globalThis.fetch) {
    super(fetchImpl);
    this.options = options;
    this.redirectUri = options.redirectUri;
    this.offlineAccess = options.offlineAccess ?? false;
    this.client = { client_id: options.clientId, id_token_signed_response_alg: "RS256" };
  }

  async createAuthorizationUrl(input: OAuthAuthorizationRequest): Promise<URL> {
    const url = authorizationUrl(googleServer, this.options, input, ["openid", "email", "profile"]);
    if (this.offlineAccess) {
      url.searchParams.set("access_type", "offline");
      url.searchParams.set("prompt", "consent");
    }
    return url;
  }

  async exchangeCode(input: OAuthCallbackInput): Promise<OAuthExchangeResult> {
    return withProviderErrors(() => exchangeOidcCode({
      provider: "google",
      server: googleServer,
      client: this.client,
      clientAuth: oauth.ClientSecretPost(this.options.clientSecret),
      redirectUri: this.redirectUri,
      callback: input,
      requestOptions: this.requestOptions()
    }));
  }

  async verifyCredential(credential: string, nonce: string): Promise<VerifiedProviderIdentity> {
    const claims = await verifyRs256Jwt({
      token: credential,
      jwksUri: googleServer.jwks_uri as string,
      issuer: ["https://accounts.google.com", "accounts.google.com"],
      audience: this.options.clientId,
      nonce,
      fetch: this.fetchImpl
    });
    return identityFromClaims("google", claims);
  }

  async refresh(refreshToken: string): Promise<OAuthRefreshResult> {
    return refreshTokens(
      googleServer,
      this.client,
      oauth.ClientSecretPost(this.options.clientSecret),
      refreshToken,
      this.requestOptions()
    );
  }

  async revoke(refreshToken: string): Promise<void> {
    await revokeToken(
      googleServer,
      this.client,
      oauth.ClientSecretPost(this.options.clientSecret),
      refreshToken,
      this.requestOptions()
    );
  }
}

export class GitHubOAuthAdapter extends OAuthAdapterBase {
  readonly provider = "github" as const;
  readonly redirectUri: string;
  readonly offlineAccess: boolean;
  private readonly options: GitHubOAuthOptions;
  private readonly client: oauth.Client;

  constructor(options: GitHubOAuthOptions, fetchImpl?: typeof globalThis.fetch) {
    super(fetchImpl);
    this.options = options;
    this.redirectUri = options.redirectUri;
    this.offlineAccess = options.offlineAccess ?? false;
    this.client = { client_id: options.clientId };
  }

  async createAuthorizationUrl(input: OAuthAuthorizationRequest): Promise<URL> {
    return authorizationUrl(githubServer, this.options, input, ["read:user", "user:email"], false);
  }

  async exchangeCode(input: OAuthCallbackInput): Promise<OAuthExchangeResult> {
    return withProviderErrors(async () => {
      const params = oauth.validateAuthResponse(
        githubServer,
        this.client,
        input.callbackParameters,
        input.state
      );
      const response = await oauth.authorizationCodeGrantRequest(
        githubServer,
        this.client,
        oauth.ClientSecretPost(this.options.clientSecret),
        params,
        this.redirectUri,
        input.codeVerifier,
        this.requestOptions()
      );
      const tokens = await oauth.processAuthorizationCodeResponse(
        githubServer,
        this.client,
        response
      );
      const identity = await loadGitHubIdentity(tokens.access_token, this.fetchImpl);
      return exchangeResult(identity, tokens);
    });
  }

  async refresh(refreshToken: string): Promise<OAuthRefreshResult> {
    return refreshTokens(
      githubServer,
      this.client,
      oauth.ClientSecretPost(this.options.clientSecret),
      refreshToken,
      this.requestOptions()
    );
  }
}

export class AppleOAuthAdapter extends OAuthAdapterBase {
  readonly provider = "apple" as const;
  readonly redirectUri: string;
  readonly offlineAccess: boolean;
  private readonly options: AppleOAuthOptions;
  private readonly client: oauth.Client;

  constructor(options: AppleOAuthOptions, fetchImpl?: typeof globalThis.fetch) {
    super(fetchImpl);
    this.options = options;
    this.redirectUri = options.redirectUri;
    this.offlineAccess = options.offlineAccess ?? false;
    this.client = { client_id: options.clientId, id_token_signed_response_alg: "RS256" };
  }

  async createAuthorizationUrl(input: OAuthAuthorizationRequest): Promise<URL> {
    const url = authorizationUrl(appleServer, this.options, input, ["name", "email"]);
    url.searchParams.set("response_mode", "form_post");
    return url;
  }

  async exchangeCode(input: OAuthCallbackInput): Promise<OAuthExchangeResult> {
    return withProviderErrors(async () => {
      const secret = await createAppleClientSecret(this.options);
      return exchangeOidcCode({
        provider: "apple",
        server: appleServer,
        client: this.client,
        clientAuth: oauth.ClientSecretPost(secret),
        redirectUri: this.redirectUri,
        callback: input,
        requestOptions: this.requestOptions()
      });
    });
  }

  async refresh(refreshToken: string): Promise<OAuthRefreshResult> {
    const secret = await createAppleClientSecret(this.options);
    return refreshTokens(
      appleServer,
      this.client,
      oauth.ClientSecretPost(secret),
      refreshToken,
      this.requestOptions()
    );
  }

  async revoke(refreshToken: string): Promise<void> {
    const secret = await createAppleClientSecret(this.options);
    await revokeToken(
      appleServer,
      this.client,
      oauth.ClientSecretPost(secret),
      refreshToken,
      this.requestOptions()
    );
  }
}

interface OAuthCallbackInput {
  callbackParameters: URLSearchParams;
  state: string;
  codeVerifier: string;
  nonce: string;
}

async function exchangeOidcCode(options: {
  provider: "google" | "apple";
  server: oauth.AuthorizationServer;
  client: oauth.Client;
  clientAuth: oauth.ClientAuth;
  redirectUri: string;
  callback: OAuthCallbackInput;
  requestOptions: RequestOptions;
}): Promise<OAuthExchangeResult> {
  const params = oauth.validateAuthResponse(
    options.server,
    options.client,
    options.callback.callbackParameters,
    options.callback.state
  );
  const response = await oauth.authorizationCodeGrantRequest(
    options.server,
    options.client,
    options.clientAuth,
    params,
    options.redirectUri,
    options.callback.codeVerifier,
    options.requestOptions
  );
  const tokens = await oauth.processAuthorizationCodeResponse(
    options.server,
    options.client,
    response,
    {
      expectedNonce: options.callback.nonce,
      requireIdToken: true,
      ...options.requestOptions
    }
  );
  await oauth.validateApplicationLevelSignature(
    options.server,
    response,
    options.requestOptions
  );
  const claims = oauth.getValidatedIdTokenClaims(tokens);
  if (!claims) throw invalidIdentity();
  return exchangeResult(identityFromClaims(options.provider, claims), tokens);
}

function authorizationUrl(
  server: oauth.AuthorizationServer,
  options: { clientId: string; redirectUri: string; scopes?: string[] },
  input: OAuthAuthorizationRequest,
  defaultScopes: string[],
  includeNonce = true
): URL {
  const url = new URL(server.authorization_endpoint as string);
  url.searchParams.set("client_id", options.clientId);
  url.searchParams.set("redirect_uri", options.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", [...new Set([...(options.scopes ?? []), ...defaultScopes])].join(" "));
  url.searchParams.set("state", input.state);
  url.searchParams.set("code_challenge", input.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  if (includeNonce) {
    url.searchParams.set("nonce", input.nonce);
  }
  return url;
}

export async function loadGitHubIdentity(
  accessToken: string,
  fetchImpl: typeof globalThis.fetch
): Promise<VerifiedProviderIdentity> {
  const headers = { authorization: `Bearer ${accessToken}`, accept: "application/vnd.github+json" };
  const [profileResponse, emailsResponse] = await Promise.all([
    fetchImpl("https://api.github.com/user", { headers }),
    fetchImpl("https://api.github.com/user/emails", { headers })
  ]);
  if (!profileResponse.ok) {
    throw new AuthError("oauth_provider_error", "GitHub identity could not be loaded", 502);
  }
  const profile = await profileResponse.json() as {
    id?: number | string;
    name?: string | null;
    login?: string;
    avatar_url?: string | null;
  };
  const emails = emailsResponse.ok
    ? await emailsResponse.json() as Array<{
        email?: string;
        verified?: boolean;
        primary?: boolean;
      }>
    : [];
  if (profile.id === undefined) {
    throw invalidIdentity();
  }
  const verified = emails.filter(
    (entry): entry is { email: string; verified: true; primary?: boolean } =>
      entry.verified === true && typeof entry.email === "string"
  );
  const selected = verified.find((entry) => entry.primary) ??
    verified.sort((left, right) => left.email.toLowerCase().localeCompare(right.email.toLowerCase()))[0];
  return {
    provider: "github",
    providerAccountId: String(profile.id),
    email: selected?.email.toLowerCase() ?? null,
    emailVerified: Boolean(selected),
    name: profile.name ?? profile.login ?? null,
    imageUrl: profile.avatar_url ?? null
  };
}

function identityFromClaims(
  provider: "google" | "apple",
  claims: Record<string, unknown>
): VerifiedProviderIdentity {
  if (typeof claims.sub !== "string") {
    throw invalidIdentity();
  }
  const verified = claims.email_verified === true || claims.email_verified === "true";
  return {
    provider,
    providerAccountId: claims.sub,
    email: typeof claims.email === "string" ? claims.email.toLowerCase() : null,
    emailVerified: verified,
    name: typeof claims.name === "string" ? claims.name : null,
    imageUrl: typeof claims.picture === "string" ? claims.picture : null
  };
}

function exchangeResult(
  identity: VerifiedProviderIdentity,
  tokens: oauth.TokenEndpointResponse
): OAuthExchangeResult {
  return {
    identity,
    refreshToken: typeof tokens.refresh_token === "string" ? tokens.refresh_token : null,
    scopes: typeof tokens.scope === "string" ? tokens.scope.split(/\s+/).filter(Boolean) : []
  };
}

async function refreshTokens(
  server: oauth.AuthorizationServer,
  client: oauth.Client,
  clientAuth: oauth.ClientAuth,
  refreshToken: string,
  requestOptions: RequestOptions
): Promise<OAuthRefreshResult> {
  return withProviderErrors(async () => {
    const response = await oauth.refreshTokenGrantRequest(
      server,
      client,
      clientAuth,
      refreshToken,
      requestOptions
    );
    const tokens = await oauth.processRefreshTokenResponse(server, client, response);
    return {
      accessToken: tokens.access_token,
      refreshToken: typeof tokens.refresh_token === "string" ? tokens.refresh_token : null,
      scopes: typeof tokens.scope === "string" ? tokens.scope.split(/\s+/).filter(Boolean) : []
    };
  });
}

async function revokeToken(
  server: oauth.AuthorizationServer,
  client: oauth.Client,
  clientAuth: oauth.ClientAuth,
  refreshToken: string,
  requestOptions: RequestOptions
): Promise<void> {
  await withProviderErrors(async () => {
    const response = await oauth.revocationRequest(
      server,
      client,
      clientAuth,
      refreshToken,
      requestOptions
    );
    await oauth.processRevocationResponse(response);
  });
}

async function createAppleClientSecret(options: AppleOAuthOptions): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = encodeJson({ alg: "ES256", kid: options.keyId });
  const payload = encodeJson({
    iss: options.teamId,
    iat: now,
    exp: now + 5 * 60,
    aud: "https://appleid.apple.com",
    sub: options.clientId
  });
  const keyBytes = pemBody(options.privateKey);
  const key = await crypto.subtle.importKey(
    "pkcs8",
    keyBytes,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(`${header}.${payload}`)
  );
  return `${header}.${payload}.${encodeBase64Url(new Uint8Array(signature))}`;
}

function pemBody(pem: string): Uint8Array {
  const body = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, "");
  try {
    return decodeBase64Url(body.replace(/\+/g, "-").replace(/\//g, "_"));
  } catch {
    throw new Error("Apple OAuth privateKey must be a PKCS8 PEM private key");
  }
}

function encodeJson(value: Record<string, unknown>): string {
  return encodeBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}

async function withProviderErrors<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (isAuthError(error)) {
      throw error;
    }
    throw new AuthError("oauth_provider_error", "OAuth provider request failed", 401);
  }
}

function invalidIdentity(): AuthError {
  return new AuthError("oauth_provider_error", "OAuth provider identity is invalid", 401);
}
