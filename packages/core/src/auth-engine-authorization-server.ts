import type { AuthEngineContext } from "./auth-engine-context.js";
import {
  createAuthorizationClient,
  listAuthorizationClients,
  revokeAuthorizationClient,
  rotateAuthorizationClientSecret,
  updateAuthorizationClient
} from "./authorization-server-clients.js";
import {
  approveAuthorizationInteraction,
  denyAuthorizationInteraction,
  getAuthorizationInteraction
} from "./authorization-server-interactions.js";
import { startAuthorization } from "./authorization-server-authorization-request.js";
import {
  getAuthorizationServerJwks,
  getAuthorizationServerMetadata
} from "./authorization-server-metadata.js";
import { exchangeAuthorizationToken } from "./authorization-server-token-exchange.js";
import {
  getAuthorizationUserInfo,
  introspectAuthorizationToken,
  listAuthorizationUserGrants,
  revokeAuthorizationProtocolToken,
  revokeAuthorizationUserGrant,
  verifyAuthorizationAccessToken
} from "./authorization-server-token-operations.js";
import type {
  AuthorizationClient,
  AuthorizationIntrospectionResponse,
  AuthorizationMetadata,
  AuthorizationRedirectResult,
  AuthorizationRequestInput,
  AuthorizationTokenActionInput,
  AuthorizationTokenRequestInput,
  AuthorizationTokenResponse,
  AuthorizationUserGrant,
  AuthorizationUserInfo,
  CompleteAuthorizationInteractionInput,
  CreatedAuthorizationClient,
  CreateAuthorizationClientInput,
  DenyAuthorizationInteractionInput,
  GetAuthorizationInteractionInput,
  ListAuthorizationUserGrantsInput,
  PublicAuthorizationInteraction,
  RevokeAuthorizationClientInput,
  RevokeAuthorizationUserGrantInput,
  RotateAuthorizationClientSecretInput,
  UpdateAuthorizationClientInput,
  VerifiedAuthorizationAccessToken,
  VerifyAuthorizationAccessTokenInput
} from "./authorization-server-types.js";

type AuthorizationServerOperationRunner = <Result>(
  operation: string,
  input: unknown,
  work: () => Promise<Result>
) => Promise<Result>;

export class OwnAuthAuthorizationServer {
  constructor(
    private readonly ctx: AuthEngineContext,
    private readonly execute: AuthorizationServerOperationRunner
  ) {}

  /** @internal Used by createOwnAuthAuthorizationServerHandler. */
  isConfigured(): boolean {
    return Boolean(this.ctx.authorizationServer && this.ctx.authorizationServerStorage);
  }

  createClient(
    input: CreateAuthorizationClientInput
  ): Promise<CreatedAuthorizationClient> {
    return this.execute("authorizationServer.createClient", input, () =>
      createAuthorizationClient(this.ctx, input));
  }

  listClients(): Promise<AuthorizationClient[]> {
    return this.execute("authorizationServer.listClients", undefined, () =>
      listAuthorizationClients(this.ctx));
  }

  updateClient(input: UpdateAuthorizationClientInput): Promise<AuthorizationClient> {
    return this.execute("authorizationServer.updateClient", input, () =>
      updateAuthorizationClient(this.ctx, input));
  }

  rotateClientSecret(input: RotateAuthorizationClientSecretInput): Promise<string> {
    return this.execute("authorizationServer.rotateClientSecret", input, () =>
      rotateAuthorizationClientSecret(this.ctx, input));
  }

  revokeClient(input: RevokeAuthorizationClientInput): Promise<AuthorizationClient> {
    return this.execute("authorizationServer.revokeClient", input, () =>
      revokeAuthorizationClient(this.ctx, input));
  }

  getInteraction(
    input: GetAuthorizationInteractionInput
  ): Promise<PublicAuthorizationInteraction> {
    return this.execute("authorizationServer.getInteraction", input, () =>
      getAuthorizationInteraction(this.ctx, input));
  }

  approveInteraction(
    input: CompleteAuthorizationInteractionInput
  ): Promise<AuthorizationRedirectResult> {
    return this.execute("authorizationServer.approveInteraction", input, () =>
      approveAuthorizationInteraction(this.ctx, input));
  }

  denyInteraction(
    input: DenyAuthorizationInteractionInput
  ): Promise<AuthorizationRedirectResult> {
    return this.execute("authorizationServer.denyInteraction", input, () =>
      denyAuthorizationInteraction(this.ctx, input));
  }

  verifyAccessToken(
    input: VerifyAuthorizationAccessTokenInput
  ): Promise<VerifiedAuthorizationAccessToken> {
    return this.execute("authorizationServer.verifyAccessToken", input, () =>
      verifyAuthorizationAccessToken(this.ctx, input));
  }

  listUserGrants(
    input: ListAuthorizationUserGrantsInput
  ): Promise<AuthorizationUserGrant[]> {
    return this.execute("authorizationServer.listUserGrants", input, () =>
      listAuthorizationUserGrants(this.ctx, input));
  }

  revokeUserGrant(input: RevokeAuthorizationUserGrantInput): Promise<void> {
    return this.execute("authorizationServer.revokeUserGrant", input, () =>
      revokeAuthorizationUserGrant(this.ctx, input));
  }

  /** @internal Used by createOwnAuthAuthorizationServerHandler. */
  start(input: AuthorizationRequestInput): Promise<AuthorizationRedirectResult> {
    return this.execute("authorizationServer.start", input, () =>
      startAuthorization(this.ctx, input));
  }

  /** @internal Used by createOwnAuthAuthorizationServerHandler. */
  exchangeToken(input: AuthorizationTokenRequestInput): Promise<AuthorizationTokenResponse> {
    return this.execute("authorizationServer.exchangeToken", input, () =>
      exchangeAuthorizationToken(this.ctx, input));
  }

  /** @internal Used by createOwnAuthAuthorizationServerHandler. */
  revokeToken(input: AuthorizationTokenActionInput): Promise<void> {
    return this.execute("authorizationServer.revokeToken", input, () =>
      revokeAuthorizationProtocolToken(this.ctx, input));
  }

  /** @internal Used by createOwnAuthAuthorizationServerHandler. */
  introspectToken(
    input: AuthorizationTokenActionInput
  ): Promise<AuthorizationIntrospectionResponse> {
    return this.execute("authorizationServer.introspectToken", input, () =>
      introspectAuthorizationToken(this.ctx, input));
  }

  /** @internal Used by createOwnAuthAuthorizationServerHandler. */
  userInfo(accessToken: string): Promise<AuthorizationUserInfo> {
    return this.execute("authorizationServer.userInfo", { accessToken }, () =>
      getAuthorizationUserInfo(this.ctx, accessToken));
  }

  /** @internal Used by createOwnAuthAuthorizationServerHandler. */
  metadata(): Promise<AuthorizationMetadata> {
    return this.execute("authorizationServer.metadata", undefined, () =>
      getAuthorizationServerMetadata(this.ctx));
  }

  /** @internal Used by createOwnAuthAuthorizationServerHandler. */
  jwks() {
    return this.execute("authorizationServer.jwks", undefined, () =>
      getAuthorizationServerJwks(this.ctx));
  }
}
