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
import { cleanupDpopProofs } from "./authorization-server-dpop.js";
import {
  approveDeviceAuthorization,
  cleanupDeviceAuthorizations,
  denyDeviceAuthorization,
  getDeviceAuthorization,
  startDeviceAuthorization
} from "./authorization-server-device.js";
import {
  getAuthorizationServerJwks,
  getAuthorizationServerMetadata
} from "./authorization-server-metadata.js";
import { introspectAuthorizationToken } from "./authorization-server-introspection.js";
import {
  createProtectedResource,
  listProtectedResources,
  revokeProtectedResource,
  rotateProtectedResourceSecret,
  updateProtectedResource
} from "./authorization-server-protected-resources.js";
import { exchangeAuthorizationToken } from "./authorization-server-token-exchange.js";
import {
  getAuthorizationUserInfo,
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
  AuthorizationUserInfoRequestInput,
  CleanupDpopProofsInput,
  CompleteAuthorizationInteractionInput,
  CreatedAuthorizationClient,
  CreatedProtectedResource,
  CreateAuthorizationClientInput,
  CreateProtectedResourceInput,
  DenyAuthorizationInteractionInput,
  GetAuthorizationInteractionInput,
  ListAuthorizationUserGrantsInput,
  PublicAuthorizationInteraction,
  ProtectedResource,
  RevokeAuthorizationClientInput,
  RevokeProtectedResourceInput,
  RevokeAuthorizationUserGrantInput,
  RotateAuthorizationClientSecretInput,
  RotateProtectedResourceSecretInput,
  UpdateAuthorizationClientInput,
  UpdateProtectedResourceInput,
  VerifiedAuthorizationAccessToken,
  VerifyAuthorizationAccessTokenInput
} from "./authorization-server-types.js";
import type { AuthOperationRunner } from "./auth-operation-runner.js";
import type {
  CleanupDeviceAuthorizationsInput,
  CompleteDeviceAuthorizationInput,
  DenyDeviceAuthorizationInput,
  DeviceAuthorizationRequestInput,
  DeviceAuthorizationResponse,
  GetDeviceAuthorizationInput,
  PublicDeviceAuthorization
} from "./authorization-server-device-types.js";

export class OwnAuthAuthorizationServer {
  constructor(
    private readonly ctx: AuthEngineContext,
    private readonly execute: AuthOperationRunner
  ) {}

  /** @internal Used by createOwnAuthAuthorizationServerHandler. */
  isConfigured(): boolean {
    return Boolean(this.ctx.authorizationServer && this.ctx.authorizationServerStorage);
  }

  /** @internal Used by createOwnAuthAuthorizationServerHandler. */
  isDeviceAuthorizationConfigured(): boolean {
    return Boolean(
      this.ctx.authorizationServer?.deviceAuthorization &&
      this.ctx.deviceAuthorizationStorage
    );
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

  createProtectedResource(
    input: CreateProtectedResourceInput
  ): Promise<CreatedProtectedResource> {
    return this.execute("authorizationServer.createProtectedResource", input, () =>
      createProtectedResource(this.ctx, input));
  }

  listProtectedResources(): Promise<ProtectedResource[]> {
    return this.execute("authorizationServer.listProtectedResources", undefined, () =>
      listProtectedResources(this.ctx));
  }

  updateProtectedResource(
    input: UpdateProtectedResourceInput
  ): Promise<ProtectedResource> {
    return this.execute("authorizationServer.updateProtectedResource", input, () =>
      updateProtectedResource(this.ctx, input));
  }

  rotateProtectedResourceSecret(
    input: RotateProtectedResourceSecretInput
  ): Promise<string> {
    return this.execute("authorizationServer.rotateProtectedResourceSecret", input, () =>
      rotateProtectedResourceSecret(this.ctx, input));
  }

  revokeProtectedResource(
    input: RevokeProtectedResourceInput
  ): Promise<ProtectedResource> {
    return this.execute("authorizationServer.revokeProtectedResource", input, () =>
      revokeProtectedResource(this.ctx, input));
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

  getDeviceAuthorization(
    input: GetDeviceAuthorizationInput
  ): Promise<PublicDeviceAuthorization> {
    return this.execute("authorizationServer.getDeviceAuthorization", input, () =>
      getDeviceAuthorization(this.ctx, input));
  }

  approveDeviceAuthorization(input: CompleteDeviceAuthorizationInput): Promise<void> {
    return this.execute("authorizationServer.approveDeviceAuthorization", input, () =>
      approveDeviceAuthorization(this.ctx, input));
  }

  denyDeviceAuthorization(input: DenyDeviceAuthorizationInput): Promise<void> {
    return this.execute("authorizationServer.denyDeviceAuthorization", input, () =>
      denyDeviceAuthorization(this.ctx, input));
  }

  cleanupDeviceAuthorizations(
    input: CleanupDeviceAuthorizationsInput
  ): Promise<number> {
    return this.execute("authorizationServer.cleanupDeviceAuthorizations", input, () =>
      cleanupDeviceAuthorizations(this.ctx, input));
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
  startDeviceAuthorization(
    input: DeviceAuthorizationRequestInput
  ): Promise<DeviceAuthorizationResponse> {
    return this.execute("authorizationServer.startDeviceAuthorization", input, () =>
      startDeviceAuthorization(this.ctx, input));
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
  userInfo(input: AuthorizationUserInfoRequestInput): Promise<AuthorizationUserInfo> {
    return this.execute("authorizationServer.userInfo", input, () =>
      getAuthorizationUserInfo(this.ctx, input));
  }

  cleanupDpopProofs(input: CleanupDpopProofsInput = {}): Promise<number> {
    return this.execute("authorizationServer.cleanupDpopProofs", input, () =>
      cleanupDpopProofs(this.ctx, input.expiredBefore));
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
