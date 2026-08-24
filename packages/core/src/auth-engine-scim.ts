import type { AuthEngineContext } from "./auth-engine-context.js";
import * as connections from "./scim-connections.js";
import type { AuthOperationRunner } from "./auth-operation-runner.js";
import {
  authenticateScimRequest,
  createScimUser,
  deleteScimUser,
  getScimUser,
  listScimUsers,
  replaceScimUser
} from "./scim-internals.js";
import * as users from "./scim-users.js";
import type {
  CreateScimConnectionInput,
  CreatedScimToken,
  CreateScimTokenInput,
  LinkScimUserInput,
  ListScimConnectionsInput,
  PublicScimConnection,
  RestoreScimUserInput,
  RevokeScimTokenInput,
  ScimConnection,
  ScimConnectionAccessInput,
  ScimTokenDetails,
  ScimUser,
  ScimUserAttributes,
  ScimUserFilter,
  ScimUserPage,
  UpdateScimConnectionInput
} from "./scim-types.js";
import type { RequestContext } from "./types.js";

export class OwnAuthScim {
  constructor(
    private readonly ctx: AuthEngineContext,
    private readonly execute: AuthOperationRunner
  ) {}

  /** @internal Used by createOwnAuthScimHandler. */
  isConfigured(): boolean {
    return Boolean(this.ctx.scim && this.ctx.scimStorage);
  }

  createConnection(input: CreateScimConnectionInput): Promise<PublicScimConnection> {
    return this.execute("scim.createConnection", input, () =>
      connections.createConnection(this.ctx, input));
  }

  getConnection(input: ScimConnectionAccessInput): Promise<PublicScimConnection> {
    return this.execute("scim.getConnection", input, () =>
      connections.getConnection(this.ctx, input));
  }

  listConnections(input: ListScimConnectionsInput): Promise<PublicScimConnection[]> {
    return this.execute("scim.listConnections", input, () =>
      connections.listConnections(this.ctx, input));
  }

  updateConnection(input: UpdateScimConnectionInput): Promise<PublicScimConnection> {
    return this.execute("scim.updateConnection", input, () =>
      connections.updateConnection(this.ctx, input));
  }

  disableConnection(input: ScimConnectionAccessInput): Promise<PublicScimConnection> {
    return this.execute("scim.disableConnection", input, () =>
      connections.setConnectionEnabled(this.ctx, input, false));
  }

  enableConnection(input: ScimConnectionAccessInput): Promise<PublicScimConnection> {
    return this.execute("scim.enableConnection", input, () =>
      connections.setConnectionEnabled(this.ctx, input, true));
  }

  createToken(input: CreateScimTokenInput): Promise<CreatedScimToken> {
    return this.execute("scim.createToken", input, () =>
      connections.createToken(this.ctx, input));
  }

  listTokens(input: ScimConnectionAccessInput): Promise<ScimTokenDetails[]> {
    return this.execute("scim.listTokens", input, () =>
      connections.listTokens(this.ctx, input));
  }

  revokeToken(input: RevokeScimTokenInput): Promise<ScimTokenDetails> {
    return this.execute("scim.revokeToken", input, () =>
      connections.revokeToken(this.ctx, input));
  }

  linkUser(input: LinkScimUserInput): Promise<ScimUser> {
    return this.execute("scim.linkUser", input, () => users.linkUser(this.ctx, input));
  }

  restoreUser(input: RestoreScimUserInput): Promise<ScimUser> {
    return this.execute("scim.restoreUser", input, () => users.restoreUser(this.ctx, input));
  }

  /** @internal Used by createOwnAuthScimHandler. */
  [authenticateScimRequest](rawToken: string, request?: RequestContext) {
    return this.execute("scim.authenticateRequest", { request }, () =>
      users.authenticateRequest(this.ctx, rawToken, request));
  }

  /** @internal Used by createOwnAuthScimHandler. */
  [createScimUser](
    connection: ScimConnection,
    input: ScimUserAttributes,
    request?: RequestContext
  ): Promise<ScimUser> {
    return this.execute("scim.createUser", { input, request }, () =>
      users.createUserResource(this.ctx, connection, input, request));
  }

  /** @internal Used by createOwnAuthScimHandler. */
  [getScimUser](connectionId: string, resourceId: string): Promise<ScimUser> {
    return this.execute("scim.getUser", { connectionId, resourceId }, () =>
      users.getUserResource(this.ctx, connectionId, resourceId));
  }

  /** @internal Used by createOwnAuthScimHandler. */
  [listScimUsers](
    connectionId: string,
    filter: ScimUserFilter | null,
    startIndex: number,
    count: number
  ): Promise<ScimUserPage> {
    return this.execute("scim.listUsers", { connectionId, filter, startIndex, count }, () =>
      users.listUserResources(this.ctx, connectionId, filter, startIndex, count));
  }

  /** @internal Used by createOwnAuthScimHandler. */
  [replaceScimUser](
    connection: ScimConnection,
    resourceId: string,
    input: ScimUserAttributes,
    expectedVersion: number | null,
    request?: RequestContext
  ): Promise<ScimUser> {
    return this.execute("scim.replaceUser", { resourceId, input, request }, () =>
      users.replaceUserResource(
        this.ctx, connection, resourceId, input, expectedVersion, request
      ));
  }

  /** @internal Used by createOwnAuthScimHandler. */
  [deleteScimUser](
    connection: ScimConnection,
    resourceId: string,
    expectedVersion: number | null,
    request?: RequestContext
  ): Promise<ScimUser> {
    return this.execute("scim.deleteUser", {
      resourceId,
      organisationId: connection.organisationId,
      request
    }, () =>
      users.deleteUserResource(this.ctx, connection, resourceId, expectedVersion, request));
  }
}
