import { isAuthorizationServerCapableStorage, isDeviceAuthorizationCapableStorage,
  isSamlCapableStorage, isScimCapableStorage } from "../../src/index.js";
import { deviceAuthorization } from "../helpers/device-authorization.js";
import { samlConnection, samlTransaction } from "../saml/saml-storage-fixtures.js";
import { scimConnection, scimToken, scimUser } from "../scim/scim-storage-fixtures.js";
import type { UserErasureHarness } from "./user-erasure-cases.js";
import { engine } from "./user-erasure-cases.js";
import { assertConformance as assert, assertConformanceEqual as equal } from "./conformance-assertions.js";

export async function eraseAuthorizationInventory({ storage, rateLimits, reopen }: UserErasureHarness): Promise<void> {
  assert(isAuthorizationServerCapableStorage(storage) && isSamlCapableStorage(storage) && isScimCapableStorage(storage), "built in capabilities");
  const provider = storage.authorizationServerStorage;
  assert(isDeviceAuthorizationCapableStorage(provider), "device capability");
  const suffix = crypto.randomUUID();
  const id = (name: string) => `${name}_${suffix}`;
  const auth = engine(storage, rateLimits);
  const actor = await auth.createUser({ email: `${id("actor")}@example.com` });
  const target = await auth.createUser({ email: `${id("target")}@example.com` });
  const { organisation } = await auth.createOrganisation({ name: "Shared organisation", ownerUserId: actor.id });
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 60_000);
  const session = await storage.createSession({ id: id("session"), userId: target.id, tokenHash: id("session-hash"),
    createdAt: now, lastActiveAt: now, expiresAt, idleExpiresAt: expiresAt, ipAddress: null, userAgent: null,
    revokedAt: null, revokeReason: null, authenticationMethods: ["password"], assuranceLevel: "aal1", authenticatedAt: now });
  const client = await provider.createAuthorizationClient({ id: id("client"), clientId: id("public-client"), name: "Shared client",
    clientType: "public", applicationType: "web", tokenEndpointAuthMethod: "none", redirectUris: ["https://example.com/callback"],
    allowedScopes: ["openid"], grantTypes: ["authorization_code", "refresh_token"], status: "active", createdAt: now, updatedAt: now, revokedAt: null }, null);
  const grant = await provider.upsertAuthorizationGrant({ id: id("grant"), authorizationClientId: client.id, userId: target.id,
    protectedResourceId: null, scopes: ["openid"], createdAt: now, updatedAt: now, revokedAt: null });
  await provider.createAuthorizationInteraction({ id: id("interaction"), interactionHash: id("interaction-hash"),
    authorizationClientId: client.id, userId: target.id, requestCiphertext: "private-request", requestNonce: "nonce", encryptionKeyId: "key",
    status: "pending", expiresAt, consumedAt: null, createdAt: now });
  await provider.createAuthorizationCode({ id: id("code"), codeHash: id("code-hash"), grantId: grant.id,
    authorizationClientId: client.id, userId: target.id, protectedResourceId: null, sessionId: session.id,
    redirectUri: client.redirectUris[0]!, scopes: ["openid"], codeChallenge: "challenge", nonceCiphertext: "private-nonce",
    nonceNonce: "nonce", encryptionKeyId: "key", expiresAt, consumedAt: null, createdAt: now });
  const token = { id: id("access"), tokenHash: id("access-hash"), prefix: id("access-prefix"), grantId: grant.id,
    authorizationClientId: client.id, userId: target.id, protectedResourceId: null, scopes: ["openid"], expiresAt, revokedAt: null, createdAt: now };
  await provider.createAuthorizationTokens(token, { ...token, id: id("refresh"), tokenHash: id("refresh-hash"),
    prefix: id("refresh-prefix"), generation: 1, replacedByTokenId: null, consumedAt: null });
  await provider.createOidcSubject({ id: id("oidc"), userId: target.id, subject: id("subject"), createdAt: now });
  await provider.deviceAuthorizationStorage.createDeviceAuthorization(deviceAuthorization({ id: id("device"),
    authorizationClientId: client.id, deviceCodeHash: id("device-hash"), userCodeHash: id("user-code-hash"), status: "approved",
    userId: target.id, sessionId: session.id, grantId: grant.id, approvedScopes: ["openid"], approvedAt: now, expiresAt, createdAt: now }));
  const saml = await storage.samlStorage.createConnection({ ...samlConnection(), id: id("saml"), key: id("saml-key"), organisationId: organisation.id });
  await storage.samlStorage.createTransaction({ ...samlTransaction(), id: id("saml-transaction"), connectionId: saml.id,
    relayStateHash: id("relay"), requestIdHash: id("request"), userId: target.id, expiresAt, createdAt: now });
  const scim = await storage.scimStorage.createConnection({ ...scimConnection(), id: id("scim"), key: id("scim-key"),
    organisationId: organisation.id, samlConnectionId: saml.id });
  const provisioningToken = await storage.scimStorage.createToken({ ...scimToken(), id: id("scim-token"), connectionId: scim.id,
    prefix: id("scim-prefix"), tokenHash: id("scim-hash") });
  const membership = { id: id("membership"), organisationId: organisation.id, userId: target.id,
    role: "member", status: "removed" as const, joinedAt: now, removedAt: now, createdAt: now, updatedAt: now };
  await storage.scimStorage.commitProvision({ membership, scimUser: { ...scimUser(id("scim-user")), connectionId: scim.id,
    userId: target.id, membershipId: membership.id, userName: target.email!, normalizedUserName: target.email!,
    email: target.email!, normalizedEmail: target.email!, active: false, deletedAt: now }, auditEvents: [] });
  await auth.admin.eraseUser({ actorUserId: actor.id, userId: target.id, reason: "requested", operationId: crypto.randomUUID() });
  const restarted = reopen();
  assert(isAuthorizationServerCapableStorage(restarted) && isSamlCapableStorage(restarted) && isScimCapableStorage(restarted), "restart capabilities");
  const restoredProvider = restarted.authorizationServerStorage;
  assert(isDeviceAuthorizationCapableStorage(restoredProvider), "restart device capability");
  equal(await restoredProvider.getAuthorizationInteractionByHash(id("interaction-hash"), now), null, "interaction removed");
  equal(await restoredProvider.getAuthorizationGrant(client.id, target.id, null), null, "grant removed");
  equal(await restoredProvider.consumeAuthorizationCode(id("code-hash"), client.id, client.redirectUris[0]!, "challenge", null, now), null, "code removed");
  equal(await restoredProvider.getAuthorizationAccessTokenByHash(id("access-hash")), null, "access token removed");
  equal(await restoredProvider.getAuthorizationRefreshTokenByHash(id("refresh-hash")), null, "refresh token removed");
  equal(await restoredProvider.getOidcSubjectByUserId(target.id), null, "OIDC subject removed");
  equal(await restoredProvider.deviceAuthorizationStorage.getDeviceAuthorizationByDeviceCodeHash(id("device-hash")), null, "approved device removed");
  equal(await restarted.samlStorage.getTransactionByRelayStateHash(id("relay")), null, "SAML request removed");
  equal(await restarted.scimStorage.getUserById(id("scim-user")), null, "SCIM tombstone removed");
  equal((await restoredProvider.getAuthorizationClientById(client.id))?.id, client.id, "shared client preserved");
  equal((await restarted.samlStorage.getConnectionById(saml.id))?.id, saml.id, "shared SAML configuration preserved");
  equal((await restarted.scimStorage.getTokenById(provisioningToken.id))?.id, provisioningToken.id, "shared provisioning credential preserved");
}
