import type { UserErasureHarness } from "./user-erasure-cases.js";
import { engine } from "./user-erasure-cases.js";
import { assertConformanceEqual as equal } from "./conformance-assertions.js";

export async function eraseIdentityInventory({ storage, rateLimits, reopen }: UserErasureHarness): Promise<void> {
  const auth = engine(storage, rateLimits);
  const suffix = crypto.randomUUID();
  const id = (name: string) => `${name}_${suffix}`;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 60_000);
  const actor = await auth.createUser({ email: `${id("actor")}@example.com` });
  const target = await auth.createUser({ email: `${id("target")}@example.com`, phone: "+447700900123" });
  const other = await auth.createUser({ email: `${id("other")}@example.com` });
  const { organisation } = await auth.createOrganisation({ name: "Preserved shared resources", ownerUserId: actor.id });
  const sharedKey = { id: id("shared-key"), keyPrefix: id("shared-prefix"), keyHash: id("shared-hash"), name: "Shared key",
    userId: null, organisationId: organisation.id, scopes: [], status: "revoked" as const, expiresAt: null, lastUsedAt: null,
    createdAt: now, revokedAt: now, revokedBy: target.id, metadata: { userId: target.id } };
  await storage.createApiKey(sharedKey);
  const invitation = { id: id("recipient-invite"), tokenId: null, organisationId: organisation.id, email: target.email, phone: null,
    role: "member", invitedByUserId: actor.id, status: "pending" as const, expiresAt, acceptedAt: null, revokedAt: null, createdAt: now };
  await storage.createInvitation(invitation);
  await storage.createInvitation({ ...invitation, id: id("sender-invite"), email: other.email, invitedByUserId: target.id });
  const account = await storage.createAccount({ id: id("account"), userId: target.id, provider: "google",
    providerAccountId: id("google"), providerEmail: target.email, providerPhone: null, createdAt: now, updatedAt: now });
  await storage.upsertOAuthCredential({ id: id("credential"), accountId: account.id, provider: "google",
    ciphertext: "encrypted-provider-secret", nonce: "nonce", encryptionKeyId: "key", scopes: [],
    createdAt: now, updatedAt: now, rotatedAt: null });
  for (const revoked of [false, true]) await storage.createSession({ id: id(`session${revoked}`), userId: target.id,
    tokenHash: id(`session-hash${revoked}`), createdAt: now, lastActiveAt: now, expiresAt, idleExpiresAt: expiresAt,
    ipAddress: "192.0.2.1", userAgent: "personal device", revokedAt: revoked ? now : null,
    revokeReason: revoked ? "logout" : null, authenticationMethods: ["password"], assuranceLevel: "aal1", authenticatedAt: now });
  for (const [index, userId] of [target.id, null, other.id].entries()) {
    await storage.createToken({ id: id(`token${index}`), tokenHash: id(`token-hash${index}`), type: "magic_link",
      userId, email: target.email, phone: null, organisationId: null, expiresAt: now, usedAt: now, createdAt: now });
    await storage.createSmsOtp({ id: id(`otp${index}`), phone: target.phone!, userId, codeHash: id(`otp-hash${index}`),
      purpose: "phone_login", expiresAt: index === 1 ? now : expiresAt, attempts: index, maxAttempts: 5, consumedAt: index === 0 ? now : null,
      createdAt: new Date(now.getTime() + index), lastSentAt: now });
  }
  for (const status of ["pending", "active", "disabled"] as const) await storage.createTotpFactor({
    id: id(status), userId: target.id, status, ciphertext: "encrypted-totp", nonce: "nonce", encryptionKeyId: "key",
    lastUsedTimestep: 1, createdAt: now, updatedAt: now, disabledAt: status === "disabled" ? now : null });
  await storage.replaceRecoveryCodes(target.id, [{ id: id("recovery"), userId: target.id, codeHash: id("recovery-hash"), consumedAt: null, createdAt: now }]);
  await storage.createMfaChallenge({ id: id("mfa"), userId: target.id, tokenHash: id("mfa-hash"), primaryMethod: "password",
    methods: ["totp"], attempts: 0, maxAttempts: 5, expiresAt, consumedAt: null, createdAt: now });
  await storage.createWebAuthnChallenge({ id: id("webauthn"), challengeHash: id("webauthn-hash"), userId: null,
    mfaChallengeId: id("mfa"), purpose: "mfa", expiresAt, consumedAt: null, createdAt: now });
  const passkey = { id: id("passkey"), userId: target.id, credentialId: id("credential-id"), publicKey: new Uint8Array([1, 2]),
    counter: 0, transports: [], deviceType: "singleDevice" as const, backedUp: false, discoverable: true,
    name: "personal device", metadata: {}, createdAt: now, updatedAt: now, lastUsedAt: null };
  await storage.createPasskeyCredential(passkey);
  await storage.createPasskeyCredential({ ...passkey, id: id("other-passkey"), userId: other.id,
    credentialId: id("other-credential"), metadata: { userId: target.id } });
  await storage.createOAuthTransaction({ id: id("oauth"), provider: "google", flowKind: "redirect", intent: "link",
    stateHash: id("state"), destination: null, interactionMode: "redirect", openerOrigin: null, userId: target.id,
    expiresAt, consumedAt: null, createdAt: now });
  await storage.createApiKey({ id: id("key"), keyPrefix: id("prefix"), keyHash: id("key-hash"), name: "personal key",
    userId: target.id, organisationId: null, scopes: [], status: "active", expiresAt: null, lastUsedAt: null,
    createdAt: now, revokedAt: null, revokedBy: null, metadata: {} });
  await storage.createAuditEvent({ id: id("key-audit"), eventType: "api_key.created", actorUserId: null,
    targetUserId: null, organisationId: null, apiKeyId: id("key"), ipAddress: "192.0.2.1", userAgent: "private",
    metadata: {}, createdAt: now });
  await storage.createAuditEvent({ id: id("nested-audit"), eventType: "user.signed_up", actorUserId: null,
    targetUserId: null, organisationId: null, apiKeyId: null, ipAddress: "192.0.2.1", userAgent: "private",
    metadata: { payload: JSON.stringify({ nested: [{ accountId: account.id }] }) }, createdAt: now });
  await rateLimits.hit(`profile:${target.id}`, 60_000, 10, target.id);
  await rateLimits.hit(`profile:${other.id}`, 60_000, 10, other.id);
  const operationId = crypto.randomUUID();
  equal((await auth.admin.eraseUser({ actorUserId: actor.id, userId: target.id, reason: "requested", operationId })).status,
    "complete", "credential inventory erasure completes");
  const restarted = reopen();
  equal((await restarted.listSessionsByUserId(target.id)).length, 0, "active and revoked sessions removed");
  equal(await restarted.getOAuthCredentialByAccountId(account.id), null, "provider secrets removed");
  for (const status of ["pending", "active", "disabled"]) equal(await restarted.getTotpFactorById(id(status)), null, `${status} factor removed`);
  equal(await restarted.consumeRecoveryCode(target.id, id("recovery-hash"), now), null, "recovery code removed");
  equal(await restarted.getMfaChallengeById(id("mfa")), null, "MFA challenge removed");
  equal(await restarted.consumeWebAuthnChallenge(id("webauthn-hash"), "mfa", now), null, "anonymous MFA child removed");
  equal(await restarted.getPasskeyCredentialById(id("passkey")), null, "passkey removed");
  equal((await restarted.getPasskeyCredentialById(id("other-passkey")))?.userId, other.id, "other person's passkey preserved");
  equal(await restarted.consumeOAuthTransaction(id("state"), "redirect", now), null, "linked OAuth request removed");
  equal(await restarted.getApiKeyByPrefix(id("prefix")), null, "personal key removed");
  equal((await restarted.getApiKeyByPrefix(id("shared-prefix")))?.id, sharedKey.id, "shared key preserved");
  equal((await restarted.getApiKeyByPrefix(id("shared-prefix")))?.revokedBy, null, "deleted revoker reference removed");
  equal(await restarted.getInvitationById(id("recipient-invite")), null, "personal recipient invitation removed");
  equal((await restarted.getInvitationById(id("sender-invite")))?.invitedByUserId, null, "another recipient keeps their invitation without its erased sender");
  for (const index of [0, 1]) equal(await restarted.getTokenByHash(id(`token-hash${index}`)), null, "owned or anonymous consumed token removed");
  equal((await restarted.getTokenByHash(id("token-hash2")))?.userId, other.id, "other person's contact token preserved");
  equal((await restarted.getLatestSmsOtp(target.phone!, "phone_login"))?.userId, other.id, "other person's OTP preserved");
  const audits = await restarted.listAuditEvents();
  equal(audits.some((event) => [id("key-audit"), id("nested-audit")].includes(event.id)), false, "key and serialized personal audit removed");
  equal((await rateLimits.hit(`profile:${target.id}`, 60_000, 10)).count, 1, "personal counter removed");
  equal((await rateLimits.hit(`profile:${other.id}`, 60_000, 10, other.id)).count, 2, "other counter preserved");
  equal((await restarted.userErasureStorage.get(operationId))?.subject, null, "all personal recovery keys removed");
}
