import { describe, expect, it, vi } from "vitest";
import { createOwnAuthScimHandler } from "../../src/scim-http.js";
import { SamlProtocolError } from "../../src/saml.js";
import { createSamlHarness, required } from "./saml-test-harness.js";

describe("SAML authentication", () => {
  it("manages immutable organisation connections through owners", async () => {
    const harness = await createSamlHarness();

    const listed = await harness.auth.saml.listConnections({
      organisationId: harness.organisation.id,
      actorUserId: harness.ownerId
    });
    expect(listed).toEqual([harness.connection]);

    const updated = await harness.auth.saml.updateConnection({
      connectionId: harness.connection.id,
      actorUserId: harness.ownerId,
      name: "Workforce SSO"
    });
    expect(updated.name).toBe("Workforce SSO");
    expect(updated.idpEntityId).toBe(harness.connection.idpEntityId);

    await harness.auth.saml.disableConnection({
      connectionId: harness.connection.id,
      actorUserId: harness.ownerId
    });
    await expect(harness.auth.saml.createSignInUrl({
      connectionId: harness.connection.id
    })).rejects.toMatchObject({ code: "saml_connection_disabled" });

    await harness.auth.saml.enableConnection({
      connectionId: harness.connection.id,
      actorUserId: harness.ownerId
    });
    await expect(harness.auth.saml.getMetadata({
      connectionId: harness.connection.id
    })).resolves.toContain(harness.connection.id);
  });

  it("provisions a non-owner member and stores only hashed SAML credentials", async () => {
    const harness = await createSamlHarness();
    const started = await harness.auth.saml.createSignInUrl({
      connectionId: harness.connection.id,
      destination: "/dashboard",
      request: { ipAddress: "203.0.113.10" }
    });

    const result = await harness.complete();
    expect(result).toMatchObject({ status: "complete", destination: "/dashboard" });
    expect(started.url).toContain("https://idp.example.com/sso");

    const user = await harness.storage.getUserByEmail("saml.user@example.com");
    expect(user).not.toBeNull();
    const member = await harness.storage.getOrganisationMember(
      harness.organisation.id,
      required(user).id
    );
    expect(member).toMatchObject({ role: "member", status: "active" });

    const [account] = await harness.storage.listAccountsByUserId(required(user).id);
    expect(account?.provider).toBe(`saml.${harness.connection.key}`);
    expect(account?.providerAccountId).not.toContain("subject-123");
    expect(await harness.storage.samlStorage.getTransactionByRelayStateHash(
      required(harness.provider.relayState)
    )).toBeNull();
  });

  it("consumes the response before identity resolution and rejects replay", async () => {
    const harness = await createSamlHarness();
    await harness.auth.saml.createSignInUrl({ connectionId: harness.connection.id });

    await expect(harness.complete()).resolves.toMatchObject({ status: "complete" });
    await expect(harness.complete()).rejects.toMatchObject({
      code: "saml_transaction_invalid"
    });
  });

  it("checks mailbox ownership when concurrent provisioning finds a linked SAML account", async () => {
    const harness = await createSamlHarness();
    let concurrentSignup: Awaited<ReturnType<typeof harness.auth.signUpEmailPassword>> | undefined;
    vi.spyOn(harness.storage.samlStorage, "commitIdentity").mockImplementationOnce(async (commit) => {
      if (!commit.user || !commit.account) throw new Error("Expected a new SAML identity");
      concurrentSignup = await harness.auth.signUpEmailPassword({
        email: harness.provider.email, password: "attacker-password"
      });
      await harness.storage.createAccount({ ...commit.account, userId: concurrentSignup.user.id });
      throw new Error("Concurrent SAML identity creation");
    });
    await harness.auth.saml.createSignInUrl({ connectionId: harness.connection.id });
    const result = await harness.complete();
    if (result.status !== "complete" || !concurrentSignup) throw new Error("Expected completed SAML sign in and race fixture");
    expect(result.user.id).not.toBe(concurrentSignup.user.id);
    expect(result.user.passwordHash).toBeNull();
    expect(await harness.auth.getCurrentSession(concurrentSignup.sessionToken)).toBeNull();
    expect((await harness.storage.listAccountsByUserId(result.user.id))
      .some((account) => account.provider === `saml.${harness.connection.key}`)).toBe(true);
  });

  it("rejects a claimed assertion on a different transaction", async () => {
    const harness = await createSamlHarness();
    harness.provider.assertionId = "_replayed_assertion";
    await harness.auth.saml.createSignInUrl({ connectionId: harness.connection.id });
    await expect(harness.complete()).resolves.toMatchObject({ status: "complete" });

    await harness.auth.saml.createSignInUrl({ connectionId: harness.connection.id });
    await expect(harness.complete()).rejects.toMatchObject({
      code: "saml_transaction_invalid"
    });
  });

  it("requires deliberate linking when a trusted email already exists", async () => {
    const harness = await createSamlHarness();
    const existing = await harness.auth.signUpEmailPassword({
      email: "saml.user@example.com",
      password: "secure-password"
    });
    await harness.auth.saml.createSignInUrl({ connectionId: harness.connection.id });

    await expect(harness.complete()).rejects.toMatchObject({
      code: "account_linking_required"
    });

    await harness.auth.saml.createLinkUrl({
      connectionId: harness.connection.id,
      actorUserId: existing.user.id
    });
    await expect(harness.complete()).resolves.toEqual({
      status: "linked",
      destination: null
    });
    expect((await harness.storage.listAccountsByUserId(existing.user.id))
      .some((account) => account.provider === `saml.${harness.connection.key}`)).toBe(true);
  });

  it("does not silently re-add a removed organisation member", async () => {
    const harness = await createSamlHarness();
    await harness.auth.saml.createSignInUrl({ connectionId: harness.connection.id });
    const signedIn = await harness.complete();
    if (signedIn.status !== "complete") throw new Error("Expected completed SAML sign-in");

    await harness.auth.removeMember({
      organisationId: harness.organisation.id,
      userId: signedIn.user.id,
      actorUserId: harness.ownerId
    });
    await harness.auth.saml.createSignInUrl({ connectionId: harness.connection.id });

    await expect(harness.complete()).rejects.toMatchObject({
      code: "saml_membership_required"
    });
    expect(await harness.storage.getOrganisationMember(
      harness.organisation.id,
      signedIn.user.id
    )).toMatchObject({ status: "removed" });
  });

  it("returns an MFA challenge without creating a session", async () => {
    const harness = await createSamlHarness();
    await harness.auth.saml.createSignInUrl({ connectionId: harness.connection.id });
    const first = await harness.complete();
    if (first.status !== "complete") throw new Error("Expected completed SAML sign-in");
    const sessionsBefore = await harness.storage.listSessionsByUserId(first.user.id);
    const now = new Date();
    await harness.storage.createTotpFactor({
      id: "mfa_saml_test",
      userId: first.user.id,
      status: "active",
      ciphertext: "test-only",
      nonce: "test-only",
      encryptionKeyId: "test-only",
      lastUsedTimestep: null,
      createdAt: now,
      updatedAt: now,
      disabledAt: null
    });

    await harness.auth.saml.createSignInUrl({ connectionId: harness.connection.id });
    const challenged = await harness.complete();
    expect(challenged).toMatchObject({ status: "mfa_required" });
    expect(await harness.storage.listSessionsByUserId(first.user.id)).toHaveLength(
      sessionsBefore.length
    );
  });

  it("allows only one winner when the same response arrives concurrently", async () => {
    const harness = await createSamlHarness();
    await harness.auth.saml.createSignInUrl({ connectionId: harness.connection.id });

    const results = await Promise.allSettled([harness.complete(), harness.complete()]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
  });

  it("preserves the unsupported-algorithm diagnostic for server error handling", async () => {
    const harness = await createSamlHarness();
    await harness.auth.saml.createSignInUrl({ connectionId: harness.connection.id });
    harness.provider.failure = new SamlProtocolError(
      "saml_signature_algorithm_unsupported",
      "SAML response uses an unsupported signature algorithm"
    );

    await expect(harness.complete()).rejects.toMatchObject({
      code: "saml_signature_algorithm_unsupported"
    });
  });

  it("verifies a paired SCIM email exactly once after trusted SAML sign-in", async () => {
    const harness = await createSamlHarness();
    const scimConnection = await harness.auth.scim.createConnection({
      organisationId: harness.organisation.id,
      actorUserId: harness.ownerId,
      name: "Acme provisioning",
      samlConnectionId: harness.connection.id
    });
    const token = await harness.auth.scim.createToken({
      connectionId: scimConnection.id,
      actorUserId: harness.ownerId,
      name: "Identity provider"
    });
    const handler = createOwnAuthScimHandler(harness.auth);
    const provisioned = await handler(new Request("https://app.example.com/scim/v2/Users", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token.rawToken}`,
        "content-type": "application/scim+json"
      },
      body: JSON.stringify({
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        externalId: "workforce-saml-user",
        userName: harness.provider.email,
        emails: [{ value: harness.provider.email, primary: true }]
      })
    }));
    expect(provisioned.status).toBe(201);
    expect(await harness.storage.getUserByEmail(harness.provider.email)).toMatchObject({
      emailVerifiedAt: null
    });

    for (let attempt = 0; attempt < 2; attempt += 1) {
      await harness.auth.saml.createSignInUrl({ connectionId: harness.connection.id });
      await expect(harness.complete()).resolves.toMatchObject({ status: "complete" });
    }

    expect(await harness.storage.getUserByEmail(harness.provider.email)).toMatchObject({
      emailVerifiedAt: expect.any(Date)
    });
    const verificationEvents = (await harness.storage.listAuditEvents())
      .filter((event) => event.eventType === "email.verified" &&
        event.metadata.scimConnectionId === scimConnection.id);
    expect(verificationEvents).toHaveLength(1);
  });
});
