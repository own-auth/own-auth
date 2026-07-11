import { describe, expect, it } from "vitest";
import {
  createOwnAuth,
  InMemoryAuthStorage,
  MemoryEmailProvider
} from "../src/index.js";

function createTestAuth() {
  return createOwnAuth({
    storage: new InMemoryAuthStorage(),
    emailProvider: new MemoryEmailProvider(),
    exposeRawTokens: true,
    baseUrl: "http://localhost:3000",
    tokenPepper: "organisation-access-test-pepper"
  });
}

describe("organisation access", () => {
  it("returns an organisation to an active member", async () => {
    const auth = createTestAuth();
    const owner = await auth.signUpEmailPassword({
      email: "owner@example.com",
      password: "correct-horse"
    });
    const { organisation } = await auth.createOrganisation({
      name: "Example Co",
      ownerUserId: owner.user.id
    });

    const result = await auth.getOrganisation({
      organisationId: organisation.id,
      actorUserId: owner.user.id
    });

    expect(result).toEqual(organisation);
  });

  it("does not expose an organisation to a user without membership", async () => {
    const auth = createTestAuth();
    const owner = await auth.signUpEmailPassword({
      email: "owner@example.com",
      password: "correct-horse"
    });
    const outsider = await auth.signUpEmailPassword({
      email: "outsider@example.com",
      password: "correct-horse"
    });
    const { organisation } = await auth.createOrganisation({
      name: "Private Co",
      ownerUserId: owner.user.id
    });

    await expect(auth.getOrganisation({
      organisationId: organisation.id,
      actorUserId: outsider.user.id
    })).rejects.toMatchObject({
      code: "organisation_not_found",
      statusCode: 404
    });
  });

  it("does not expose an organisation to a removed member", async () => {
    const auth = createTestAuth();
    const owner = await auth.signUpEmailPassword({
      email: "owner@example.com",
      password: "correct-horse"
    });
    const { organisation } = await auth.createOrganisation({
      name: "Former Member Co",
      ownerUserId: owner.user.id
    });
    const formerUser = await auth.createUser({ email: "former-member@example.com" });
    const invitation = await auth.inviteMember({
      organisationId: organisation.id,
      email: "former-member@example.com",
      invitedByUserId: owner.user.id
    });
    await auth.acceptInvite({
      token: invitation.token ?? "",
      userId: formerUser.id
    });

    await auth.removeMember({
      organisationId: organisation.id,
      userId: formerUser.id,
      actorUserId: owner.user.id
    });

    await expect(auth.getMember({
      organisationId: organisation.id,
      userId: formerUser.id,
      actorUserId: owner.user.id
    })).rejects.toMatchObject({
      code: "member_not_found",
      statusCode: 404
    });

    await expect(auth.getOrganisation({
      organisationId: organisation.id,
      actorUserId: formerUser.id
    })).rejects.toMatchObject({
      code: "organisation_not_found",
      statusCode: 404
    });
  });

  it("lists active organisation members", async () => {
    const auth = createTestAuth();
    const owner = await auth.signUpEmailPassword({
      email: "member-list-owner@example.com",
      password: "correct-horse",
      name: "Alice"
    });
    const activeUser = await auth.signUpEmailPassword({
      email: "active-list-member@example.com",
      password: "correct-horse",
      name: "Bob"
    });
    const removedUser = await auth.createUser({
      email: "removed-list-member@example.com"
    });
    const { organisation } = await auth.createOrganisation({
      name: "Member List Co",
      ownerUserId: owner.user.id
    });
    const activeInvitation = await auth.inviteMember({
      organisationId: organisation.id,
      email: "active-list-member@example.com",
      invitedByUserId: owner.user.id
    });
    const active = await auth.acceptInvite({
      token: activeInvitation.token ?? "",
      userId: activeUser.user.id
    });
    const removedInvitation = await auth.inviteMember({
      organisationId: organisation.id,
      email: "removed-list-member@example.com",
      invitedByUserId: owner.user.id
    });
    await auth.acceptInvite({
      token: removedInvitation.token ?? "",
      userId: removedUser.id
    });
    await auth.removeMember({
      organisationId: organisation.id,
      userId: removedUser.id,
      actorUserId: owner.user.id
    });

    const members = await auth.listMembers({
      organisationId: organisation.id,
      actorUserId: activeUser.user.id
    });

    expect(members).toEqual([
      expect.objectContaining({
        userId: owner.user.id,
        name: "Alice",
        email: "member-list-owner@example.com",
        role: "owner"
      }),
      expect.objectContaining({
        userId: activeUser.user.id,
        name: "Bob",
        email: "active-list-member@example.com",
        role: "member"
      })
    ]);
    expect(members.every((member) => member.status === "active")).toBe(true);

    const member = await auth.getMember({
      organisationId: organisation.id,
      userId: activeUser.user.id,
      actorUserId: owner.user.id
    });
    expect(member).toMatchObject({
      id: active.member.id,
      userId: activeUser.user.id,
      name: "Bob",
      email: "active-list-member@example.com",
      role: "member"
    });
  });

  it("does not return a member from another organisation", async () => {
    const auth = createTestAuth();
    const firstOwner = await auth.signUpEmailPassword({
      email: "first-member-owner@example.com",
      password: "correct-horse"
    });
    const secondOwner = await auth.signUpEmailPassword({
      email: "second-member-owner@example.com",
      password: "correct-horse"
    });
    const first = await auth.createOrganisation({
      name: "First Members Co",
      ownerUserId: firstOwner.user.id
    });
    await auth.createOrganisation({
      name: "Second Members Co",
      ownerUserId: secondOwner.user.id
    });

    await expect(auth.getMember({
      organisationId: first.organisation.id,
      userId: secondOwner.user.id,
      actorUserId: firstOwner.user.id
    })).rejects.toMatchObject({
      code: "member_not_found",
      statusCode: 404
    });
  });

  it("does not list members for a user outside the organisation", async () => {
    const auth = createTestAuth();
    const owner = await auth.signUpEmailPassword({
      email: "private-members-owner@example.com",
      password: "correct-horse"
    });
    const outsider = await auth.signUpEmailPassword({
      email: "private-members-outsider@example.com",
      password: "correct-horse"
    });
    const { organisation } = await auth.createOrganisation({
      name: "Private Members Co",
      ownerUserId: owner.user.id
    });

    await expect(auth.listMembers({
      organisationId: organisation.id,
      actorUserId: outsider.user.id
    })).rejects.toMatchObject({
      code: "permission_denied",
      statusCode: 403
    });
  });

  it("permanently deletes an organisation without deleting users", async () => {
    const auth = createTestAuth();
    const owner = await auth.signUpEmailPassword({
      email: "delete-owner@example.com",
      password: "correct-horse"
    });
    const { organisation } = await auth.createOrganisation({
      name: "Delete Me Co",
      ownerUserId: owner.user.id
    });
    const activeUser = await auth.createUser({ email: "active-member@example.com" });
    const pendingUser = await auth.createUser({ email: "pending-member@example.com" });
    const acceptedInvitation = await auth.inviteMember({
      organisationId: organisation.id,
      email: "active-member@example.com",
      invitedByUserId: owner.user.id
    });
    await auth.acceptInvite({
      token: acceptedInvitation.token ?? "",
      userId: activeUser.id
    });
    const pendingInvitation = await auth.inviteMember({
      organisationId: organisation.id,
      email: "pending-member@example.com",
      invitedByUserId: owner.user.id
    });
    const key = await auth.createApiKey({
      name: "Production",
      organisationId: organisation.id,
      actorUserId: owner.user.id
    });

    const deleted = await auth.deleteOrganisation({
      organisationId: organisation.id,
      actorUserId: owner.user.id,
      request: { ipAddress: "203.0.113.10" }
    });

    expect(deleted).toEqual(organisation);
    await expect(
      auth.listOrganisations({ actorUserId: owner.user.id })
    ).resolves.toEqual([]);
    await expect(auth.checkPermission(
      organisation.id,
      owner.user.id,
      "manage_organisation"
    )).resolves.toBe(false);
    await expect(auth.getOrganisation({
      organisationId: organisation.id,
      actorUserId: owner.user.id
    })).rejects.toMatchObject({ code: "organisation_not_found" });
    await expect(auth.updateOrganisation(organisation.id, {
      actorUserId: owner.user.id,
      name: "Still Deleted"
    })).rejects.toMatchObject({ code: "organisation_not_found" });
    await expect(auth.verifyApiKey(key.rawKey)).rejects.toMatchObject({
      code: "api_key_invalid"
    });
    await expect(auth.acceptInvite({
      token: pendingInvitation.token ?? "",
      userId: pendingUser.id
    })).rejects.toMatchObject({ code: "invalid_token" });

    const [storedOrganisation, storedMembers, storedKeys, storedInvitations] = await Promise.all([
      auth.storage.getOrganisationById(organisation.id),
      auth.storage.listOrganisationMembers(organisation.id),
      auth.storage.listApiKeysByOrganisationId(organisation.id),
      auth.storage.listInvitationsByOrganisationId(organisation.id)
    ]);
    expect(storedOrganisation).toBeNull();
    expect(storedMembers).toEqual([]);
    expect(storedKeys).toEqual([]);
    expect(storedInvitations).toEqual([]);
    await expect(auth.storage.getUserById(owner.user.id)).resolves.toMatchObject({
      id: owner.user.id
    });
    await expect(auth.storage.getUserById(activeUser.id)).resolves.toMatchObject({
      id: activeUser.id
    });

    const auditEvents = await auth.listAuditEvents({ actorUserId: owner.user.id });
    expect(auditEvents).toEqual(expect.arrayContaining([
      expect.objectContaining({
        eventType: "organisation.deleted",
        actorUserId: owner.user.id,
        organisationId: null,
        ipAddress: "203.0.113.10",
        metadata: {
          organisationId: organisation.id,
          name: organisation.name,
          slug: organisation.slug,
          membersRemoved: 2,
          apiKeysRemoved: 1,
          invitationsRemoved: 2
        }
      })
    ]));

    await expect(auth.deleteOrganisation({
      organisationId: organisation.id,
      actorUserId: owner.user.id
    })).rejects.toMatchObject({ code: "organisation_not_found" });
  });

  it("only allows the organisation owner to delete it", async () => {
    const auth = createTestAuth();
    const owner = await auth.signUpEmailPassword({
      email: "owner-only@example.com",
      password: "correct-horse"
    });
    const { organisation } = await auth.createOrganisation({
      name: "Owner Only Co",
      ownerUserId: owner.user.id
    });
    const adminUser = await auth.createUser({ email: "admin@example.com" });
    const invitation = await auth.inviteMember({
      organisationId: organisation.id,
      email: "admin@example.com",
      role: "admin",
      invitedByUserId: owner.user.id
    });
    await auth.acceptInvite({
      token: invitation.token ?? "",
      userId: adminUser.id
    });

    await expect(auth.deleteOrganisation({
      organisationId: organisation.id,
      actorUserId: adminUser.id
    })).rejects.toMatchObject({
      code: "permission_denied",
      statusCode: 403
    });

    await expect(auth.getOrganisation({
      organisationId: organisation.id,
      actorUserId: owner.user.id
    })).resolves.toMatchObject({ id: organisation.id, disabledAt: null });
  });
});
