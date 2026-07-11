import { describe, expect, it } from "vitest";
import { createOwnAuth, InMemoryAuthStorage } from "../src/index.js";

function createTestAuth() {
  return createOwnAuth({
    storage: new InMemoryAuthStorage(),
    tokenPepper: "session-revocation-test-pepper"
  });
}

describe("session revocation", () => {
  it("revokes one session owned by the current user", async () => {
    const auth = createTestAuth();
    const first = await auth.signUpEmailPassword({
      email: "sessions@example.com",
      password: "correct-horse"
    });
    const second = await auth.signInEmailPassword({
      email: "sessions@example.com",
      password: "correct-horse"
    });

    const revoked = await auth.revokeSession({
      sessionToken: first.sessionToken,
      sessionId: second.session.id,
      request: {
        ipAddress: "203.0.113.10",
        userAgent: "Session settings"
      }
    });

    expect(revoked.revokedAt).toBeInstanceOf(Date);
    expect(revoked.revokeReason).toBe("user_revoked");
    await expect(auth.getCurrentSession(first.sessionToken)).resolves.not.toBeNull();
    await expect(auth.getCurrentSession(second.sessionToken)).resolves.toBeNull();

    const events = await auth.listAuditEvents({ actorUserId: first.user.id });
    expect(events).toEqual(expect.arrayContaining([
      expect.objectContaining({
        eventType: "session.revoked",
        ipAddress: "203.0.113.10",
        metadata: {
          reason: "user_revoked",
          sessionId: second.session.id
        }
      })
    ]));
  });

  it("allows the current session to revoke itself by ID", async () => {
    const auth = createTestAuth();
    const signup = await auth.signUpEmailPassword({
      email: "self-revoke@example.com",
      password: "correct-horse"
    });

    await auth.revokeSession({
      sessionToken: signup.sessionToken,
      sessionId: signup.session.id
    });

    await expect(auth.getCurrentSession(signup.sessionToken)).resolves.toBeNull();
  });

  it("does not revoke a session owned by another user", async () => {
    const auth = createTestAuth();
    const actor = await auth.signUpEmailPassword({
      email: "actor@example.com",
      password: "correct-horse"
    });
    const other = await auth.signUpEmailPassword({
      email: "other@example.com",
      password: "correct-horse"
    });

    await expect(auth.revokeSession({
      sessionToken: actor.sessionToken,
      sessionId: other.session.id
    })).rejects.toMatchObject({
      code: "invalid_session",
      statusCode: 404
    });

    await expect(auth.getCurrentSession(other.sessionToken)).resolves.not.toBeNull();
  });
});
