import { describe, expect, it } from "vitest";
import {
  createOwnAuth,
  InMemoryAuthStorage,
  type Session
} from "../src/index.js";

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

  it.each(["revoked", "missing", "disabled"] as const)(
    "fails closed when a session becomes %s during its activity update",
    async (outcome) => {
      const storage = new SessionTouchRaceStorage(outcome);
      const auth = createOwnAuth({
        storage,
        tokenPepper: `session-${outcome}-race`
      });
      const signup = await auth.signUpEmailPassword({
        email: `${outcome}-session-race@example.com`,
        password: "correct-horse"
      });
      storage.arm(signup.user.id);

      await expect(auth.getCurrentSession(signup.sessionToken)).resolves.toBeNull();
    }
  );
});

class SessionTouchRaceStorage extends InMemoryAuthStorage {
  private armed = false;
  private userId: string | null = null;

  constructor(private readonly outcome: "revoked" | "missing" | "disabled") {
    super();
  }

  arm(userId: string): void {
    this.armed = true;
    this.userId = userId;
  }

  override async updateSession(
    id: string,
    patch: Partial<Session>
  ): Promise<Session | null> {
    if (!this.armed || !patch.lastActiveAt) {
      return super.updateSession(id, patch);
    }
    this.armed = false;
    if (this.outcome === "missing") {
      return null;
    }
    if (this.outcome === "disabled") {
      await super.updateUser(this.userId ?? "", {
        disabledAt: new Date(),
        updatedAt: new Date()
      });
      return super.updateSession(id, patch);
    }
    await super.updateSession(id, {
      revokedAt: new Date(),
      revokeReason: "concurrent_revocation"
    });
    return super.updateSession(id, patch);
  }
}
