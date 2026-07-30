import { describe, expect, it } from "vitest";
import {
  createOwnAuth,
  createOwnAuthHandler,
  InMemoryAuthStorage,
  MemoryEmailProvider,
  MemorySmsProvider
} from "../src/index.js";
import { jsonRequest } from "./http-test-helpers.js";

function createHarness(options: Parameters<typeof createOwnAuthHandler>[1] = {}) {
  const auth = createOwnAuth({
    storage: new InMemoryAuthStorage(),
    emailProvider: new MemoryEmailProvider(),
    smsProvider: new MemorySmsProvider(),
    tokenPepper: "http-handler-test-pepper"
  });
  return { auth, handler: createOwnAuthHandler(auth, options) };
}

describe("createOwnAuthHandler", () => {
  it("creates a secure session cookie without returning raw secrets", async () => {
    const { handler } = createHarness();

    const response = await handler(jsonRequest("/api/auth/sign-up/email", {
      email: "user@example.com",
      password: "correct-horse"
    }));
    const body = await response.json() as Record<string, unknown>;
    const cookie = response.headers.get("set-cookie");

    expect(response.status).toBe(200);
    expect(cookie).toContain("own_auth_session=");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).not.toContain("Secure");
    expect(body).not.toHaveProperty("sessionToken");
    expect(body.user).not.toHaveProperty("passwordHash");
    expect(body.session).not.toHaveProperty("tokenHash");
  });

  it("marks production HTTPS session cookies as Secure", async () => {
    const { handler } = createHarness();
    const response = await handler(jsonRequest(
      "/api/auth/sign-up/email",
      { email: "secure@example.com", password: "correct-horse" },
      {},
      "https://app.example.com"
    ));

    expect(response.headers.get("set-cookie")).toContain("Secure");
  });

  it("reads the session from the central cookie", async () => {
    const { handler } = createHarness();
    const signup = await handler(jsonRequest("/api/auth/sign-up/email", {
      email: "session@example.com",
      password: "correct-horse"
    }));
    const cookie = signup.headers.get("set-cookie")?.split(";", 1)[0] ?? "";

    const response = await handler(new Request("http://localhost/api/auth/session", {
      headers: { cookie }
    }));
    const body = await response.json() as { session: { user: { email: string } } | null };

    expect(body.session?.user.email).toBe("session@example.com");
  });

  it("accepts bearer sessions for non-browser callers", async () => {
    const { auth, handler } = createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "bearer@example.com",
      password: "correct-horse"
    });

    const response = await handler(new Request("http://localhost/api/auth/session", {
      headers: { authorization: `Bearer ${signup.sessionToken}` }
    }));
    const body = await response.json() as { session: { user: { email: string } } | null };

    expect(body.session?.user.email).toBe("bearer@example.com");
  });

  it("rejects Bearer headers with trailing values", async () => {
    const { auth, handler } = createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "malformed-bearer@example.com",
      password: "correct-horse"
    });

    const response = await handler(new Request("http://localhost/api/auth/session", {
      headers: {
        authorization: `Bearer ${signup.sessionToken} unexpected`
      }
    }));

    await expect(response.json()).resolves.toEqual({ session: null });
  });

  it("fails closed when the session cookie appears more than once", async () => {
    const { auth, handler } = createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "duplicate-cookie@example.com",
      password: "correct-horse"
    });

    const response = await handler(new Request("http://localhost/api/auth/session", {
      headers: {
        cookie: `own_auth_session=untrusted; own_auth_session=${signup.sessionToken}`
      }
    }));

    await expect(response.json()).resolves.toEqual({ session: null });
  });

  it("rejects cross-origin mutation requests", async () => {
    const { handler } = createHarness();
    const response = await handler(jsonRequest(
      "/api/auth/sign-in/email",
      { email: "user@example.com", password: "correct-horse" },
      { origin: "https://evil.example" }
    ));

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "csrf_failed" }
    });
  });

  it("allows explicitly trusted browser origins", async () => {
    const { handler } = createHarness({ trustedOrigins: ["https://app.example.com"] });
    const response = await handler(jsonRequest(
      "/api/auth/sign-up/email",
      { email: "trusted@example.com", password: "correct-horse" },
      { origin: "https://app.example.com" }
    ));

    expect(response.status).toBe(200);
  });

  it("rejects cookie-authenticated mutations without an Origin header", async () => {
    const { auth, handler } = createHarness();
    const signup = await auth.signUpEmailPassword({
      email: "csrf-cookie@example.com",
      password: "correct-horse"
    });
    const response = await handler(new Request("http://localhost/api/auth/sign-out", {
      method: "POST",
      headers: { cookie: `own_auth_session=${signup.sessionToken}` }
    }));

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "csrf_failed" }
    });
  });

  it("returns the documented validation error envelope", async () => {
    const { handler } = createHarness();
    const response = await handler(jsonRequest("/api/auth/sign-in/email", {
      email: "missing-password@example.com"
    }));

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: { code: "validation_error", message: "Invalid request body" }
    });
  });

  it("rejects repeated scalar OAuth callback fields", async () => {
    const { handler } = createHarness();
    const response = await handler(new Request(
      "http://localhost/api/auth/oauth/google/callback?code=first&code=second&state=state"
    ));

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "validation_error" }
    });
  });

  it("rejects JSON bodies over the configured limit", async () => {
    const { handler } = createHarness({ maxRequestBodyBytes: 16 });
    const response = await handler(jsonRequest("/api/auth/sign-in/email", {
      email: "large@example.com",
      password: "correct-horse"
    }));

    expect(response.status).toBe(413);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "invalid_request" }
    });
  });

  it("returns 405 with the allowed method for a known route", async () => {
    const { handler } = createHarness();
    const response = await handler(new Request("http://localhost/api/auth/session", {
      method: "POST",
      headers: { origin: "http://localhost" }
    }));

    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET");
  });
});
