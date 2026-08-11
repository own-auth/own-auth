import { describe, expect, it, vi } from "vitest";
import {
  AuthError,
  createOwnAuth,
  InMemoryAuthStorage,
  isAuthError
} from "../src/index.js";

describe("AuthError", () => {
  it("is recognised across duplicated package-module boundaries", async () => {
    vi.resetModules();
    const duplicate = await import("../src/index.js");
    const auth = createOwnAuth({ storage: new InMemoryAuthStorage() });

    const error = await auth.signInEmailPassword({
      email: "missing@example.com",
      password: "wrong-password"
    }).catch((caught: unknown) => caught);

    expect(AuthError).not.toBe(duplicate.AuthError);
    expect(error).toBeInstanceOf(duplicate.AuthError);
    expect(duplicate.isAuthError(error)).toBe(true);
    expect(error).toMatchObject({ code: "invalid_credentials" });
    expect(duplicate.toAuthError(error)).toBe(error);
  });

  it("does not accept unbranded errors with matching public fields", () => {
    const error = Object.assign(new Error("Invalid email or password"), {
      name: "AuthError",
      code: "invalid_credentials",
      statusCode: 401,
      safeMessage: "Invalid email or password"
    });

    expect(isAuthError(error)).toBe(false);
    expect(error).not.toBeInstanceOf(AuthError);
  });

  it("preserves normal instanceof behavior for AuthError subclasses", () => {
    class SpecificAuthError extends AuthError {}

    const baseError = new AuthError("invalid_credentials", "Invalid credentials", 401);
    const specificError = new SpecificAuthError(
      "invalid_credentials",
      "Invalid credentials",
      401
    );

    expect(baseError).not.toBeInstanceOf(SpecificAuthError);
    expect(specificError).toBeInstanceOf(SpecificAuthError);
    expect(specificError).toBeInstanceOf(AuthError);
  });
});
