import { describe, expect, it } from "vitest";
import {
  randomBase64Url,
  randomNumericCode,
  createId,
  hashSecret,
  safeEqual,
  hashPassword,
  passwordNeedsRehash,
  verifyPassword
} from "../src/crypto.js";
import { createPbkdf2PasswordHasher } from "../src/password-hashing.js";
import {
  legacyScryptHash,
  nativeArgon2idHash
} from "./password-hash-fixtures.js";

describe("randomBase64Url", () => {
  it("returns a URL-safe base64 string of the expected length", () => {
    const token = randomBase64Url(32);
    expect(token.length).toBeGreaterThan(0);
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("produces unique values", () => {
    const a = randomBase64Url(32);
    const b = randomBase64Url(32);
    expect(a).not.toBe(b);
  });
});

describe("randomNumericCode", () => {
  it("returns a string of the requested length", () => {
    expect(randomNumericCode(6)).toHaveLength(6);
    expect(randomNumericCode(4)).toHaveLength(4);
    expect(randomNumericCode(8)).toHaveLength(8);
  });

  it("contains only digits", () => {
    for (let i = 0; i < 20; i++) {
      expect(randomNumericCode(6)).toMatch(/^\d+$/);
    }
  });
});

describe("createId", () => {
  it("returns a prefixed random id", () => {
    const id = createId("usr");
    expect(id).toMatch(/^usr_[A-Za-z0-9_-]+$/);
  });

  it("produces unique ids", () => {
    const a = createId("usr");
    const b = createId("usr");
    expect(a).not.toBe(b);
  });
});

describe("hashSecret", () => {
  it("returns a hex SHA-256 hash without pepper", () => {
    const hash = hashSecret("test-value");
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it("returns a different hash with pepper", () => {
    const plain = hashSecret("test-value");
    const peppered = hashSecret("test-value", "my-pepper");
    expect(plain).not.toBe(peppered);
    expect(peppered).toMatch(/^[a-f0-9]{64}$/);
  });

  it("is deterministic", () => {
    expect(hashSecret("foo", "bar")).toBe(hashSecret("foo", "bar"));
    expect(hashSecret("foo")).toBe(hashSecret("foo"));
  });

  it("treats empty pepper same as no pepper", () => {
    expect(hashSecret("foo", "")).toBe(hashSecret("foo"));
  });
});

describe("safeEqual", () => {
  it("returns true for equal strings", () => {
    expect(safeEqual("abc", "abc")).toBe(true);
  });

  it("returns false for different strings", () => {
    expect(safeEqual("abc", "xyz")).toBe(false);
  });

  it("returns false for different lengths", () => {
    expect(safeEqual("short", "longer-string")).toBe(false);
  });
});

describe("hashPassword / verifyPassword", () => {
  it("verifies a correct password", async () => {
    const hash = await hashPassword("my-password");
    expect(await verifyPassword("my-password", hash)).toBe(true);
  });

  it("rejects a wrong password", async () => {
    const hash = await hashPassword("my-password");
    expect(await verifyPassword("wrong-password", hash)).toBe(false);
  });

  it("produces unique hashes for the same password", async () => {
    const a = await hashPassword("same");
    const b = await hashPassword("same");
    expect(a).not.toBe(b);
  });

  it("uses the current Argon2id parameters", async () => {
    const hash = await hashPassword("test");
    expect(hash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    expect(passwordNeedsRehash(hash)).toBe(false);
  });

  it("verifies Argon2id hashes created by the previous native implementation", async () => {
    expect(await verifyPassword("worker-compatible-password", nativeArgon2idHash)).toBe(true);
    expect(await verifyPassword("wrong-password", nativeArgon2idHash)).toBe(false);
    expect(passwordNeedsRehash(nativeArgon2idHash)).toBe(false);
  });

  it("verifies legacy scrypt hashes and marks them for rehashing", async () => {
    const hash = legacyScryptHash("old-password");

    expect(await verifyPassword("old-password", hash)).toBe(true);
    expect(await verifyPassword("wrong-password", hash)).toBe(false);
    expect(passwordNeedsRehash(hash)).toBe(true);
  });

  it("rejects legacy hashes with altered work factors", async () => {
    const hash = legacyScryptHash("old-password").replace("scrypt$16384$", "scrypt$32768$");

    expect(await verifyPassword("old-password", hash)).toBe(false);
  });

  it("rejects a malformed hash", async () => {
    expect(await verifyPassword("test", "garbage")).toBe(false);
    expect(await verifyPassword("test", "wrong$format")).toBe(false);
    expect(await verifyPassword("test", "$argon2id$broken")).toBe(false);
  });

  it("rejects oversized password inputs before expensive hashing work", async () => {
    const oversized = "a".repeat(4_097);

    await expect(hashPassword(oversized)).rejects.toThrow("Password input is too long.");
    await expect(verifyPassword(oversized, nativeArgon2idHash)).resolves.toBe(false);
  });
});

describe("createPbkdf2PasswordHasher", () => {
  const hasher = createPbkdf2PasswordHasher();

  it("uses native Web Crypto PBKDF2 with the current work factor", async () => {
    const hash = await hasher.hash("worker-password");

    expect(hash).toMatch(/^pbkdf2-sha256\$600000\$/);
    expect(await hasher.verify("worker-password", hash)).toBe(true);
    expect(await hasher.verify("wrong-password", hash)).toBe(false);
    expect(hasher.needsRehash(hash)).toBe(false);
    expect(await verifyPassword("worker-password", hash)).toBe(true);
    expect(passwordNeedsRehash(hash)).toBe(false);
  });

  it("accepts existing Argon2id hashes and marks them for migration", async () => {
    expect(await hasher.verify("worker-compatible-password", nativeArgon2idHash)).toBe(true);
    expect(hasher.needsRehash(nativeArgon2idHash)).toBe(true);
  });
});
