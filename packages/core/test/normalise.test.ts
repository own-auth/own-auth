import { describe, expect, it } from "vitest";
import {
  isExpired,
  isValidEmailAddress,
  isValidE164Phone,
  normalizeEmail,
  normalizePhone,
  slugify
} from "../src/normalise.js";

describe("normalizeEmail", () => {
  it("lowercases and trims", () => {
    expect(normalizeEmail("  User@Example.COM  ")).toBe("user@example.com");
  });

  it("handles already-normalized emails", () => {
    expect(normalizeEmail("user@example.com")).toBe("user@example.com");
  });

  it("validates normalized email addresses", () => {
    expect(isValidEmailAddress("user@example.com")).toBe(true);
    expect(isValidEmailAddress("missing-at.example.com")).toBe(false);
    expect(isValidEmailAddress("@example.com")).toBe(false);
    expect(isValidEmailAddress("user@")).toBe(false);
    expect(isValidEmailAddress("user @example.com")).toBe(false);
  });

  it.each([
    "user@example@com",
    ".user@example.com",
    "user.@example.com",
    "user..name@example.com",
    "user@example..com",
    "user\u0000@example.com"
  ])("rejects structurally invalid email address %j", (email) => {
    expect(isValidEmailAddress(email)).toBe(false);
  });
});

describe("normalizePhone", () => {
  it("strips common phone-number formatting", () => {
    expect(normalizePhone("+1 (555) 123-4567")).toBe("+15551234567");
  });

  it("keeps a plain number as-is", () => {
    expect(normalizePhone("+15551234567")).toBe("+15551234567");
  });

  it("strips dots and spaces", () => {
    expect(normalizePhone("+1.555.123.4567")).toBe("+15551234567");
  });

  it("does not hide unsupported characters from validation", () => {
    const normalized = normalizePhone("call +1 (555) 123-4567");

    expect(normalized).toBe("call+15551234567");
    expect(isValidE164Phone(normalized)).toBe(false);
  });

  it("validates normalized E.164 numbers", () => {
    expect(isValidE164Phone("+15551234567")).toBe(true);
    expect(isValidE164Phone("15551234567")).toBe(false);
    expect(isValidE164Phone("+0123456789")).toBe(false);
    expect(isValidE164Phone("++15551234567")).toBe(false);
  });
});

describe("slugify", () => {
  it("converts to lowercase hyphenated slug", () => {
    expect(slugify("My Organisation")).toBe("my-organisation");
  });

  it("strips special characters", () => {
    expect(slugify("Acme & Co!")).toBe("acme-co");
  });

  it("trims leading and trailing hyphens", () => {
    expect(slugify("--hello--")).toBe("hello");
  });

  it("collapses multiple separators", () => {
    expect(slugify("a   b   c")).toBe("a-b-c");
  });

  it("falls back to 'organisation' for empty input", () => {
    expect(slugify("")).toBe("organisation");
    expect(slugify("!!!")).toBe("organisation");
  });
});

describe("isExpired", () => {
  it("returns true when date is in the past", () => {
    const past = new Date(Date.now() - 1000);
    expect(isExpired(past)).toBe(true);
  });

  it("returns false when date is in the future", () => {
    const future = new Date(Date.now() + 60_000);
    expect(isExpired(future)).toBe(false);
  });

  it("returns true when date equals now", () => {
    const now = new Date();
    expect(isExpired(now, now)).toBe(true);
  });

  it("accepts a custom now parameter", () => {
    const date = new Date("2025-01-01T00:00:00Z");
    const before = new Date("2024-12-31T00:00:00Z");
    const after = new Date("2025-01-02T00:00:00Z");
    expect(isExpired(date, before)).toBe(false);
    expect(isExpired(date, after)).toBe(true);
  });
});
