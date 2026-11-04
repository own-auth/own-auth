import { describe, expect, it } from "vitest";
import { rateLimitIpIdentifier } from "../src/rate-limit-ip.js";

describe("IP rate limit identifiers", () => {
  it.each([
    "2001:db8:abcd:12::1",
    "2001:0DB8:ABCD:0012:0000:0000:0000:0001",
    "[2001:db8:abcd:12::2]",
    "2001:db8:abcd:12:ffff:ffff:ffff:ffff"
  ])("shares the same IPv6 network budget for %s", (address) => {
    expect(rateLimitIpIdentifier(address)).toBe("ipv6:2001:db8:abcd:12/64");
  });

  it("keeps separate IPv6 networks independent", () => {
    expect(rateLimitIpIdentifier("2001:db8:abcd:12::1"))
      .not.toBe(rateLimitIpIdentifier("2001:db8:abcd:13::1"));
  });

  it.each(["192.0.2.1", "::ffff:192.0.2.1", "::ffff:c000:201", "[0:0:0:0:0:ffff:c000:201]"])(
    "shares an IPv4 budget with its mapped address %s", (address) => {
      expect(rateLimitIpIdentifier(address)).toBe("192.0.2.1");
    }
  );

  it("keeps distinct IPv4 addresses independent", () => {
    expect(rateLimitIpIdentifier("192.0.2.1")).not.toBe(rateLimitIpIdentifier("192.0.2.2"));
  });

  it.each(["", "random-value", "999.0.0.1", "[::1]:80", "[::1]:443", "[::1]/", "[::1]?x=1", "host.example", "2001:db8:::1"])(
    "puts invalid supplied IP %s in one bounded budget", (address) => {
      expect(rateLimitIpIdentifier(address)).toBe("invalid-ip");
    }
  );
});
