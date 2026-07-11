import { describe, expect, it } from "vitest";
import { permissionsForRole, roleHasPermission } from "../src/permissions.js";
import type { Permission } from "../src/permissions.js";

describe("permissionsForRole", () => {
  it("gives owner all permissions", () => {
    const perms = permissionsForRole("owner");
    expect(perms).toContain("manage_organisation");
    expect(perms).toContain("invite_members");
    expect(perms).toContain("remove_members");
    expect(perms).toContain("change_member_roles");
    expect(perms).toContain("view_members");
    expect(perms).toContain("view_audit_events");
    expect(perms).toContain("manage_sessions");
    expect(perms).toContain("manage_api_keys");
    expect(perms).toContain("manage_basic_settings");
    expect(perms).toHaveLength(9);
  });

  it("does not give admins owner-only permissions", () => {
    const perms = permissionsForRole("admin");
    expect(perms).not.toContain("manage_organisation");
    expect(perms).not.toContain("change_member_roles");
    expect(perms).toContain("invite_members");
    expect(perms).toContain("manage_api_keys");
    expect(perms).toHaveLength(7);
  });

  it("gives member only view_members", () => {
    const perms = permissionsForRole("member");
    expect(perms).toEqual(["view_members"]);
  });

  it("returns a copy, not the original array", () => {
    const a = permissionsForRole("owner");
    const b = permissionsForRole("owner");
    expect(a).not.toBe(b);
    expect(a).toEqual(b);
  });
});

describe("roleHasPermission", () => {
  it("owner has manage_organisation", () => {
    expect(roleHasPermission("owner", "manage_organisation")).toBe(true);
  });

  it("admin does not have manage_organisation", () => {
    expect(roleHasPermission("admin", "manage_organisation")).toBe(false);
  });

  it("member does not have invite_members", () => {
    expect(roleHasPermission("member", "invite_members")).toBe(false);
  });

  it("member has view_members", () => {
    expect(roleHasPermission("member", "view_members")).toBe(true);
  });

  const allPermissions: Permission[] = [
    "manage_organisation",
    "invite_members",
    "remove_members",
    "change_member_roles",
    "view_members",
    "view_audit_events",
    "manage_sessions",
    "manage_api_keys",
    "manage_basic_settings"
  ];

  it("owner has every permission", () => {
    for (const perm of allPermissions) {
      expect(roleHasPermission("owner", perm)).toBe(true);
    }
  });
});
