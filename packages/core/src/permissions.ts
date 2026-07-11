import type { OrganisationRole } from "./types.js";

export type Permission =
  | "manage_organisation"
  | "invite_members"
  | "remove_members"
  | "change_member_roles"
  | "view_members"
  | "view_audit_events"
  | "manage_sessions"
  | "manage_api_keys"
  | "manage_basic_settings";

const rolePermissions: Record<OrganisationRole, Permission[]> = {
  owner: [
    "manage_organisation",
    "invite_members",
    "remove_members",
    "change_member_roles",
    "view_members",
    "view_audit_events",
    "manage_sessions",
    "manage_api_keys",
    "manage_basic_settings"
  ],
  admin: [
    "invite_members",
    "remove_members",
    "view_members",
    "view_audit_events",
    "manage_sessions",
    "manage_api_keys",
    "manage_basic_settings"
  ],
  member: ["view_members"]
};

export function permissionsForRole(role: OrganisationRole): Permission[] {
  return [...rolePermissions[role]];
}

export function roleHasPermission(role: OrganisationRole, permission: Permission): boolean {
  return rolePermissions[role].includes(permission);
}
