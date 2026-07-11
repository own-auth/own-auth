# Roles

Own Auth ships with three built-in roles:

| Role | Description |
|---|---|
| `owner` | Full control. Can manage members, change roles, update the organisation, and delete it. |
| `admin` | Can manage members and update the organisation. Cannot change roles or delete the organisation. |
| `member` | Basic access. Cannot manage members or update the organisation. |

These roles are fixed in the MVP. Custom roles with granular permissions are planned for a future release.

## What each role can do

| Permission | Owner | Admin | Member |
|---|---|---|---|
| Update organisation | Yes | Yes | No |
| Delete organisation | Yes | No | No |
| Invite members | Yes | Yes | No |
| Remove members | Yes | Yes | No |
| Change member roles | Yes | No | No |
| View members | Yes | Yes | Yes |
| View audit events | Yes | Yes | No |
| Manage sessions | Yes | Yes | No |
| Manage API keys | Yes | Yes | No |

Only owners can change roles or remove another owner. Admins can invite and remove non-owner members. The last owner cannot be demoted or removed.

Own Auth's organisation methods check these permissions internally. Use the helpers below when protecting organisation-specific actions in the surrounding application.

## Check A Permission

Use `checkPermission` when the application handles a denied action itself.

```ts
const allowed = await auth.checkPermission(
  organisationId,
  currentUser.id,
  "invite_members",
);
```

## Require A Permission

Use `requirePermission` when the action must stop immediately. It returns the active membership when allowed and throws `permission_denied` otherwise.

```ts
const membership = await auth.requirePermission(
  organisationId,
  currentUser.id,
  "manage_api_keys",
);
```

Permission checks require an active membership. Removed or unknown members are denied.

## Next step

Learn about [Invites](/docs/organisations/invites) to bring new members in by email, or add [API keys](/docs/api-keys) for programmatic access.
