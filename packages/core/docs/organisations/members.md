# Members

Members are users who belong to an organisation. Each member has a role that determines what they can do within that organisation.

## Add a member

Members join by accepting an organisation invitation. The returned member is active and uses the role assigned by the invitation.

```ts
const { organisation, member } = await auth.acceptInvite({
  token,
  userId: currentUser.id,
});
```

## Get a member

```ts
const member = await auth.getMember({
  organisationId,
  userId: targetUser.id,
  actorUserId: currentUser.id,
});

// member -> {
//   id: "mem_...",
//   userId: "usr_...",
//   name: "Alice",
//   email: "alice@example.com",
//   role: "owner",
//   status: "active",
//   joinedAt: new Date("2026-07-11T..."),
// }
```

The requesting user must have the `view_members` permission. A missing, removed, or different organisation's member returns `member_not_found`.

## List members

```ts
const members = await auth.listMembers({
  organisationId,
  actorUserId: currentUser.id,
});

// members -> [
//   {
//     id: "mem_...",
//     userId: "usr_...",
//     name: "Alice",
//     email: "alice@example.com",
//     role: "owner",
//     status: "active",
//     joinedAt: new Date("2026-07-11T..."),
//   },
// ]
```

The requesting user must be an active organisation member with the `view_members` permission. The result contains active members with their name, email, role, and membership dates.

## Change a member's role

```ts
await auth.changeMemberRole({
  organisationId: organisation.id,
  userId: targetUser.id,
  role: "admin",
  actorUserId: currentUser.id,
});
```

Only owners can change roles. Role changes take effect immediately.

### What each role can do

| Action | Owner | Admin | Member |
|---|---|---|---|
| Manage members | Yes | Yes | No |
| Update organisation | Yes | Yes | No |
| Change roles | Yes | No | No |
| Delete organisation | Yes | No | No |

### Role rules

- An owner can promote a member to admin or owner.
- An owner can demote an admin to member.
- An admin cannot change another admin's or owner's role.
- A member cannot change any roles.
- The last owner cannot be demoted. Promote another member to owner first.

### Errors

| Code | When |
|---|---|
| `last_owner` | Trying to demote the only owner. |
| `permission_denied` | The acting user does not have permission to change roles. |
| `member_not_found` | The target user is not an active member of this organisation. |

## Remove a member

The actor must have the `remove_members` permission.

```ts
await auth.removeMember({
  organisationId: organisation.id,
  userId: targetUser.id,
  actorUserId: currentUser.id,
});
```

The user loses access to the organisation immediately. Their user account is not affected.

Only an owner can remove another owner. Owners cannot be removed unless another owner exists. The last owner of an organisation cannot be removed. Transfer ownership first by promoting another member to owner.

### Errors

| Code | When |
|---|---|
| `last_owner` | Trying to remove the only owner. Promote someone else first. |
| `member_not_found` | The user is not an active member of this organisation. |
| `permission_denied` | The acting user does not have permission to remove the member. |

## Next step

Learn about [Invites](/docs/organisations/invites) to bring new members in by email, or add [API keys](/docs/api-keys) for programmatic access.
