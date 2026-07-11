# Invites

Invite users to join an organisation by email. The invited person receives an email containing a single-use link and accepts the organisation membership through the application.

## Create an invite

The inviting user must have the `invite_members` permission.

```ts
const { invitation } = await auth.inviteMember({
  organisationId: organisation.id,
  email: "bob@example.com",
  role: "member",
  invitedByUserId: currentUser.id,
});

// invitation.id        -> "inv_a1b2c3..."
// invitation.email     -> "bob@example.com"
// invitation.role      -> "member"
// invitation.expiresAt -> Date
```

Own Auth creates the invitation, generates a single-use token, stores only its hash, and sends the invitation through the configured email provider. The email link points to the application, or to a [hosted page](/docs/hosted-auth-links) when hosted links are enabled.

### Errors

| Code | When |
|---|---|
| `already_member` | The invited email is already an active member of this organisation. |
| `invite_exists` | A pending invite for this email and organisation already exists. |
| `permission_denied` | The inviting user does not have permission to invite members. |
| `rate_limited` | Too many invites have been sent for this organisation. |

## List invitations

Pass the signed-in user as the actor:

```ts
const invitations = await auth.listInvitations({
  organisationId,
  actorUserId: currentUser.id,
});

// invitations -> [
//   {
//     id: "inv_...",
//     email: "bob@example.com",
//     role: "member",
//     status: "pending",
//     expiresAt: new Date("2026-07-18T..."),
//   },
// ]
```

Own Auth checks the actor's active membership and `invite_members` permission before returning invitations.

`listInvitations` returns every invitation record for the organisation, including accepted, revoked, and expired invitations. Filter by `status` and `expiresAt` when displaying only pending invitations:

```ts
const now = new Date();
const pendingInvitations = invitations.filter(
  (invitation) =>
    invitation.status === "pending" && invitation.expiresAt > now,
);
```

## Accept an invite

When the invited person clicks the link and reaches the application, check that they are signed in and accept the invite in the backend:

```ts
const { organisation, member } = await auth.acceptInvite({
  token: tokenFromUrl,
  userId: currentUser.id,
});

// organisation.name -> "Acme Corp"
// member.role        -> "member"
```

This consumes the token, adds the user to the organisation with the specified role, and writes an audit log entry.

### If the user does not have an account

The application handles signup or signin before accepting the invite:

1. The user clicks the invite link and arrives at the application.
2. If the user is not signed in, redirect them to sign up or sign in.
3. Preserve the invite token while they complete authentication.
4. Call `acceptInvite` with the token and signed-in user ID.

Store the invite token temporarily in the session or an HTTP-only cookie:

```ts
// On invite link click, if the user is not signed in:
res.cookie("pending_invite", tokenFromUrl, {
  httpOnly: true,
  maxAge: 60 * 60 * 1000,
});
res.redirect("/sign-up");

// After signup or signin completes:
const pendingInvite = req.cookies.pending_invite;
if (pendingInvite) {
  await auth.acceptInvite({
    token: pendingInvite,
    userId: currentUser.id,
  });
  res.clearCookie("pending_invite");
}
```

Own Auth does not create an account during invite acceptance.

### Errors

| Code | When |
|---|---|
| `expired_token` | The invite has expired. The default lifetime is seven days. |
| `token_already_used` | The invite has already been accepted or revoked. |
| `invalid_token` | The token is malformed, missing, or does not match an active invite. |
| `invalid_session` | No signed-in user ID was supplied. |
| `permission_denied` | The signed-in user's email does not match the invited email. |
| `user_not_found` | The supplied user does not exist. |

## Revoke an invitation

Only a pending invitation can be revoked. The actor must have the `invite_members` permission.

```ts
const invitation = await auth.revokeInvitation({
  invitationId,
  actorUserId: currentUser.id,
});
```

The invitation is marked as revoked and the link can no longer be accepted.

### Errors

| Code | When |
|---|---|
| `invitation_not_found` | The invitation does not exist. |
| `invitation_not_pending` | The invitation has already been accepted, revoked, or expired. |
| `permission_denied` | The actor does not have permission to revoke invitations. |

## Configuration

```ts
const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  tokenTtlMs: {
    organisation_invite: 7 * 24 * 60 * 60 * 1000, // 7 days
  },
});
```

## Next step

Add [API keys](/docs/api-keys) for programmatic access, or review the [Security model](/docs/security).
