# Organisations

Organisations are teams, workspaces, or tenants. A user can belong to multiple organisations. Each organisation has members with roles. Built in from the start, not something you bolt on later.

## Create an organisation

Creating an organisation also creates an active owner membership for `ownerUserId`.

```ts
const { organisation, ownerMembership } = await auth.createOrganisation({
  name: "Acme Inc",
  ownerUserId: user.id,
});
```

Own Auth generates a unique slug from the organisation name unless a slug is supplied.

```ts
const { organisation } = await auth.createOrganisation({
  name: "Acme Inc",
  slug: "acme",
  ownerUserId: user.id,
});
```

## Get an organisation

```ts
const organisation = await auth.getOrganisation({
  organisationId,
  actorUserId: currentUser.id,
});

// organisation -> {
//   id: "org_...",
//   name: "Acme Inc",
//   slug: "acme-inc",
//   ownerUserId: "usr_...",
//   metadata: {},
//   createdAt: new Date("2026-07-11T..."),
//   updatedAt: new Date("2026-07-11T..."),
// }
```

Only an active member can retrieve the organisation. A missing organisation, inactive membership, or user without membership returns `organisation_not_found`.

## List A User's Organisations

```ts
const organisations = await auth.listOrganisations({
  actorUserId: currentUser.id,
});

// organisations -> [
//   {
//     id: "org_...",
//     name: "Acme Inc",
//     slug: "acme-inc",
//     ownerUserId: "usr_...",
//   },
// ]
```

Only organisations with an active membership for that user are returned.

## Update An Organisation

Owners and admins can update organisation settings.

```ts
const organisation = await auth.updateOrganisation(organisationId, {
  actorUserId: currentUser.id,
  name: "Acme Platform",
  slug: "acme-platform",
  metadata: {
    plan: "pro",
  },
});
```

Changing the slug keeps it unique across organisations.

## Delete an organisation

```ts
await auth.deleteOrganisation({
  organisationId: orgId,
  actorUserId: currentUser.id,
});
```

Only the owner can delete an organisation. This permanently removes the organisation, all memberships, invitations, organisation API keys, and invitation tokens. User accounts are not affected; they simply lose membership. An audit log entry records who deleted the organisation and what was removed.

This action is permanent.

## Next step

Learn about [Members](/docs/organisations/members) to manage who belongs to an organisation, or [Invites](/docs/organisations/invites) to bring new people in.
