# Erase an Own Auth account

Complete erasure removes a person's Own Auth login, credentials, sessions, personal audit events, queued webhook copies, and related personal authentication records. It preserves other people's accounts and shared configuration. Disabling a user or calling `auth.cloud.eraseUser(userId)` does not perform complete erasure.

## Upgrade storage first

Apply core migration `020_user_erasure` before enabling erasure with Postgres or D1. Use `npx own-auth migrate` for Postgres or the existing D1 migration process. Migration 020 adds durable operation recovery, deletion write guards, personal rate counter ownership, and webhook send authorization. Run all migrations in order. Back up and test your normal migration process before applying it to a live database.

Postgres erasure requires a pool with `connect()`, a checked out pool client dedicated to Own Auth, or a queryable with `transaction(work)` that provides one isolated transaction connection. A wrapper exposing only `query()` cannot guarantee atomic erasure and receives `user_erasure_unsupported`. Built in rate storage shares the authentication database. Custom adapters must implement `UserErasureCapableStorage`, atomic deletion, durable recovery, write guards, and webhook send authorization with the same guarantees. They must enforce any supplied authentication authority expiry when creating users, accounts, sessions, MFA challenges, SAML identities, or email ownership claims. Expired callbacks must fail at the database write even when earlier verification succeeded.

## Erase your own account

Keep an independently generated UUID before sending the request. The operation ID is a recovery reference, not proof of permission.

```ts
const operationId = crypto.randomUUID();
const result = await auth.eraseUser({
  sessionToken,
  operationId,
  confirmation: "erase"
});
```

The browser client uses `client.eraseUser({ operationId, confirmation: "erase" })`. The HTTP endpoint is `POST /api/auth/user/erase`. It uses the authenticated session and rejects a target user ID or actor ID in the body. Normal cookie CSRF and trusted origin protections apply.

Authentication must be no older than five minutes by default. Configure `userErasure.maxAuthenticationAgeMs` to change that requirement. An account with an active TOTP factor or registered passkey requires an MFA authenticated session. Old authentication produces `reauthentication_required`. Sign in again, complete MFA when required, then submit a new request.

Successful database deletion ends every session and removes usable credentials. Both complete HTTP 200 and pending HTTP 202 clear the browser session and MFA cookies. The client clears its cached account. A lost response does not establish completion. Keep the operation ID and recover through a trusted server or an authorized administrator.

## Administrator erasure and recovery

Configure the existing `administration.authorize` callback. Each action requires its own permission: `users:erase`, `erasures:read`, `erasures:resume`, and `organisations:resolve-erasure`. The callback receives the authenticated actor and the relevant target or operation. Never grant these actions solely because the request knows a user ID or operation ID.

```ts
await auth.admin.eraseUser({
  actorUserId: administratorId,
  userId: targetUserId,
  reason: "Account holder requested erasure",
  operationId
});
await auth.admin.getUserErasure({ actorUserId: administratorId, operationId });
await auth.admin.resumeUserErasure({ actorUserId: administratorId, operationId });
```

The HTTP operations are `POST /api/auth/admin/user/erase`, `GET /api/auth/admin/user-erasure?operationId=...`, and `POST /api/auth/admin/user-erasure/resume`. The HTTP handler derives the actor from its session. Administrator erasure can target a disabled account without impersonating it. The reason is validated but is not retained in the completed receipt.

Trusted server code can use `auth.getUserErasure({ operationId })` and `auth.resumeUserErasure({ operationId })` without configuring administration. Do not expose those trusted methods through an unauthenticated route.

## Organisation ownership

If another active owner exists, Own Auth preserves the organisation and its members. Otherwise `user_erasure_ownership_required` returns every organisation ID that needs a decision, without changing records.

Supply an explicit decision in `organisations`:

```ts
const transfer = { organisationId, action: "transfer", newOwnerUserId: eligibleActiveMemberId };
const deletion = { organisationId, action: "delete", confirmation: "delete_organisation" };
```

A transfer promotes an existing active member whose account is enabled. Organisation deletion requires its separate confirmation. Other members keep their Own Auth accounts. Administrator supplied decisions also require `organisations:resolve-erasure`.

## Pending results and retries

Results contain `operationId`, `status`, `local`, `cloud`, and `pendingLocalStores`. `status` is complete only when local cleanup and configured Cloud deletion have both completed. `cloud` is `not_configured`, `pending`, or `complete`. A pending result must never be presented as completed erasure.

Retry trusted cleanup with the same operation ID. A pending operation for the same target joins existing recovery. A closed operation ID cannot erase another or newly registered identity. Missing operations produce `erasure_operation_not_found`; conflicting targets produce `erasure_operation_conflict`; closed IDs produce `erasure_operation_closed`.

Required plugins declare `userErasure: { personalData: true, erase(subject) { ... } }`. A plugin storing no personal records declares `userErasure: { personalData: false }`. Missing declarations or a rate limit store without `eraseUser(subject)` produce `user_erasure_unsupported` before deletion. Personal cleanup must be safe to repeat and must coordinate its writers so delayed work cannot recreate deleted records. The callback receives only the identifiers needed for deletion. It must never retain provider secrets or make an audit copy of removed content.

Cleanup failures remain durable and keep `local` pending. Restore the same plugin ID and version to retry its outstanding step. Removing a plugin from configuration does not prove its records were erased. Temporary protection for old anonymous identity requests and security cache expiry also keeps local completion pending until their actual authority ends.

## Cloud and retained protection

The existing priority outbox persists Cloud deletion requests in the same commit as local deletion. It also coordinates explicitly deleted organisations and preserves transferred ownership. Cloud outages and lost acknowledgements leave a durable pending request. The receiver must explicitly confirm deletion at the requested version. Acceptance alone does not establish remote erasure.

Continue the existing `auth.cloud.flushOutbox()` scheduling process while Cloud deletion is pending. Clearing or purging the ordinary outbox preserves required erasure requests until confirmed completion. No additional queue is required. Coordinate the package upgrade with the Cloud receiver and its migration `043_consolidate_user_erasure_protection`.

After confirmed Cloud erasure, Cloud retains only an application scoped keyed digest of the old user ID, deletion version, and deletion time. This remains a retained identifier. It prevents delayed events and restored data from recreating that identity. It contains no contact details, profile, authentication secret, personal audit body, or reason. Restore recovery uses that same record. Retain it while delayed events or restored data can recreate the old identity. A new signup has a new ID and is unaffected.

Completed local receipts retain only the opaque operation ID, nonpersonal status, and timestamps. Pending recovery retains only the personal lookup information still required to finish deletion. It never preserves erased credentials.

## Systems owned outside Own Auth

External identity provider accounts, such as Google or Apple accounts, belong to those providers. This operation deletes credentials saved by Own Auth. Deleting the provider account or revoking grants at the provider requires action through that provider.

An application's orders, posts, invoices, and other business records belong to the application using Own Auth. Their deletion requires the application's own process and does not block Own Auth erasure.

Messages already delivered and independent webhook receivers belong to their respective recipients or operators. Own Auth removes its stored copies and stops work that has not obtained send authorization. It cannot recall transmitted requests or remove a receiver's independent copy.

Database backups belong to the database operator. Expiry or removal of backups requires that operator's retention process. Cloud restore recovery must copy the current deletion protection before restored data is allowed to serve traffic.
