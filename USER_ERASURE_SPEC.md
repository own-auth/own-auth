# Complete user erasure specification

**Status:** Local implementation and erasure acceptance complete, including the shared cleanup changes. Package changes are committed. Cloud changes remain uncommitted. Neither is released.

**Baseline:** Local Own Auth package version `0.3.13`.

**Scope of this task:** Implement the library feature, migrations, documentation, and test source. Only the package commit is authorized. Publishing and live data deletion are not authorized.

**Implementation ledger:** [Current implementation status](/Users/tina/Code/own-auth/own-auth-package/USER_ERASURE_IMPLEMENTATION.md).

**Verification evidence:** [Current test results](/Users/tina/Code/own-auth/own-auth-package/USER_ERASURE_VERIFICATION.md).

## Outcome and scope

An application can permanently erase a person's Own Auth login identity, stored authentication credentials, personal audit records, and other personal records held by Own Auth. The same operation coordinates deletion from optional Own Auth Cloud without making Cloud a requirement for local erasure.

Erasure must remove the records themselves. Disabling login, marking a session revoked, clearing a browser cookie, or removing a foreign key reference does not satisfy this requirement. Other users must retain their accounts and organisation access.

The configured Own Auth storage remains the source of truth for authentication. This feature covers records maintained by the library, its configured authentication storage and plugins, and optional Own Auth Cloud. Application business data is outside this feature's scope and must not become a dependency of Own Auth erasure.

## Actions and ownership

All eight actions are complete in local source and have passing acceptance evidence. Package changes are committed. Cloud changes remain uncommitted. Neither is released. Exact execution results are recorded in the linked verification report.

| Required change | Responsible role | Current status | Acceptance criteria | Validation evidence |
| --- | --- | --- | --- | --- |
| Let a signed in person erase their own Own Auth account after confirming their identity. | Backend engineer | Complete locally. | A confirmed request erases only the authenticated person's records and ends every session. | Passed: `packages/core/test/user-erasure.test.ts`, `packages/core/test/user-erasure-http.test.ts`, and `packages/core/test/client.test.ts`. Cases establish recent authentication, TOTP and passkey MFA, confirmation, CSRF, trusted origins, target isolation, cookie clearing, and stale client response handling. |
| Let an authorized administrator erase a named Own Auth account and inspect its erasure operation. | Backend engineer | Complete locally. | The administration authorization callback grants each required erasure permission before records or operation details are accessed. | Passed: `packages/core/test/administration.test.ts`, `packages/core/test/administration-http.test.ts`, and the erasure HTTP cases. They establish allowed and denied deletion, separate read and retry permissions, disabled targets, completed operations, and missing targets. |
| Remove the person's records consistently from Postgres, D1, and development memory storage. | Database engineer | Complete locally. | Local completion leaves no usable credentials or personal records covered by the deletion rules, and preserves unrelated records. | Passed: shared `packages/core/test/conformance/user-erasure-cases.ts` through the memory runner, `packages/core/test/postgres/postgres-user-erasure.integration.test.ts`, and `pnpm cloudflare:check`. Cases establish credential removal, unrelated record preservation, rollback, database connection recovery, and receipt recovery after actual Worker restart. Postgres migration cases also pass. |
| Preserve other members' access when the erased person owns an organisation. | Backend engineer | Complete locally. | Erasure uses an explicitly authorized ownership resolution or returns every organisation requiring a decision before changing records. An authorized administrator can resolve ownership for a disabled target without impersonation. | Passed: shared ownership cases on all three adapters and the administration cases. They establish another owner, sole ownership, disabled ownership, transfer, deletion of multiple confirmed organisations, preservation of other members, and rejection after concurrent membership removal. |
| Remove personal audit and webhook copies and prevent new delivery of erased events. | Backend engineer | Complete locally. | Personal events and their stored copies are removed. Claimed work cannot start another delivery or recreate erased records after the erasure fence takes effect. | Passed: `packages/core/test/webhooks.test.ts` and shared `packages/core/test/conformance/user-erasure-delivery-cases.ts`. Cases establish personal metadata removal, delivered and failed copy deletion, claimed send refusal, handling of transmitted requests, retry refusal, and settlement without recreation. |
| Coordinate Cloud deletion through the existing priority outbox. | Backend engineer | Complete locally. | Local deletion and its durable Cloud request commit together. The result distinguishes remote acceptance from confirmed remote erasure. | Passed: `packages/core/test/cloud.test.ts`, persistent adapter cases, and Cloud projection, command, restore, and database cases. They establish outages, lost acknowledgements, duplicate delivery, priority request preservation, stale backfill rejection, plain and encrypted copy deletion, and the approved minimal protection record. |
| Remove personal records from configured Own Auth plugins, rate limit storage, and security caches. | Backend engineer | Complete locally. | Each configured Own Auth store has a declared deletion path. Local completion is withheld while any required store still holds the person's records. | Passed: `packages/core/test/user-erasure-plugins.test.ts`, shared plugin restart cases, rate storage cases, and the Cloud cache lifetime case. They establish unsupported storage rejection, deletion failure, restart, retry, and withholding completion until cached authority expires. |
| Document the erasure API and storage upgrade requirements. | Application engineer | Complete locally. | Packaged documentation explains authorization, ownership decisions, retries, result states, and migration requirements for Own Auth records. | Passed: `packages/core/test/docs-contract.test.ts`, documentation consistency checks, and package compilation. Inspected built declarations, HTTP schemas, OpenAPI response handling, public API definitions, packaged documentation, migration exports, and examples agree with the implemented operations. |

## Current product behavior

The local source includes the complete erasure service, self and administrator APIs, HTTP and client handling, Postgres and D1 migration 020, memory storage, durable plugin cleanup, and coordinated Cloud receiver changes. The approved Cloud retention exception permits only the minimal deletion protection record. Required erasure acceptance passes locally. This does not establish which package version a separate application has installed.

[Disabling a user](/Users/tina/Code/own-auth/own-auth-package/packages/core/src/auth-engine-users.ts) retains their profile and credentials. [Session revocation](/Users/tina/Code/own-auth/own-auth-package/packages/core/src/auth-engine-sessions.ts) retains session records. [SCIM deletion](/Users/tina/Code/own-auth/own-auth-package/packages/core/src/scim-users.ts:352) removes organisation access and creates a tombstone. None provides complete user erasure.

Dedicated erasure cases now exercise the complete operation and recovery. Existing session revocation, disabling, SCIM deletion, and Cloud only purge APIs keep their separate meanings.

### Local implementation and acceptance

| Requirement | Product outcome and passing evidence |
| --- | --- |
| Erase only the authenticated account after fresh identity proof. | `user-erasure-http.test.ts` and `client.test.ts` establish session derived targets, MFA, CSRF, confirmation, cookie clearing, lost responses, and stale client responses. |
| Require explicit administrator permissions for erasure and recovery. | `administration.test.ts`, `administration-http.test.ts`, and the dedicated erasure HTTP cases establish separate permissions, disabled ownership resolution, completed receipts, and missing operations. |
| Remove personal authentication records and preserve other people. | Shared `conformance/user-erasure-cases.ts` exercises memory, real Postgres connections, and the D1 Worker. Inventories include credentials, consumed records, anonymous proofs, authorization grants, device requests, SAML, SCIM tombstones, invitations, shared keys, and personal metadata. |
| Roll back failed deletion and durably resume later cleanup. | Memory, Postgres, and Worker failure cases establish rollback. Shared plugin cases establish restart, unavailable plugins, repeatable cleanup, and joining the original pending operation. |
| Prevent expired callbacks and late sends from restoring deleted records. | Database writes enforce supplied authority expiry. Provider callback cases establish expiry during verification. Webhook processor and adapter cases establish send authorization, removed attempts, retry refusal, and settlement without recreation. |
| Confirm Cloud deletion through the existing outbox. | Package Cloud cases distinguish acceptance from completion and recover lost acknowledgements. Cloud database cases apply real migrations, erase plain and encrypted replicas, reject stale child events and backfill, and consolidate the old journal into minimal protection. |
| Keep installed documentation and declarations consistent. | `docs/user-erasure.md`, the site manifest, generated API snapshot, OpenAPI, package exports, and migration exports describe the same feature. Documentation and example checks pass. |

## Public operations and authorization

### Erase your own account

`auth.eraseUser(input)` is available through the core API, existing HTTP handler, and TypeScript client. The service derives the target user from the validated session. A browser request cannot choose another target through a user ID or actor ID supplied in its body.

The input contains the current session credential, explicit permanent deletion confirmation, an operation ID generated by the caller for safe retries, and any organisation ownership decisions. Browser credentials continue to use the existing cookie or bearer handling. Tokens must not be copied into URLs, telemetry, or stored erasure receipts.

Require successful authentication within `userErasure.maxAuthenticationAgeMs`, which defaults to five minutes, with the account's required MFA completed. Validate this centralized setting as a positive duration. Compare the stored `authenticatedAt` with the current time; session activity alone must not refresh it. Reject invalid or future authentication timestamps. Reuse the existing password, OAuth, magic link, phone, passkey, and configured SAML paths for fresh identity proof. A fresh login must prove the same user ID. Do not require a password from an account that has no password.

Use the existing CSRF, trusted origin, rate limiting, and error handling rules. Once the main authentication database commits deletion, clear the session cookie and update the client session state through the existing session listeners, even if another Own Auth store or Cloud still needs cleanup. Discard an older in progress session response that would restore the deleted account in client state. A request rejected before deletion must preserve the session. Requests from other tabs must fail authentication; when those clients next refresh their session or receive an authentication failure, their displayed session must clear through the same client handling.

If a host application presents a deletion control, its confirmation must explain permanent loss of the login and personal authentication history. Use an application modal and explicit confirmation. Cancelling must have no effect. Document the same requirement for applications that build their own controls.

### Erase an account through administration

`auth.admin.eraseUser(input)` and its administration HTTP operation are available. The administration action set includes `users:erase`, `erasures:read`, `erasures:resume`, and `organisations:resolve-erasure`. The erasure request accepts the target user ID, operation ID, a validated reason, and explicit ownership decisions. Existing administration reason validation applies. The reason is not stored in the erased person's audit history or operation receipt.

Use the existing active actor validation and configured administration authorization callback. An organisation role or possession of a target user ID does not grant permission. Disabled target accounts can be erased through this authorized administration path. Verify authorization before disclosing whether the target exists.

Both public paths must use the same erasure service and atomic storage operation. Framework adapters only translate requests and responses.

### Results and retry behavior

Return only the operation ID and deletion status, with the configured Own Auth stores still requiring cleanup identified by nonpersonal store names. The result is:

```ts
interface UserErasureResult {
  operationId: string;
  status: "pending" | "complete";
  local: "pending" | "complete";
  cloud: "not_configured" | "pending" | "complete";
  pendingLocalStores: string[];
}
```

`local` covers all configured Own Auth storage, including plugins, personal rate limit keys, security caches, and local event copies. A store is pending until actual deletion is confirmed. Do not return the deleted user, email, phone, credentials, audit entries, or free form reason.

Overall erasure is complete when `local` is `complete` and Cloud is either `complete` or `not_configured`. No business record deletion, external account deletion, or generic application cleanup callback participates in this decision. Missing required erasure support must fail preflight. A temporary failure after the main database commit remains pending with its durable retry intact.

HTTP `200` means confirmed completion. HTTP `202` means the main authentication database has committed deletion but another Own Auth store or Cloud remains pending. The shared endpoint response carries this status through the handler, client, and generated OpenAPI. Both responses clear the deleted person's session. Acceptance of a Cloud event does not establish completed Cloud deletion.

`auth.getUserErasure({ operationId })` and `auth.resumeUserErasure({ operationId })` are trusted server operations over the same erasure service. They work without optional administration or a surviving target account. They are not public HTTP endpoints and do not appear in the browser client. Possession of an operation ID does not grant access through a host's own routes.

Administration operations `auth.admin.getUserErasure` and `auth.admin.resumeUserErasure` enforce existing actor validation and the `erasures:read` and `erasures:resume` permissions. These permissions must be granted explicitly. Permission to erase one target does not grant access to every receipt. Completed receipts have no target relationship, so authorization does not depend on loading the erased user. The administration authorization context includes the operation ID for these actions.

Self erasure remains available without administration configured. A pending result or lost response is recovered through the trusted server operation and existing Cloud flushing, not by preserving the deleted session. An invalid session alone does not prove erasure completion. Do not create an unauthenticated status lookup or require the person to create another account to finish cleanup.

While an operation is pending, repeating an authorized request with the same operation ID resumes it. Reject that ID for a different target. Concurrent requests for the same user must join one operation rather than duplicate cleanup. Once its target relationship has been destroyed on completion, reserve the closed operation ID without personal data. A new erase request using that ID returns `erasure_operation_closed`; it cannot claim that a different supplied target was erased. The status operation returns the existing nonpersonal receipt.

An authorized request for an absent user must resume an existing pending operation when its ID is provided. Without an operation receipt, return `user_not_found` rather than claiming all historical records or Cloud copies were erased. Never choose a target by email or phone during retry, because a new account may now use those identifiers.

### Request and error definitions

The HTTP operations are `POST /user/erase`, `POST /admin/user/erase`, `GET /admin/user-erasure`, and `POST /admin/user-erasure/resume` beneath the configured auth base path. The core and browser self erasure input requires `confirmation: "erase"` and an `operationId` generated independently with a cryptographically secure UUID generator. The core also accepts `sessionToken` and request context; the browser uses the existing credential transport. The admin HTTP body excludes actor IDs and derives the actor from its session. Administration status uses an `operationId` query parameter; administration resume uses an `operationId` JSON field. Both erase requests may contain explicit organisation resolutions.

Use the existing errors for invalid input, invalid session, forbidden access, rate limiting, and a missing user. Add `reauthentication_required` with HTTP `401`, `user_erasure_unsupported` with HTTP `409`, `user_erasure_ownership_required` with HTTP `409`, `erasure_operation_conflict` with HTTP `409`, `erasure_operation_closed` with HTTP `409`, and `erasure_operation_not_found` with HTTP `404`. Ownership conflicts return authorized organisation IDs and required choices through a typed error detail field shared by the core API, HTTP handler, client, and OpenAPI. Do not put raw database errors, tokens, or deleted content in those details.

## Records to erase and records to preserve

Capture the target's identifiers and owned record relationships inside the protected erasure operation before removing them. Match records through authoritative ownership and structured references. Include email and phone records without a user ID when their ownership can be established. Do not delete another person's records solely because an old email address, phone number, or arbitrary text happens to match.

| Stored information | Required outcome |
| --- | --- |
| The user's profile and login accounts | Delete the user, password hash, profile metadata, provider identifiers, and linked password, phone, magic link, OAuth, and SAML account records. |
| Sessions and authentication tokens | Delete active, expired, consumed, and revoked sessions and tokens belonging to the person, including password reset and verification tokens. Every old credential must fail when presented to Own Auth afterward. |
| Phone verification and recovery codes | Delete the person's OTP records, including records without a user ID when ownership is established, and prevent a previously issued code from authenticating a later account. |
| MFA and passkeys | Delete TOTP secrets, pending enrollment, MFA challenges, recovery codes, passkey credentials, and linked WebAuthn challenges. Physical passkeys on a person's device remain under that device's control. |
| OAuth credentials and pending sign in | Delete encrypted local provider credentials and user linked OAuth transactions. Invalidated callbacks and linking requests must not restore the deleted identity. |
| Authorization server records | Delete the person's grants, authorization interactions, codes, access tokens, refresh token families, OIDC subjects, and approved device authorization records. Preserve shared client registrations and protected resources. |
| Device and SAML requests | Remove requests linked to the user, session, or grant. Preserve shared replay protection that contains no personal relationship and remains necessary to reject reused proofs. |
| User owned API keys | Delete their hashes and associated personal metadata. Preserve organisation owned keys that are independent of the user, remove references to the erased person, and verify that no retained key derives authority from the deleted account. |
| Organisation membership and SCIM records | Delete the person's memberships and personal SCIM resources, including tombstones and external identity attributes. Preserve organisation connections, provisioning tokens, and other members. A later provisioning request must create a new identity rather than restore the erased one. |
| Invitations addressed to the person | Remove invitation details and linked tokens when ownership is established, including accepted and revoked copies. Other invitees must retain their invitations. |
| Invitations sent by the person to somebody else | Preserve the other recipient's valid invitation, remove personal sender details, and record an absent sender without inventing another actor. Change the schema and invitation handling where required. |
| Personal audit records | Delete events where the person is the actor or target, and events authoritatively linked through erased credentials or declared personal metadata. Remove the full event, including IP address, user agent, and metadata. Setting actor or target to null is insufficient. |
| Copies of audit events sent through webhooks | Delete related stored event bodies, delivery records, and attempts, including delivered and failed copies. Prevent pending or claimed work from starting a new send after the erasure fence. A request already transmitted cannot be recalled; its eventual settlement must not recreate local records. |
| Cloud state in the application database | Remove personal event copies, commands, results, and obsolete personal lookup records. Preserve only the minimum deletion request and ordering information needed until Cloud confirms completion and stale work cannot restore the person. |
| Plugin owned personal records | Delete declared personal records and caches through the same erasure lifecycle. A plugin that stores personal data must declare its erasure support. Missing support must be detected before destructive work starts. |
| Rate limiting and security state | Remove personal lookup keys and state tied solely to the erased person, including process caches across active instances. Declare the keys and stores owned by each authentication operation so custom rate limit storage can participate. Preserve shared abuse counters and nonpersonal replay protection. Hashing an email address does not by itself make a retained personal lookup anonymous. |

Every Own Auth writer that stores personal metadata must declare the user's relationship when writing it. Extend records without enough attribution, including pending sign in requests and personal lookup keys, rather than relying on text matching during erasure. For existing records, use provable relationships and remove the complete related personal record. Keep a legacy record category unverified until a safe migration or other concrete evidence establishes its deletion. An unverified category cannot satisfy complete erasure or pass the feature release gate. This requirement does not add cleanup of unrelated application content.

## Organisation ownership decisions

Erasure must not silently delete an organisation or leave it without an owner. Reuse the existing membership and ownership rules.

If another eligible owner exists, transfer the primary ownership reference to that owner using the established ownership selection rule. If the person is the last owner, return a structured conflict naming the affected organisations and the permitted resolutions before any deletion occurs.

Allow an explicit resolution for each such organisation: transfer ownership to an eligible member with the required authorization, or permanently delete that organisation after separate explicit confirmation and the existing organisation deletion permission checks. Do not promote a member without authorization or treat user erasure confirmation as organisation deletion confirmation.

Represent a resolution as `{ organisationId, action: "transfer", newOwnerUserId }` or `{ organisationId, action: "delete", confirmation: "delete_organisation" }`. Self erasure uses the person's existing ownership authority. Administration requires a separate `organisations:resolve-erasure` authorization decision for every affected organisation, with its ID and target user ID supplied to the callback. This explicit permission authorizes the required transfer or deletion for a disabled or inaccessible owner. It must not be inferred from `users:erase`, and the administrator must never execute as the deleted person.

Validate all resolutions again when committing erasure. Concurrent owner removal or membership changes must not bypass the last owner rule. Deleting a solely owned organisation must use the existing organisation cleanup responsibilities and include its downstream records.

## Atomic deletion and concurrent activity

One atomic erasure operation provides equivalent behavior in Postgres, D1, and memory storage. Migration 020 resolves restricting references and adds durable recovery and write protection. The service does not rely on a sequence of independently committed deletes.

Before destructive work, validate caller authority, storage support, configured plugin and rate limit store support, ownership decisions, and the ability to durably record required cleanup for Own Auth stores and Cloud. An unsupported adapter must return a clear capability error without partially erasing records. Document custom adapter upgrade requirements. Adding erasure must not make unrelated authentication operations require the new optional capability until the documented adapter compatibility change is introduced.

The atomic operation must establish the target and its dependencies, resolve authorized ownership changes, remove covered records in the main authentication database, and persist necessary cleanup requests together. Postgres must provide database atomicity and D1 must provide the equivalent through its supported atomic batch mechanism. Roll back those database changes if the atomic operation fails. Never make a remote network call inside a database transaction.

Configured Own Auth stores outside that atomic database, such as custom rate limit storage or plugin caches, require durable, repeatable cleanup steps owned by the erasure service. The existing plugin after hooks are insufficient because they do not provide durable completion. Missing participation support must be detected before deletion; a later transient failure keeps `local` pending. Do not claim that unrelated stores share a database transaction.

The erasure fence is the shared storage rule that prevents older work from writing records or starting another delivery for an identity being deleted. Authentication, token issuance, credential refresh, account linking, SCIM updates, audit writes, webhook claims, and Cloud backfill must respect this ordering. Work that started before erasure must not commit new records for the deleted identity, produce a credential usable after deletion, or enqueue personal events after that rule takes effect. Enforce it across processes and database connections, not only with a process local lock. Claimed senders must coordinate their authority to start a send with deletion and must not restore deleted delivery state during settlement. A separate existence check followed by an unprotected send is insufficient. Do not promise to recall bytes already transmitted.

Requests received after completion may use ordinary signup policy to create a genuinely new account. Give that account a new user ID and OIDC subject. Do not restore prior membership, credentials, audit history, or pending verification authority. A previously approved provider callback must not count as a new deliberate signup.

Pending anonymous OAuth, SAML, and passkey requests cannot always identify a person when they start. Erasure must therefore also reject proofs initiated before deletion when they later resolve to the erased identity. Reuse existing request expiry and replay protection. If a temporary personal deletion marker is necessary, retain no authentication secret, derive its lifetime from the actual remaining authority of those requests, and keep `local` pending until the marker can safely be removed. Do not keep a permanent personal tombstone or invalidate unrelated users' sign in requests to avoid solving this case.

Own Auth session validation, API key validation, token exchange, introspection, and userinfo must reject erased identities. Previously issued signed OIDC ID tokens are identity statements already delivered to clients; deleting their local subject does not change those signed bytes. They must not become a way to restore the erased Own Auth login.

## Own Auth Cloud coordination

The existing Cloud erasure path and priority outbox own delivery. The deletion request persists in the same local commit as user erasure and retains existing lease, retry, duplicate protection, and entity ordering behavior. There is no second Cloud sender or queue.

The priority receiver returns an explicit erasure completion response after committed deletion. The package validates its event ID and completion status before recording remote completion. Acceptance alone cannot establish removal of replicas, events, commands, delivery records, audit and security records, analytics membership, and exports.

Cloud must reject stale events and backfill that would recreate an erased user. Claimed work, events arriving out of order, lost responses, and repeated deletion requests must converge on the same erased result. A later signup with a new user ID remains independent.

`auth.cloud.flushOutbox`, the configured Cloud flush mode, and the existing scheduling integration perform Cloud retries and track confirmed deletion completion. Pending Own Auth cleanup remains durable and does not require the deleted person to sign in again. A host that uses manual flushing must continue invoking its existing flush process while a deletion remains pending. This feature uses no provider revocation worker or generic application cleanup queue.

Keep the existing `auth.cloud.eraseUser(userId)` API compatible as a Cloud specific operation. Its documentation must continue to distinguish it from the new complete erasure operation. Complete erasure coordinates Cloud automatically when Cloud is configured.

## Privacy of recovery and operational records

Retries need durable coordination because the main database cannot atomically delete records in Own Auth Cloud or a separate configured Own Auth store. Use the existing Cloud outbox for Cloud delivery and add only the operation coordination it cannot represent. There must be one owner for erasure state and recovery.

Pending cleanup may retain only the protected target reference, declared lookup keys, destination, temporary deletion marker, and delivery status needed to finish deleting Own Auth records. Authentication secrets and personal event bodies are never allowed in recovery records. Delete stored provider credentials, including encrypted refresh tokens, with the main authentication database records; never move them to another table or retry record. Removing a local credential requires no successful network request to that provider.

A remaining personal lookup key or temporary deletion marker keeps `local` pending. A minimum target reference needed solely for the Cloud deletion request keeps `cloud` pending. Pending recovery information must not appear in personal audit listings.

Cloud may retain only its keyed digest of the old user ID, deletion version, and deletion time as deletion protection after completion. This approved exception prevents delayed events and restored data from recreating the old identity. The digest remains a retained identifier and must be disclosed as such. It must contain no contact details, profile, authentication secret, personal audit body, or reason. Keep it only while stale events or restored data can recreate that identity. A newly registered account has a new ID and is unaffected.

On completion, destroy the local target relationship and personal cleanup keys. Any retained operational receipt may contain only an unrelated opaque operation ID, timestamps, nonpersonal counts, and outcome categories. Do not retain user IDs, hashes of user identifiers, email addresses, phones, IP addresses, user agents, arbitrary reasons, or deleted event bodies in that receipt. The separate minimal Cloud deletion protection record is the sole approved identifier retention exception. Use independently generated random operation IDs, never identifiers derived from personal fields. Do not create a new personal deletion audit event after erasing the existing audit history.

Preserve unrelated administrator activity records unchanged. Do not redact a related personal audit event merely to retain it; the deletion rules require removing that event. Never retain a copy of deleted content for troubleshooting. Failure logs must use sanitized error categories and the opaque operation ID.

## Acceptance criteria

Core, HTTP, client, shared adapter, Worker, and Cloud acceptance passes locally. Exact execution evidence is recorded in the linked verification report.

- [x] Core self erasure removes the memory user, accounts, sessions, and personal audit events while preserving another account that references the erased person.
- [x] Plugin cleanup failure keeps the operation pending, and trusted server retry completes it without the deleted login. Unsupported or malformed plugin participation is rejected.
- [x] Pending requests for the same memory user join one operation. Conflicting targets and reuse of a closed operation ID are rejected without erasing the other account.
- [x] Memory rate limit cleanup removes keys for declared personal identifiers while preserving similar unrelated keys. Delayed session and account writes remain rejected after the completed receipt loses its target.

The complete requirements below are implemented and accepted locally.

- [x] A freshly authenticated person can erase their account through the core API and HTTP client with the same authorization and deletion outcome.
- [x] Required MFA, explicit confirmation, CSRF protection, trusted origin validation, and rate limiting are enforced before deletion.
- [x] Another user's ID, forged actor information, old authentication, and an unapproved administrator cannot trigger erasure.
- [x] An authorized administrator can erase an active or disabled target, inspect the operation, and resume outstanding cleanup.
- [x] Postgres, D1, and memory storage remove every applicable record category while preserving unrelated users and shared organisation resources.
- [x] Records without a user ID are removed when ownership is established, and reused email addresses or phone numbers do not cause deletion of another person's records.
- [x] Ownership conflicts cause no partial deletion, and authorized ownership resolutions remain safe under concurrent changes. A separately authorized administrator can resolve a disabled sole owner's organisation without impersonation.
- [x] Personal audit events and all local serialized copies are removed, including nested metadata, failed deliveries, and delivered webhook copies.
- [x] Old sessions, tokens, OTPs, recovery codes, refresh credentials, approved device requests, and pending callbacks cannot restore the account or authenticate a new one.
- [x] Concurrent authentication, provisioning, event delivery, and backfill cannot recreate erased records across connections or after restart. Transmitted webhook requests are distinguished from sends that have not started.
- [x] Failure before the main database commit rolls back that database change. Failure afterward preserves durable Own Auth recovery without restoring login or retaining provider tokens.
- [x] Duplicate requests and lost responses do not duplicate deletion or affect a newly registered identity. Closed operation IDs cannot be reused to imply a different target was erased.
- [x] Cloud acceptance, Cloud completion, and cleanup of each configured Own Auth store produce the specified truthful complete or pending result.
- [x] Required plugin, rate limit, and security cache deletion is enforced, with recoverable failures and no silent skipped personal storage.
- [x] Completion destroys temporary personal recovery records and leaves no new personal audit trail. Temporary deletion markers last only for the actual remaining authority of old requests and prevent a premature complete result.
- [x] Self erasure and trusted server recovery work without optional administration. Administrator access to operation receipts requires explicit erasure oversight permission.
- [x] Client state and session cookies clear after main database deletion for both HTTP `200` and `202`. An older session response cannot restore the deleted account.
- [x] Typed errors name ownership decisions, unsupported stores, operation conflicts, closed operation IDs, and missing operations without exposing deleted content.
- [x] Package exports, generated API declarations, endpoint schemas, OpenAPI, error definitions, and documentation describe the same operations and statuses.

## Verification and release gates

Local implementation, required test source, and erasure acceptance are complete. Shared Postgres transaction handling, MFA method selection, and combined organisation cleanup pass the focused package cases and actual D1 Worker qualification. Cloud projection, restore, and database cases pass with the shared personal event scan, including plain and encrypted old invitation copies and unrelated owner preservation. Exact execution results belong in the linked verification report.

The D1 Worker qualification establishes real D1 execution, repeated migration application, rollback, and completed receipt recovery after Worker restart. Cloud database cases apply the actual migration sequence and establish both plain and encrypted replica erasure. Package type checking, generated documentation checks, and package contents checks pass.

The complete Cloud repository has separate release gates outside this feature: `tests/opennext-version-support.test.ts` must pass, and `tests/dashboard-auth-rate-limit.integration.ts` must compile at its reported failing call sites. The focused erasure cases do not waive those repository gates.

Package source changes are committed and unreleased. Cloud source changes remain uncommitted and unreleased. Only the package commit was approved. A coordinated release requires package migration `020_user_erasure`, Cloud migration `043_consolidate_user_erasure_protection`, and the updated priority receiver. Cloud currently has `own-auth@0.3.12` installed and declares `^0.3.12`. Its build generates event definitions from the sibling package source when present and otherwise from the installed package. The released Cloud dependency must therefore include the matching event definitions. Publishing and upgrading that dependency require their existing approvals. No live behavior, live erasure, or installed consumer upgrade is claimed here.
