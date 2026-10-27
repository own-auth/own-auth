# User erasure verification

**Date:** 2026-10-27.

**Scope:** Local package, isolated Postgres, local D1 Worker, and Cloud erasure source.

**Specification:** [Complete user erasure](/Users/tina/Code/own-auth/own-auth-package/USER_ERASURE_SPEC.md).

## Outcome and scope

The latest requested repeat acceptance run passes 275 package tests across 22 files, 39 Cloud unit tests across seven files, and three Cloud database cases, with no failures or skipped tests. Actual D1 Worker qualification also passes, including the shared erasure cases, rollback, and completed receipt recovery after Worker restart. No unhandled errors were reported. Package compilation and documentation consistency passed in the preceding run. All eight implementation actions have passing local acceptance evidence.

Before simplification, the complete package regression suite passed 740 tests across 74 files with required Postgres integration enabled, no failures, and no skips. The preceding focused package checks passed 71 tests across four files, and Cloud erasure unit checks passed 39 tests across seven files. The current focused results above establish the changed paths after simplification. D1 qualification includes 13 erasure cases, rollback, restart, and existing qualification checks.

These are local acceptance results. No production database, live Cloud service, application release, publishing, tagging, or pushing participated. Postgres used an isolated local server at `127.0.0.1:55439/own_auth_test`. Each integration file created and dropped its own schema. The temporary server has been stopped.

## Current acceptance evidence

| Requirement | Evidence and product result |
| --- | --- |
| Self erasure and administrator authorization. | Dedicated core, HTTP, administration, and client cases establish fresh authentication, TOTP and passkey MFA, confirmation, CSRF, trusted origins, target isolation, separate permissions, disabled targets, operation access, and cookie clearing for complete and pending results. |
| Complete deletion and unrelated account preservation. | Shared inventories run on memory, real Postgres connections, and actual D1. They cover credential categories, consumed and revoked records, identity proofs, authorization grants, device requests, SAML, SCIM, personal audit copies, invitations, unrelated credentials, and shared resources. |
| Safe organisation ownership decisions. | Shared cases cover other owners, sole owners, all unresolved organisations, authorized transfer and deletion, disabled owners, and concurrent membership changes. |
| Durable recovery and prevention of recreation. | Rollback, restart, plugin failure, unavailable configuration, concurrent requests, expired authentication authority, delayed credentials, claimed webhook sends, in progress settlement, and delayed Cloud commands are exercised. |
| Cloud completion and approved minimal protection. | Outbox cases distinguish acceptance from confirmed erasure and preserve required requests across clearing, outages, and lost acknowledgements. Cloud tests cover plain and encrypted records, nested metadata, stale child events, stale backfill, guarded writes, retry cancellation, restore replay, and migration of the old journal into the same minimal record. |
| Configured stores and security caches. | Unsupported stores fail before deletion. Failed plugin and rate cleanup remains pending. The security cache test establishes that local completion waits for the maximum authority of cached decisions on other instances. |
| Public package consistency. | Package build, public type checks, basic Node example, direct new test source compilation, documentation checks, generated API snapshot checks, and package contents inspection pass. The dry run includes packaged documentation and migration 020. |

## Execution results

Each completed test execution appears once below. A passing result has zero failures and skips unless stated. Node test runners do not report aggregate file outcomes, so their selected files are named. No browser engine or viewport width was exercised. No unhandled errors were reported. Expected failure scenarios emit sanitized plugin errors and Cloud warnings. Earlier package runs emitted a Postgres concurrent client query warning; transaction serialization was corrected in the shared Postgres connection helper.

For package rows, `test` means `pnpm --filter own-auth test` followed by the named files. Database rows use `OWN_AUTH_TEST_DATABASE_URL=postgres://tina@127.0.0.1:55439/own_auth_test OWN_AUTH_REQUIRE_POSTGRES=true`. Cloud unit rows use `node --import tsx --test`. Cloud integration rows additionally use `TEST_DATABASE_URL=postgres://tina@127.0.0.1:55439/own_auth_test`.

| Run | Selected command or cases | File result | Test result and interpretation |
| --- | --- | --- | --- |
| 1 | Package `test/user-erasure.test.ts`. | 1 passed. | 7 passed. Original memory cases. |
| 2 | Complete package suite before initial corrections. | 60 passed, 5 failed, 5 skipped. | 612 passed, 7 failed, 65 skipped. Memory guard and CLI regressions; local Postgres unavailable. |
| 3 | Package erasure, SAML, email ownership, memory, Cloud, and CLI files. | 6 passed. | 122 passed. Initial affected paths corrected. |
| 4 | `pnpm run test:release`. | 1 passed. | 17 passed. Fake runtime, no release. |
| 5 | Complete package suite with required Postgres. | 70 passed. | 685 passed. Baseline before expanded acceptance cases. |
| 6 | Shared adapter cases. | 1 passed. | 8 passed. |
| 7 | Adapter, erasure, rate limit, Postgres rate limit, and client files. | 5 passed. | 39 passed. |
| 8 | Postgres erasure integration. | 1 failed. | 4 failed. JSONB expression needed an explicit cast. |
| 9 | Postgres erasure integration. | 1 failed. | 4 failed. Version expression needed a bigint cast. |
| 10 | Erasure HTTP cases. | 1 passed. | 10 passed. |
| 11 | Postgres erasure integration after casts. | 1 passed. | 4 passed. |
| 12 | Core erasure, HTTP, and adapter files. | 3 passed. | 26 passed. |
| 13 | Postgres erasure integration after audit relationship correction. | 1 passed. | 4 passed. |
| 14 | Expanded adapter cases. | 1 failed. | 9 passed, 1 failed. Anonymous authority fixture did not represent the request authority. |
| 15 | Cloud focused unit cases. | 3 selected. | 31 passed. |
| 16 | Adapter cases after authority correction. | 1 passed. | 10 passed. |
| 17 | Expanded adapter inventory. | 1 passed. | 12 passed. |
| 18 | Adapter and plugin files. | 2 passed. | 16 passed. |
| 19 | Client, webhook, adapter, and plugin files. | 4 passed. | 42 passed. |
| 20 | OAuth, SAML, administration, and administration HTTP files. | 3 passed, 1 failed. | 45 passed, 1 failed. OAuth mock fixture used an unavailable mock method. |
| 21 | Cloud unit cases after guarded write changes. | 4 selected. | 20 passed, 3 failed. Transaction client fixtures required updates. |
| 22 | Corrected Cloud unit fixtures. | 2 selected. | 4 passed. |
| 23 | Adapter and OAuth files. | 2 failed. | 30 passed, 2 failed. Test helper imported the webhook capability from the wrong entry. |
| 24 | Postgres erasure integration. | 1 passed. | 7 passed. |
| 25 | Adapter cases including the intermediate SQL harness. | 1 passed. | 20 passed. D1 acceptance subsequently moved to the actual Worker runner. |
| 26 | Cloud focused unit files. | 7 selected. | 38 passed. |
| 27 | Expanded Postgres erasure integration. | 1 failed. | 9 passed, 1 failed. Delivery timestamp expression required a cast. |
| 28 | D1 Worker qualification. | Worker scenario failed. | SQL capture exceeded the compound SELECT limit. |
| 29 | D1 Worker qualification with initial diagnostics. | Worker scenario failed. | Same compound SELECT failure. |
| 30 | D1 Worker qualification with database cause reporting. | Worker scenario failed. | Confirmed compound SELECT limit. |
| 31 | D1 Worker qualification with capture diagnostics. | Worker scenario failed. | Identified the exact capture statement. Capture was split within the same atomic batch. |
| 32 | Memory adapter cases after concurrency additions. | 1 passed. | 11 passed. |
| 33 | Postgres erasure integration after timestamp and concurrency corrections. | 1 passed. | 11 passed. |
| 34 | D1 Worker qualification after capture correction. | Worker scenario failed. | Erasure succeeded; the assertion incorrectly expected an unrelated retained webhook record to disappear. |
| 35 | Cloud erasure database integration. | 1 selected. | 2 failed. Application fixture omitted required slug. |
| 36 | Cloud erasure database integration after fixture correction. | 1 selected. | 2 passed. |
| 37 | D1 Worker qualification after preservation assertion correction. | Worker scenario passed. | Atomic, concurrency, erasure, rollback, restart, migration, and existing Worker qualification completed. |
| 38 | Complete Cloud `tests/*.test.ts` suite. | Node did not report aggregate file outcomes. | 623 passed, 1 failed, zero skipped. The installed OpenNext version support check fails outside the erasure source. |
| 39 | Complete package suite during expanded acceptance. | 70 passed, 4 failed. | 725 passed, 7 failed. Client, Cloud, documentation, and Postgres Cloud paths exposed compatibility gaps. |
| 40 | Cloud and memory adapter files. | 2 failed. | 48 passed, 2 failed. Outbox preservation assertions required the erasure behavior. |
| 41 | Six affected package files. | Failures in client cases. | 105 passed, 2 failed. New fixtures called an API the client does not expose. |
| 42 | Postgres and memory erasure adapter files. | 2 passed. | 24 passed. |
| 43 | Five affected package files. | 4 passed, 1 failed. | 60 passed, 1 failed. Documentation example used invalid standalone object syntax. |
| 44 | Three affected package files. | 2 passed, 1 failed. | 30 passed, 1 failed. Same documentation example before its correction. |
| 45 | Postgres Cloud, Postgres erasure, memory erasure, client, and documentation files. | 5 passed. | 48 passed. |
| 46 | `pnpm run test:release`. | 1 passed. | 17 passed. Fake runtime, no release. |
| 47 | Cloud erasure database integration with encryption. | 1 selected. | 3 passed. |
| 48 | D1 Worker qualification after authority expiry additions. | Worker scenario failed. | Expired SAML commit created no records but incorrectly reported success. |
| 49 | D1 Worker qualification after expired commit correction. | Worker scenario passed. | 38 atomic cases, 8 authentication races, 13 erasure cases, rollback, restart, and all other Worker checks passed. |
| 50 | Complete package suite. | 73 passed, 1 failed. | 738 passed, 1 failed. SAML storage mock required preserving the legacy result when no expiry authority is supplied. |
| 51 | Complete package suite after SAML compatibility correction. | 74 passed. | 739 passed. |
| 52 | Package `test/cloud.test.ts`. | 1 passed. | 40 passed, including cache authority lifetime. |
| 53 | Package Cloud, memory erasure, Postgres erasure, and Postgres SAML storage files. | 4 passed. | 71 passed, including the final delayed command guard changes. |
| 54 | Cloud remote commands, projections, restore, audit exports, security service, delivery cancellation, and contract files. | 7 selected. | 39 passed, including retry cancellation after erasure. |
| 55 | Final D1 Worker qualification after delayed command guards. | Worker scenario passed. | 38 atomic cases, 8 authentication races, 13 erasure cases, rollback, restart, and all other Worker checks passed. |
| 56 | Final Cloud erasure database integration. | 1 selected. | 3 passed with plain records, encrypted records, and legacy journal consolidation. |
| 57 | Complete package suite with required Postgres and `--reporter=dot`, before simplification. | 74 passed. | 740 passed, zero failed, zero skipped. |
| 58 | Focused erasure, HTTP, plugin, adapter, Postgres erasure, Postgres persistence, Postgres concurrency, identity expansion, passkey, HTTP identity, SAML, and OAuth files after simplification. | 12 passed. | 165 passed, zero failed, zero skipped. Both client and pool rollback and multiple organisation deletion pass. |
| 59 | D1 Worker qualification after shared MFA and grouped organisation cleanup. | Worker scenario passed. | 38 atomic cases, 8 authentication races, 13 erasure cases, rollback, restart, and all other Worker checks passed. |
| 60 | Cloud projection and restore unit files after duplicate scan removal. | 2 selected. | 19 passed, zero failed, zero skipped. |
| 61 | Cloud erasure database integration with old invitation fixtures. | 1 selected. | 1 passed, 2 failed. Both invitations used the same organisation version, so ingestion correctly rejected the second fixture before erasure. The fixture now uses increasing versions and asserts that both copies exist before deletion. |
| 62 | Cloud erasure database integration with corrected invitation versions. | 1 selected. | 3 passed, zero failed, zero skipped. Plain and encrypted old copies are removed, and copies explicitly owned by another user remain. |
| 63 | Requested package erasure regression: core erasure, HTTP, adapters, plugins, administration, administration HTTP, client, webhook, Cloud, rate limit, Postgres erasure, Postgres persistence, Postgres concurrency, Postgres Cloud, identity expansion, passkey, HTTP identity, SAML, and OAuth files. | 19 passed. | 263 passed, zero failed, zero skipped. Required Postgres integration is enabled. |
| 64 | Requested Cloud remote command, projection, restore, audit export, security service, delivery cancellation, and contract files. | 7 selected. | 39 passed, zero failed, zero skipped. |
| 65 | Requested Cloud erasure database integration. | 1 selected. | 3 passed, zero failed, zero skipped. Plain and encrypted records, old invitations, unrelated owner preservation, and legacy journal consolidation pass. |
| 66 | Requested documentation, Postgres migration, and Postgres rate storage files. | 3 passed. | 12 passed, zero failed, zero skipped. Required Postgres integration is enabled. |
| 67 | Requested D1 Worker qualification against the rebuilt package. | Worker scenario passed. | 38 atomic cases, 8 authentication races, 13 erasure cases, erasure rollback and restart, device authorization, DPoP, SAML, SCIM, webhook, lifecycle, migration, secret, and close checks pass. |
| 68 | Repeated Cloud remote command, projection, restore, audit export, security service, delivery cancellation, and contract files. | 7 selected. | 39 passed, zero failed, zero skipped. |
| 69 | Repeated Cloud erasure database integration. | 1 selected. | 3 passed, zero failed, zero skipped. Plain and encrypted deletion, old invitation copies, unrelated owner preservation, and legacy journal consolidation pass. |
| 70 | Repeated D1 Worker qualification. | Worker scenario passed. | 38 atomic cases, 8 authentication races, 13 erasure cases, erasure rollback and restart, device authorization, DPoP, SAML, SCIM, webhook, lifecycle, migration, secret, and close checks pass. |
| 71 | Repeated package erasure acceptance, including documentation, Postgres migrations, and rate storage. | 22 passed. | 275 passed, zero failed, zero skipped. Required Postgres integration is enabled. |

## Corrected causes and concrete coverage gaps

The original memory guard treated an external Cloud dashboard actor as a local account. Mailbox replacement also moved owned records before inserting the replacement owner. Both existing paths now preserve their intended ownership and ordering while rejecting delayed writes for missing or erased users.

Earlier erasure cases did not inventory all credentials, authentication proofs, personal event copies, and provisioning records. Shared inventories now exercise those categories on each adapter. They establish unrelated record preservation as well as removal. Actual D1 execution exposed a SQL limit that an intermediate SQLite harness did not establish. The retained D1 runner uses the Worker runtime, repeated migrations, rollback, and restart.

Authentication callbacks could expire during external verification or before persistence. Authority expiry is now carried to the existing atomic database write. SQL predicates and memory writes reject expired authority. Dedicated OAuth, SAML, and shared adapter cases execute that delay. Existing session and MFA lifetimes remain unchanged.

Webhook signing created an asynchronous gap before send authorization. Authorization now occurs immediately before transmission, with durable send state. Claimed work cannot start after erasure; an already transmitted request can settle without recreating local copies.

Cloud previously acknowledged acceptance without proving committed erasure, and its restore journal duplicated the retained user digest. The receiver now confirms the committed deletion version. Ingestion, backfill, exports, security writes, and remote command retries share deletion protection. Migration 043 consolidates the old journal into the approved minimal record.

## Compilation and package inspection

The package build, package and public type checks, basic Node example build, direct new test source compilation, documentation consistency checks, and package dry run pass. Generated declarations, endpoint schemas, API snapshot, documented examples, and exported migrations agree. Compilation and packaging do not establish live deletion.

The final Cloud repository type check reports five errors in `tests/dashboard-auth-rate-limit.integration.ts` at lines 94, 96, 111, 113, and 125. The callback inference combines incompatible result promises. These call sites are outside the erasure changes. No other TypeScript errors were reported.

## Separate Cloud repository gates

`tests/opennext-version-support.test.ts:14` expects the installed Next version to be supported by the installed OpenNext AWS package. The installed package returns false for that assertion. This file has no erasure changes.

The five dashboard rate limit integration compilation errors and the OpenNext support test remain repository release gates. Focused erasure acceptance does not waive them. No feature implementation action is delegated to a future engineer.

The package and Cloud changes remain uncommitted and unreleased. Coordinated release must include package migration 020, Cloud migration 043, and the updated priority receiver through the established approval process. Cloud currently installs `own-auth@0.3.12` under its declared `^0.3.12` dependency. Its generator prefers the sibling package source locally and otherwise imports the installed package. Cloud's released dependency must contain the matching event definitions. No dependency upgrade or package publication occurred in this task.
