# User erasure implementation status

**Status:** All eight implementation actions and their local acceptance are complete. Package changes are committed. Cloud changes remain uncommitted. Neither is released.

**Specification:** [Complete user erasure](/Users/tina/Code/own-auth/own-auth-package/USER_ERASURE_SPEC.md).

**Verification:** [Exact execution results](/Users/tina/Code/own-auth/own-auth-package/USER_ERASURE_VERIFICATION.md).

## Remaining acceptance and release gates

| Requirement | Current product outcome | Exact result still required |
| --- | --- | --- |
| Establish the Cloud repository release gate. | Cloud erasure, restore, encryption, completion acknowledgement, and stale data rejection pass against real migrated Postgres schemas. | `tests/opennext-version-support.test.ts` must pass. `tests/dashboard-auth-rate-limit.integration.ts` must compile at its reported failing call sites. These are separate repository gates outside the erasure feature. |
| Generate the released Cloud event definitions from the matching Own Auth package. | Local generation reads the sibling package source. Cloud currently has `own-auth@0.3.12` installed, which predates these event changes. | The Application engineer must upgrade Cloud to the released package containing the erasure event definitions before coordinated release. Package publication and dependency upgrade require separate authorization. |

## Implemented local behavior

| Requirement | Product outcome | Passing evidence |
| --- | --- | --- |
| Let a person or separately authorized administrator erase an Own Auth account. | Fresh authentication and required MFA protect self erasure. Administrator permissions protect deletion, ownership decisions, operation reads, and retries. Disabled targets do not require impersonation. | Core, administration, dedicated HTTP, and client cases. |
| Remove personal records and preserve shared resources. | Memory, Postgres, and D1 delete credentials, personal authorization and provisioning records, invitations, audit copies, webhook attempts, and related Cloud work. Another person's credentials, organisation access, shared keys, and shared configuration remain. | Shared erasure inventories, ownership cases, rollback cases, real Postgres connections, and the D1 Worker qualification. |
| Prevent old work from recreating the erased identity. | Storage validates authentication authority expiry at writes. Durable send authorization prevents a claimed webhook from starting after deletion. Settlement and retries cannot restore removed records. | Expired identity, provider callback, webhook processor, and shared adapter cases. |
| Recover cleanup without keeping the deleted login alive. | Plugins and rate stores declare deletion support. Failed cleanup remains pending and retries through the same durable operation after restart. Personal recovery keys disappear on completion. | Unsupported store, failure, concurrent request, plugin restart, and closed operation cases. |
| Coordinate Cloud deletion through the existing outbox. | User and confirmed organisation deletions commit with local erasure. Required requests survive ordinary outbox clearing. The receiver confirms committed deletion and rejects references to erased identities. | Shared adapter coordination, completion protocol, migrated Cloud database, encrypted replica, stale backfill, and restore consolidation cases. |
| Disclose approved retained protection and publish matching APIs. | Cloud retains only the keyed old user ID digest, deletion version, and deletion time. The same record protects ingestion and restore recovery. Package and Cloud documentation disclose it. | Generated documentation checks, public examples, exported migrations, built declarations, Cloud contract parity, and package contents inspection. |

## Shared implementation rules

Self and administrator requests share one erasure service. Sign in and erasure share registered MFA method selection. Postgres erasure, lazy persistence, and checked out clients share one transaction lifecycle. SQL adapters share deletion preparation and relationship matching, and delete confirmed organisations together. Built in rate stores share identifier selection and participate through the existing persistence configuration. Plugin cleanup uses the immutable runtime registry. Cloud shares its personal event scan across old and current records and uses its existing outbox, ordering, retries, and receiver. No separate cleanup queue or duplicate restore journal is introduced.
