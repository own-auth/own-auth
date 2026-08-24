# Own Auth Cloud

Own Auth Cloud is the optional managed operations layer for Own Auth. It adds a dashboard, analytics, advisory security checks, managed email and SMS, and retained audit-log copies. Authentication continues to run locally. Cloud never connects to the application database, verifies passwords or tokens, or creates sessions.

## Setup

Create an app at `dashboard.own-auth.com`, then add its Cloud key to the server environment.

```bash
OWN_AUTH_CLOUD_KEY=oac_sk_...
# Optional fixed local challenge key for environments that do not persist generated configuration.
OWN_AUTH_CHALLENGE_SECRET=replace-with-at-least-32-random-bytes
```

```ts
import { createOwnAuth } from "own-auth";
import { cloud } from "own-auth/cloud";

export const auth = createOwnAuth({
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER,
  plugins: [
    cloud({
      key: process.env.OWN_AUTH_CLOUD_KEY!,
      challengeSecret: process.env.OWN_AUTH_CHALLENGE_SECRET,
      security: {
        credentialStuffing: {
          enabled: true,
          thresholds: { challenge: 3, deny: 10 },
        },
        impossibleTravel: { enabled: true, action: "challenge" },
        botDetection: { enabled: true },
      },
      onDeliveryError(error) {
        console.error("Cloud delivery failed", error.code, error.channel);
      },
    }),
  ],
});
```

Run the migration after enabling Cloud:

```bash
npx own-auth migrate
```

## Client

The client plugin solves a Cloud proof-of-work challenge away from the browser main thread and retries the request once.

```ts
import { cloudClient, createOwnAuthClient } from "own-auth/client";

export const authClient = createOwnAuthClient({
  plugins: [cloudClient({ autoSolveChallenge: true })],
});
```

React Native and other native clients can use `cloudNativeClient()`. Server-side clients can import `solveCloudChallenge()` from `own-auth/challenge-solver`.

## Events And Outbox

Cloud events contain allowlisted projections only. Passwords, session tokens, one-time codes, provider credentials, invitation tokens, message bodies, and raw request bodies are never included. Each event is capped at 64 KB and every string is capped at 4096 characters.

Postgres and D1 store events in `own_auth_cloud_outbox`. Regular events are sent in batches and retried with exponential backoff. Deletion events use the priority endpoint and are never cleared unless `includePriority: true` is passed explicitly.

By default, Own Auth awaits a small outbox flush at the end of each auth operation. This is the safest mode for ordinary servers and request handlers. Runtimes with a request-lifetime scheduler can move that work after the response:

```ts
cloud({
  key: process.env.OWN_AUTH_CLOUD_KEY!,
  flushMode: "background",
  schedule(task) {
    executionContext.waitUntil(task);
  },
});
```

Long-running processes can use `flushMode: "manual"` and call `auth.cloud.flushOutbox()` from their existing worker or scheduled job. Own Auth never starts a timer that keeps a process alive.

```ts
await auth.cloud.flushOutbox();
await auth.cloud.clearOutbox();
```

Use the remaining operational methods for scheduled maintenance and incident response:

```ts
auth.cloud.isConfigured();
await auth.cloud.rotateChallengeSecret();
await auth.cloud.cleanup(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000));
```

When 10,000 unacknowledged regular events are queued, Own Auth stops recording new regular events and authentication continues. The adapter checks capacity and writes atomically, so concurrent requests cannot exceed the limit or advance an entity version for a dropped event. Priority deletion events are still recorded.

Own Auth records when backpressure first drops an event. After regular ingestion resumes, it reports the completed period to Cloud and clears the local marker only after Cloud acknowledges it. The Cloud dashboard shows the latest active or completed data-gap period because historical audit, delivery, and analytics events dropped during that period cannot be reconstructed by backfill.

## Backfill

Backfill explicitly sends current users, organisations, organisation memberships, and active sessions to a newly connected Cloud app. It does not reconstruct historical audit, login, analytics, or delivery events.

```ts
await auth.cloud.backfill({
  batchSize: 100,
  onProgress(progress) {
    console.log(progress.sent, progress.cursor);
  },
});
```

Backfill is paginated, resumable, cancellable through an `AbortSignal`, and idempotent by entity version. It never runs automatically.

## User Erasure

Call `auth.cloud.eraseUser(userId)` when an application user is permanently deleted. Own Auth removes pending local events linked through the user, actor, a user-type audit target, delivery recipient, invitation recipient, or metadata before writing the priority deletion event. Cloud then removes that user's replicas, ingested events, remote commands, delivery records, audit and security records, analytics membership, and pending exports.

```ts
await auth.cloud.eraseUser(userId);
```

## Delivery

When Cloud is configured without an explicit provider, email and SMS requests use its authenticated delivery endpoints. A delivery failure does not undo token or code creation. The result reports the failure explicitly and `onDeliveryError` receives its safe category.

```ts
const result = await auth.requestMagicLink({ email: "user@example.com" });

if (result.delivery.status === "failed") {
  console.error(result.delivery.reason);
}
```

Configure `emailProvider` or `smsProvider` to send that channel through another service while keeping Cloud enabled for the dashboard, analytics, security, and any other managed channel. An explicit provider always takes precedence over Cloud delivery.

## Advisory Security

Before login operations, Own Auth can ask Cloud for `allow`, `challenge`, or `deny`. The request times out after 200 ms. On network failure, Own Auth uses a short local cache and its local rate limits. After five consecutive failures, the Cloud security circuit opens for 30 seconds. Set `security.localOnly: true` to disable Cloud security calls while keeping other Cloud modules.

Pass the trusted client IP through `createOwnAuthHandler({ getRequestContext })` when using IP-based security. Do not copy an untrusted client-supplied forwarding header directly. Without an IP, Cloud can still advise on the request, but Own Auth does not cache that decision.

Challenge tokens are signed and verified locally, expire after 30 seconds, and are bound to the request IP and path. Their nonce is consumed once. Cloud never signs or verifies these tokens.

After a denial, a client may retry once with `X-OwnAuth-Appeal: 1`. Own Auth responds with a higher-difficulty, single-use challenge. Solving it proves the retry locally; it does not change Cloud's stored security decision.

## Remote Mutations

The framework-neutral Own Auth handler exposes the configured webhook path, `/api/auth/cloud-webhook` by default. It accepts signed commands to disable a user, enable a user, or revoke that user's sessions. The application must expose this handler route publicly for dashboard mutations to work.

Create the webhook secret in the Cloud app settings and keep it in the server environment as `OWN_AUTH_WEBHOOK_SECRET`. Applications that do not use remote dashboard mutations do not need this secret or the webhook route.

Commands require a timestamp, nonce, idempotency key, key ID, and HMAC-SHA256 signature. Reservations and replay checks are durable in Postgres and D1. Resolved retries return the stored result; a concurrent command returns `503` with `Retry-After: 5`.

During webhook-secret rotation, configure both secrets with distinct key IDs. Remove the previous pair after Cloud's overlap window ends.

```ts
cloud({
  key: process.env.OWN_AUTH_CLOUD_KEY!,
  webhookSigningSecret: process.env.OWN_AUTH_WEBHOOK_SECRET,
  webhookKeyId: "2026-08",
  webhookPreviousSigningSecret: process.env.OWN_AUTH_PREVIOUS_WEBHOOK_SECRET,
  webhookPreviousKeyId: "2026-07",
  webhookPreviousValidUntil: process.env.OWN_AUTH_PREVIOUS_WEBHOOK_VALID_UNTIL,
});
```

## Disconnecting

Disconnect the app in the Cloud dashboard or call the Cloud disconnect API before removing `cloud()`. Removing the plugin alone cannot notify Cloud, so Cloud otherwise waits for the inactivity timeout. Authentication, users, sessions, organisations, API keys, and audit records remain in the application database. After pending privacy events are acknowledged, the Cloud migration tables can be dropped.
