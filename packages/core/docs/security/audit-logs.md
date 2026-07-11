# Audit Logs

Audit logs record who performed an authentication action, who or what it affected, when it happened, and the available request context. Own Auth writes these events automatically as part of each supported operation.

## Recorded events

| Event | Recorded when |
|---|---|
| `user.signed_up` | A user signs up or is created through an external provider. |
| `user.signed_in` | A user signs in with a password, magic link, phone code, or external provider. |
| `user.signed_out` | A user signs out with a session token. |
| `user.disabled` | A user account is disabled. |
| `user.re_enabled` | A disabled account is enabled again. |
| `external_provider.linked` | An Apple or Google account is linked to a user. |
| `session.created` | A session is created. |
| `session.revoked` | One session is revoked during signout or from a session list. |
| `session.revoked_other` | Every session except the current one is revoked. |
| `session.revoked_all` | Every session for a user is revoked. |
| `magic_link.requested` | A magic-link email is requested. |
| `magic_link.used` | A magic link is consumed to sign in. |
| `email_verification.requested` | An email-verification link is requested. |
| `email.verified` | An email-verification link is consumed. |
| `sms_otp.sent` | An SMS code is sent. |
| `sms_otp.verified` | An SMS code is verified. |
| `phone.verified` | A user's phone number is marked as verified. |
| `password_reset.requested` | A password-reset link is requested. |
| `password.changed` | A password is changed or reset. |
| `api_key.created` | An application API key is created. |
| `api_key.used` | An application API key authenticates a request. |
| `api_key.revoked` | An application API key is revoked. |
| `organisation.created` | An organisation is created. |
| `organisation.deleted` | An organisation is permanently deleted by its owner. |
| `organisation.updated` | An organisation is updated. |
| `member.invited` | An organisation invitation is created. |
| `invite.accepted` | An organisation invitation is accepted. |
| `invite.revoked` | An organisation invitation is revoked. |
| `member.removed` | A member is removed from an organisation. |
| `member.role_changed` | A member's organisation role is changed. |

Own Auth does not currently write events when sessions merely expire or when a rate limit rejects a request.

## Audit event fields

Each `AuditEvent` contains:

| Field | Description |
|---|---|
| `id` | Unique event ID. |
| `eventType` | One of the recorded event names above. |
| `actorUserId` | The user who performed the action, when known. |
| `targetUserId` | The user affected by the action, when known. |
| `organisationId` | The related organisation, when applicable. |
| `apiKeyId` | The related API-key record, when applicable. |
| `ipAddress` | Request IP address when supplied through `request`. |
| `userAgent` | User-Agent value when supplied through `request`. |
| `metadata` | Event-specific structured data. |
| `createdAt` | The time the event was written. |

## Query audit logs

Use `listAuditEvents`. Results are returned as an array with the newest events first.

```ts
const events = await auth.listAuditEvents({
  actorUserId: currentUser.id,
});
```

Filter by API key:

```ts
const events = await auth.listAuditEvents({
  actorUserId: currentUser.id,
  apiKeyId,
});
```

Filters can be combined:

```ts
const events = await auth.listAuditEvents({
  userId,
  organisationId,
  apiKeyId,
  actorUserId: currentUser.id,
});
```

`actorUserId` is required. The available filters are `userId`, `organisationId`, and `apiKeyId`. A user filter matches events where that user is either the actor or the target. Without an organisation filter, users can read only their own events.

`listAuditEvents` does not currently support event-type filters, date ranges, limits, offsets, cursors, or total counts.

### Response

```ts
const [event] = await auth.listAuditEvents({
  actorUserId: currentUser.id,
});

// event -> {
//   id: "evt_...",
//   eventType: "session.created",
//   actorUserId: "usr_...",
//   targetUserId: "usr_...",
//   organisationId: null,
//   apiKeyId: null,
//   ipAddress: "203.0.113.42",
//   userAgent: "Mozilla/5.0...",
//   metadata: { sessionId: "ses_..." },
//   createdAt: Date,
// }
```

## Organisation audit logs

Pass the signed-in user as the actor when loading organisation events:

```ts
const events = await auth.listAuditEvents({
  organisationId,
  actorUserId: currentUser.id,
});
```

Own Auth checks the actor's active membership and `view_audit_events` permission before returning organisation events.

## Request context

Pass request context to auth methods when the audit trail should include an IP address and user agent:

```ts
await auth.signInEmailPassword({
  email,
  password,
  request: {
    ipAddress: req.ip,
    userAgent: req.headers["user-agent"],
  },
});
```

When request context is omitted, `ipAddress` and `userAgent` are stored as `null`.

## Event metadata

Metadata depends on the event:

| Event | Example metadata |
|---|---|
| `session.created` | `{ sessionId: "ses_..." }` |
| `session.revoked` | `{ reason: "user_logout" }` or `{ reason: "user_revoked", sessionId: "ses_..." }` |
| `session.revoked_all` | `{ reason: "password_reset", revoked: 3 }` |
| `user.signed_in` | `{ method: "magic_link" }` or `{ method: "phone_otp" }` when applicable |
| `external_provider.linked` | `{ provider: "google" }` |
| `sms_otp.sent` | `{ purpose: "phone_login", otpId: "otp_..." }` |
| `api_key.created` | `{ name: "Production", scopes: ["reports:read"] }` |
| `api_key.used` | `{ requiredScopes: ["reports:read"] }` |
| `organisation.created` | `{ name: "Acme", slug: "acme" }` |
| `organisation.deleted` | `{ organisationId: "org_...", name: "Acme", slug: "acme", membersRemoved: 3, apiKeysRemoved: 2, invitationsRemoved: 1 }` |
| `member.invited` | `{ email: "bob@example.com", role: "member", invitationId: "inv_..." }` |
| `member.role_changed` | `{ previousRole: "member", role: "owner", ownershipTransferredTo: null }` |
| `member.removed` | `{ memberId: "mem_...", role: "owner", ownershipTransferredTo: "usr_..." }` |

## Retention

Audit events remain in `own_auth_audit_events` until they are removed. Own Auth does not delete them automatically.

Delete events older than a chosen cutoff:

```ts
const deleted = await auth.cleanupAuditLogs({
  olderThan: new Date("2025-01-01T00:00:00.000Z"),
});
```

`cleanupAuditLogs` permanently deletes every audit event created before `olderThan` and returns the number deleted.

## Next step

Read the full [Security Model](/docs/security-model) to understand how the security features work together.
