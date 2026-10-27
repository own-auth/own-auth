const requestMeta = ["ip", "userAgent"] as const;
const userRequestMeta = ["ip", "userAgent", "userId"] as const;
const userMeta = ["userId"] as const;
const requiredUserMeta = ["userId"] as const;

export const cloudEventContract = {
  version: 1,
  maxEventBytes: 64 * 1024,
  maxStringLength: 4096,
  timestampPattern: "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,9})?(?:Z|[+-]\\d{2}:\\d{2})$",
  systemEvents: {
    "email.sent": systemDeliveryEvent(false),
    "email.failed": systemDeliveryEvent(true),
    "sms.sent": systemDeliveryEvent(false),
    "sms.failed": systemDeliveryEvent(true)
  },
  events: {
    "user.created": event("user", {
      userId: field("string", true),
      email: field("string", true, { nullable: true }),
      name: field("string", false, { nullable: true }),
      authMethods: field("string-array", true)
    }, { meta: requestMeta }),
    "user.updated": event("user", {
      userId: field("string", true),
      email: field("string", true, { nullable: true }),
      name: field("string", false, { nullable: true }),
      authMethods: field("string-array", true)
    }, { meta: userRequestMeta, requiredMeta: requiredUserMeta }),
    "user.deleted": event("user", { userId: field("string", true) }, {
      meta: userMeta,
      requiredMeta: requiredUserMeta,
      priority: true
    }),
    "user.disabled": event("user", {
      userId: field("string", true),
      reason: field("string", true, { values: ["manual", "security"] })
    }, { meta: userMeta, requiredMeta: requiredUserMeta }),
    "user.enabled": event("user", { userId: field("string", true) }, {
      meta: userMeta,
      requiredMeta: requiredUserMeta
    }),
    "session.created": event("session", {
      sessionId: field("string", true),
      userId: field("string", true),
      expiresAt: field("date", true),
      authMethods: field("string-array", true)
    }, { meta: userRequestMeta, requiredMeta: requiredUserMeta }),
    "session.validated": event(null, {
      sessionId: field("string", true),
      userId: field("string", true)
    }, { meta: userRequestMeta, requiredMeta: requiredUserMeta }),
    "session.revoked": event("session", {
      sessionId: field("string", true),
      userId: field("string", true),
      reason: field("string", true, {
        values: ["manual", "logout", "security", "expired"]
      })
    }, { meta: userMeta, requiredMeta: requiredUserMeta }),
    "session.expired": event("session", {
      sessionId: field("string", true),
      userId: field("string", true)
    }, { meta: userMeta, requiredMeta: requiredUserMeta }),
    "login.failed": event(null, {
      userId: field("string", false),
      reason: field("string", true, {
        values: [
          "invalid_credentials",
          "invalid_password",
          "user_not_found",
          "disabled",
          "rate_limited",
          "blocked"
        ]
      })
    }, { meta: requestMeta }),
    "login.challenged": event(null, {
      reason: field("string", true, {
        values: ["credential_stuffing", "bot", "impossible_travel", "ip_reputation"]
      }),
      difficulty: field("integer", true, { minimum: 1, maximum: 20 })
    }, { meta: userRequestMeta }),
    "login.blocked": event(null, {
      reason: field("string", true, {
        values: ["credential_stuffing", "bot", "impossible_travel", "ip_reputation"]
      })
    }, { meta: userRequestMeta }),
    "org.created": event("org", {
      orgId: field("string", true),
      name: field("string", true),
      ownerId: field("string", true)
    }, { meta: userMeta, requiredMeta: requiredUserMeta }),
    "org.updated": event("org", {
      orgId: field("string", true),
      name: field("string", true),
      ownerId: field("string", false)
    }, { meta: userMeta }),
    "org.deleted": event("org", { orgId: field("string", true) }, {
      meta: userMeta,
      priority: true
    }),
    "org.member.added": event("org", {
      orgId: field("string", true),
      userId: field("string", true),
      role: field("string", true)
    }, { meta: userMeta }),
    "org.member.removed": event("org", {
      orgId: field("string", true),
      userId: field("string", true)
    }, { meta: userMeta, requiredMeta: requiredUserMeta }),
    "org.invite.created": event("org", {
      orgId: field("string", true),
      invitationId: field("string", true),
      inviteeEmail: field("string", true),
      role: field("string", true),
      expiresAt: field("date", true)
    }, { meta: userMeta, requiredMeta: requiredUserMeta }),
    "org.invite.revoked": event("org", {
      orgId: field("string", true),
      invitationId: field("string", true)
    }, { meta: userMeta, requiredMeta: requiredUserMeta }),
    "email.requested": event(null, {
      messageId: field("string", true),
      type: field("string", true, {
        values: ["magic_link", "verification", "password_reset", "invite"]
      }),
      recipientUserId: field("string", false)
    }, { meta: userMeta }),
    "sms.requested": event(null, {
      messageId: field("string", true),
      type: field("string", true, { values: ["phone_verification", "sms_login_otp"] }),
      recipientUserId: field("string", false)
    }, { meta: userMeta }),
    "ratelimit.triggered": event(null, {
      endpoint: field("string", true),
      limit: field("integer", true, { minimum: 1 }),
      window: field("integer", true, { minimum: 1 })
    }, { meta: userRequestMeta }),
    "audit.entry": event(null, {
      action: field("string", true),
      actorId: field("string", false),
      targetId: field("string", false),
      targetType: field("string", false),
      metadata: field("object", true)
    }, { meta: userRequestMeta })
  }
} as const;

function systemDeliveryEvent(failed: boolean) {
  return event(null, {
    messageId: field("string", true),
    ...(failed ? {
      errorCode: field("string", true, {
        values: [
          "provider_rejected",
          "invalid_recipient",
          "quota_exhausted",
          "retry_exhausted",
          "internal_error"
        ]
      })
    } : {})
  }, { meta: [] });
}

type CloudFieldType = "date" | "integer" | "object" | "string" | "string-array";

function field<
  Type extends CloudFieldType,
  Required extends boolean,
  Values extends readonly string[] | undefined = undefined
>(
  type: Type,
  required: Required,
  options: {
    maximum?: number;
    minimum?: number;
    nullable?: boolean;
    values?: Values;
  } = {}
) {
  return { type, required, ...options } as const;
}

function event<
  Entity extends "org" | "session" | "user" | null,
  Fields extends Record<string, ReturnType<typeof field>>,
  Meta extends readonly ("ip" | "userAgent" | "userId")[],
  RequiredMeta extends readonly Meta[number][] = readonly []
>(
  entity: Entity,
  fields: Fields,
  options: { meta: Meta; requiredMeta?: RequiredMeta; priority?: boolean }
) {
  return { entity, fields, ...options } as const;
}

export type CloudEventContract = typeof cloudEventContract;
