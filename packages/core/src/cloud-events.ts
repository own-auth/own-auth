import { createUuidV7, hashSecret } from "./crypto.js";
import { cloudEventContract } from "./cloud-event-contract.js";
import {
  cloudEventTypes,
  type CloudEntityType,
  type CloudEvent,
  type CloudEventType,
  type CloudOperationContext
} from "./cloud-types.js";
import type {
  Organisation,
  OrganisationMember,
  Session,
  AuditEvent,
  User
} from "./types.js";
import type { AuthStorage } from "./storage.js";
import { cloudSignInOperations } from "./cloud-runtime-helpers.js";
import { isRecord } from "./value-guards.js";

const eventTypes = new Set<string>(cloudEventTypes);
const topLevelFields = new Set([
  "id", "type", "timestamp", "appId", "version", "entityVersion", "data", "meta"
]);
const eventMetaFields = cloudEventFieldSets((type) =>
  cloudEventContract.events[type].meta
);
const eventDataFields = cloudEventFieldSets((type) =>
  Object.keys(cloudEventContract.events[type].fields)
);
const uuidV7Pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export interface CloudEventDraft {
  type: CloudEventType;
  data: Record<string, unknown>;
  entity?: { type: CloudEntityType; id: string };
  priority?: boolean;
  context?: CloudOperationContext["request"];
  userId?: string;
}

type CloudFieldDefinition = {
  type: "date" | "integer" | "object" | "string" | "string-array";
  required: boolean;
  maximum?: number;
  minimum?: number;
  nullable?: boolean;
  values?: readonly string[];
};

export async function cloudUserAuthMethods(
  storage: AuthStorage,
  user: User
): Promise<string[]> {
  const [accounts, totp, passkeys] = await Promise.all([
    storage.listAccountsByUserId(user.id),
    storage.getActiveTotpFactorByUserId(user.id),
    storage.listPasskeyCredentialsByUserId(user.id)
  ]);
  return [...new Set([
    ...(user.passwordHash ? ["password"] : []),
    ...(user.email ? ["magic_link"] : []),
    ...(user.phone ? ["phone"] : []),
    ...accounts.map(({ provider }) => provider),
    ...(totp ? ["totp"] : []),
    ...(passkeys.length > 0 ? ["passkey"] : [])
  ])].sort();
}

export function cloudUserEvent(
  type: "user.created" | "user.updated",
  user: User,
  authMethods: readonly string[],
  context?: CloudOperationContext["request"]
): CloudEventDraft {
  return {
    type,
    data: {
      userId: user.id,
      email: user.email,
      name: user.name,
      authMethods: [...authMethods]
    },
    entity: { type: "user", id: user.id },
    context,
    userId: user.id
  };
}

export function createCloudEvent(
  appId: string,
  draft: CloudEventDraft,
  now = new Date()
): CloudEvent {
  const definition = cloudEventContract.events[draft.type];
  const metadata = {
    ip: draft.context?.ipAddress,
    userAgent: draft.context?.userAgent,
    userId: draft.userId
  };
  const event: CloudEvent = {
    id: createUuidV7(now.getTime()),
    type: draft.type,
    timestamp: now.toISOString(),
    appId,
    version: 1,
    data: stripUndefined(draft.data),
    meta: stripUndefined(Object.fromEntries(
      definition.meta.map((name) => [name, metadata[name]])
    ))
  };
  validateCloudEvent(event);
  return event;
}

export function validateCloudEvent(event: CloudEvent, requireEntityVersion = false): void {
  const input = event as unknown as Record<string, unknown>;
  if (!isRecord(input)) throw new Error("Cloud event must be an object");
  rejectUnknownFields(input, topLevelFields, "Cloud event");
  if (!eventTypes.has(event.type)) throw new Error(`Cloud event has unsupported type ${event.type}`);
  if (!uuidV7Pattern.test(event.id)) throw new Error("Cloud event has invalid id");
  if (typeof event.appId !== "string" || !event.appId || event.appId.length > 128) {
    throw new Error("Cloud event has invalid appId");
  }
  if (event.version !== 1) throw new Error("Cloud event has unsupported version");
  if (!isIsoTimestamp(event.timestamp)) {
    throw new Error("Cloud event has invalid timestamp");
  }
  if (!isRecord(event.data)) throw new Error("Cloud event data must be an object");
  if (!isRecord(event.meta)) throw new Error("Cloud event metadata must be an object");
  const definition = cloudEventContract.events[event.type];
  rejectUnknownFields(event.meta, eventMetaFields[event.type], "Cloud event metadata");
  const requiredMeta = "requiredMeta" in definition
    ? definition.requiredMeta ?? []
    : [];
  for (const name of requiredMeta) {
    if (typeof event.meta[name] !== "string" || !event.meta[name]) {
      throw new Error(`Cloud event ${event.type} has invalid metadata ${name}`);
    }
  }
  if (Object.values(event.meta).some((value) => typeof value !== "string")) {
    throw new Error("Cloud event metadata values must be strings");
  }
  for (const key of Object.keys(event.data)) {
    if (!eventDataFields[event.type].has(key)) {
      throw new Error(`Cloud event ${event.type} contains unknown field ${key}`);
    }
  }
  if (definition.entity) {
    if (requireEntityVersion && event.entityVersion === undefined) {
      throw new Error(`Cloud event ${event.type} requires an entity version`);
    }
    if (event.entityVersion !== undefined &&
      (!Number.isSafeInteger(event.entityVersion) || event.entityVersion < 1)) {
      throw new Error(`Cloud event ${event.type} has an invalid entity version`);
    }
  } else if (event.entityVersion !== undefined) {
    throw new Error(`Cloud event ${event.type} must not contain an entity version`);
  }
  assertValues(event.data);
  assertValues(event.meta);
  validateCloudEventData(
    event.type,
    event.data,
    definition.fields as Record<string, CloudFieldDefinition>
  );
  if (event.type === "audit.entry") validateAuditMetadata(event.data.metadata);
  if (new TextEncoder().encode(JSON.stringify(event)).length > cloudEventContract.maxEventBytes) {
    throw new Error("Cloud event payload exceeds 64KB");
  }
}

function cloudEventFieldSets(
  values: (type: CloudEventType) => readonly string[]
): Record<CloudEventType, ReadonlySet<string>> {
  const fields = Object.create(null) as Record<
    CloudEventType,
    ReadonlySet<string>
  >;
  for (const type of cloudEventTypes) {
    fields[type] = new Set(values(type));
  }
  return fields;
}

function isIsoTimestamp(value: string): boolean {
  return new RegExp(cloudEventContract.timestampPattern).test(value) &&
    Number.isFinite(Date.parse(value)) && validIsoCalendarDate(value);
}

function validIsoCalendarDate(value: string): boolean {
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(5, 7));
  const day = Number(value.slice(8, 10));
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return year >= 1 && month >= 1 && month <= 12 &&
    day >= 1 && day <= (days[month - 1] ?? 0);
}

function rejectUnknownFields(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  label: string
): void {
  const unknown = Object.keys(value).find((key) => !allowed.has(key));
  if (unknown) throw new Error(`${label} contains unknown field ${unknown}`);
}

function validateCloudEventData(
  type: CloudEventType,
  data: Record<string, unknown>,
  fields: Record<string, CloudFieldDefinition>
): void {
  for (const [name, field] of Object.entries(fields)) {
    const value = data[name];
    if (value === undefined) {
      if (field.required) throw new Error(`Cloud event ${type} has invalid ${name}`);
      continue;
    }
    if (value === null) {
      if (!field.nullable) throw new Error(`Cloud event ${type} has invalid ${name}`);
      continue;
    }
    const valid = field.type === "string"
      ? typeof value === "string" && value.length > 0
      : field.type === "string-array"
        ? Array.isArray(value) && value.every((item) => typeof item === "string" && item.length > 0)
        : field.type === "date"
          ? typeof value === "string" && isIsoTimestamp(value)
          : field.type === "integer"
            ? Number.isSafeInteger(value) &&
              (field.minimum === undefined || Number(value) >= field.minimum) &&
              (field.maximum === undefined || Number(value) <= field.maximum)
            : isRecord(value);
    if (!valid || (field.values && !field.values.includes(value as string))) {
      throw new Error(`Cloud event ${type} has invalid ${name}`);
    }
  }
}

export function isPriorityCloudEvent(type: CloudEventType): boolean {
  const definition = cloudEventContract.events[type];
  return "priority" in definition && definition.priority === true;
}

export function cloudAppId(key: string): string {
  return `app_${hashSecret(key).slice(0, 24)}`;
}

export function cloudEventsForOperation(context: CloudOperationContext): CloudEventDraft[] {
  const result = isRecord(context.result) ? context.result : null;
  const input = isRecord(context.input) ? context.input : null;
  const request = context.request;
  const user = userFrom(result);
  const session = sessionFrom(result);

  switch (context.operation) {
    case "createUser":
      return user ? [userEvent("user.created", user, request)] : [];
    case "changePassword":
    case "resetPassword":
    case "verifyEmail":
      return user ? [userEvent("user.updated", user, request)] : [];
    case "signUpEmailPassword":
      return session ? [sessionEvent("session.created", session, request)] : [];
    case "signInEmailPassword":
    case "verifyMagicLink":
    case "verifySmsOtp":
    case "completeOAuthSignIn":
    case "signInWithGoogleOneTap":
    case "signInWithVerifiedExternalIdentity":
    case "completePasskeyAuthentication":
    case "completeMfaWithTotp":
    case "completeMfaWithRecoveryCode":
      return session ? [sessionEvent("session.created", session, request)] : [];
    case "getCurrentSession":
    case "requireCurrentSession":
      return session ? [{
        type: "session.validated",
        data: { sessionId: session.id, userId: session.userId },
        context: request,
        userId: session.userId
      }] : [];
    case "disableUser":
      return user ? [{
        type: "user.disabled",
        data: { userId: user.id, reason: input?.reason === "security" ? "security" : "manual" },
        entity: { type: "user", id: user.id },
        context: request,
        userId: user.id
      }] : [];
    case "enableUser":
      return user ? [{
        type: "user.enabled",
        data: { userId: user.id },
        entity: { type: "user", id: user.id },
        context: request,
        userId: user.id
      }] : [];
    case "updateOrganisation": {
      const org = result as unknown as Organisation | null;
      return org?.id ? [organisationEvent("org.updated", org, input, request)] : [];
    }
    case "createOrganisation": {
      const org = isRecord(result?.organisation) ? result.organisation as unknown as Organisation : null;
      const owner = isRecord(result?.ownerMembership)
        ? result.ownerMembership as unknown as OrganisationMember<string>
        : null;
      return org ? [
        organisationEvent("org.created", org, input, request),
        ...(owner ? [cloudOrganisationMemberAddedEvent(
          owner,
          request,
          stringValue(input?.ownerUserId)
        )] : [])
      ] : [];
    }
    case "deleteOrganisation": {
      const org = result as unknown as Organisation | null;
      return org?.id ? [{
        type: "org.deleted",
        data: { orgId: org.id },
        entity: { type: "org", id: org.id },
        priority: true,
        context: request,
        userId: stringValue(input?.actorUserId)
      }] : [];
    }
    case "changeMemberRole": {
      const member = result as unknown as OrganisationMember<string> | null;
      return member?.id
        ? [cloudOrganisationMemberAddedEvent(member, request, stringValue(input?.actorUserId))]
        : [];
    }
    case "acceptInvite": {
      const member = isRecord(result?.member)
        ? result.member as unknown as OrganisationMember<string>
        : null;
      return member?.id ? [cloudOrganisationMemberAddedEvent(member, request, member.userId)] : [];
    }
    case "removeMember": {
      const member = result as unknown as OrganisationMember<string> | null;
      return member?.id ? [cloudOrganisationMemberRemovedEvent(
        member.organisationId,
        member.userId,
        request,
        stringValue(input?.actorUserId)
      )] : [];
    }
    case "scim.deleteUser": {
      const userId = stringValue(result?.userId);
      const organisationId = stringValue(input?.organisationId);
      return userId && organisationId ? [cloudOrganisationMemberRemovedEvent(
        organisationId,
        userId,
        request,
        userId
      )] : [];
    }
    case "inviteMember": {
      const invitation = isRecord(result?.invitation) ? result.invitation : result;
      const orgId = stringValue(invitation?.organisationId);
      return orgId ? [{
        type: "org.invite.created",
        data: {
          orgId,
          invitationId: stringValue(invitation?.id),
          inviteeEmail: stringValue(invitation?.email),
          role: stringValue(invitation?.role),
          expiresAt: dateString(invitation?.expiresAt)
        },
        entity: { type: "org", id: orgId },
        context: request,
        userId: stringValue(input?.invitedByUserId)
      }] : [];
    }
    case "revokeInvitation": {
      const invitation = isRecord(result) ? result : null;
      const orgId = stringValue(invitation?.organisationId);
      return orgId ? [{
        type: "org.invite.revoked",
        data: { orgId, invitationId: stringValue(invitation?.id) },
        entity: { type: "org", id: orgId },
        context: request,
        userId: stringValue(input?.actorUserId)
      }] : [];
    }
    default:
      return [];
  }
}

export function failedLoginEvent(context: CloudOperationContext): CloudEventDraft | null {
  if (!failedAuthenticationOperations.has(context.operation)) return null;
  return {
    type: "login.failed",
    data: {
      userId: context.userId,
      reason: failureReason(context.operation, context.error, Boolean(context.userId))
    },
    context: context.request,
    userId: context.userId
  };
}

const failedAuthenticationOperations = new Set([
  ...cloudSignInOperations,
  "completeMfaWithTotp",
  "completeMfaWithRecoveryCode"
]);

export function auditCloudEvent(event: AuditEvent): CloudEventDraft {
  const targetId = event.targetUserId ?? event.organisationId ?? event.apiKeyId ?? undefined;
  const targetType = event.targetUserId
    ? "user"
    : event.organisationId ? "organisation" : event.apiKeyId ? "api_key" : undefined;
  return {
    type: "audit.entry",
    data: {
      action: event.eventType,
      actorId: event.actorUserId ?? undefined,
      targetId,
      targetType,
      metadata: auditMetadata(event.metadata)
    },
    context: {
      ipAddress: event.ipAddress ?? undefined,
      userAgent: event.userAgent ?? undefined
    },
    userId: event.actorUserId ?? event.targetUserId ?? undefined
  };
}

export function rateLimitCloudEvent(
  endpoint: string,
  limit: number,
  windowMs: number
): CloudEventDraft {
  return {
    type: "ratelimit.triggered",
    data: { endpoint, limit, window: windowMs }
  };
}

export function sessionRevokedCloudEvent(
  session: Session,
  context?: CloudOperationContext["request"]
): CloudEventDraft {
  const reason = cloudSessionRevokeReason(session.revokeReason);
  return {
    type: reason === "expired" ? "session.expired" : "session.revoked",
    data: reason === "expired"
      ? { sessionId: session.id, userId: session.userId }
      : { sessionId: session.id, userId: session.userId, reason },
    entity: { type: "session", id: session.id },
    context,
    userId: session.userId
  };
}

function userEvent(
  type: "user.created" | "user.updated",
  user: User,
  context: CloudOperationContext["request"]
): CloudEventDraft {
  return cloudUserEvent(type, user, basicAuthMethods(user), context);
}

function sessionEvent(
  type: "session.created",
  session: Session,
  context: CloudOperationContext["request"]
): CloudEventDraft {
  return {
    type,
    data: {
      sessionId: session.id,
      userId: session.userId,
      expiresAt: session.expiresAt.toISOString(),
      authMethods: session.authenticationMethods
    },
    entity: { type: "session", id: session.id },
    context,
    userId: session.userId
  };
}

function cloudSessionRevokeReason(
  reason: string | null
): "manual" | "logout" | "security" | "expired" {
  if (reason === "user_logout") return "logout";
  if (reason === "expired") return "expired";
  if (reason?.includes("security") || reason === "user_disabled") return "security";
  return "manual";
}

function organisationEvent(
  type: "org.created" | "org.updated",
  org: Organisation,
  input: Record<string, unknown> | null,
  context: CloudOperationContext["request"]
): CloudEventDraft {
  return {
    type,
    data: type === "org.created"
      ? { orgId: org.id, name: org.name, ownerId: stringValue(input?.ownerUserId) }
      : { orgId: org.id, name: org.name },
    entity: { type: "org", id: org.id },
    context,
    userId: stringValue(input?.actorUserId ?? input?.ownerUserId)
  };
}

export function cloudOrganisationMemberAddedEvent(
  member: OrganisationMember<string>,
  context: CloudOperationContext["request"],
  actorUserId?: string
): CloudEventDraft {
  return {
    type: "org.member.added",
    data: { orgId: member.organisationId, userId: member.userId, role: member.role },
    entity: { type: "org", id: member.organisationId },
    context,
    userId: actorUserId
  };
}

export function cloudOrganisationMemberRemovedEvent(
  organisationId: string,
  userId: string,
  context?: CloudOperationContext["request"],
  actorUserId?: string
): CloudEventDraft {
  return {
    type: "org.member.removed",
    data: { orgId: organisationId, userId },
    entity: { type: "org", id: organisationId },
    context,
    userId: actorUserId
  };
}

function userFrom(result: Record<string, unknown> | null): User | null {
  const candidate = isRecord(result?.user) ? result.user : result;
  return candidate && typeof candidate.id === "string" && "email" in candidate
    ? candidate as unknown as User
    : null;
}

function sessionFrom(result: Record<string, unknown> | null): Session | null {
  const candidate = isRecord(result?.session) ? result.session : result;
  return candidate && typeof candidate.id === "string" && typeof candidate.userId === "string" &&
    candidate.expiresAt instanceof Date
    ? candidate as unknown as Session
    : null;
}

function basicAuthMethods(user: User): string[] {
  const methods: string[] = [];
  if (user.passwordHash) methods.push("password");
  if (user.phone) methods.push("phone");
  return methods;
}

function failureReason(operation: string, error: unknown, knownUser: boolean): string {
  const code = isRecord(error) ? error.code : null;
  if (code === "disabled_user") return "disabled";
  if (code === "rate_limited") return "rate_limited";
  if (code === "cloud_access_denied") return "blocked";
  if (operation === "signInEmailPassword") {
    return knownUser ? "invalid_password" : "user_not_found";
  }
  return "invalid_credentials";
}

function assertValues(value: unknown): void {
  if (typeof value === "string") {
    if (value.length > cloudEventContract.maxStringLength) {
      throw new Error(
        `Cloud event field exceeds ${cloudEventContract.maxStringLength} characters`
      );
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const child of value) assertValues(child);
    return;
  }
  if (isRecord(value)) for (const child of Object.values(value)) assertValues(child);
}

function validateAuditMetadata(value: unknown): void {
  if (!isRecord(value) || Object.keys(value).length > 10) {
    throw new Error("Cloud audit metadata must contain at most 10 string fields");
  }
  for (const entry of Object.values(value)) {
    if (typeof entry !== "string" || entry.length > 256 || containsTokenLikeUrl(entry)) {
      throw new Error("Cloud audit metadata contains an unsafe value");
    }
  }
}

function auditMetadata(value: Record<string, unknown>): Record<string, string> {
  const entries = Object.entries(value);
  if (entries.length > 10) throw new Error("Cloud audit metadata contains too many fields");
  const metadata: Record<string, string> = {};
  for (const [key, child] of entries) {
    if (typeof child !== "string") continue;
    if (child.length > 256 || containsTokenLikeUrl(child)) {
      throw new Error("Cloud audit metadata contains an unsafe value");
    }
    metadata[key] = child;
  }
  return metadata;
}

function containsTokenLikeUrl(value: string): boolean {
  return /https?:\/\/\S*[A-Za-z0-9_-]{17,}/u.test(value);
}

function stripUndefined<T extends Record<string, unknown>>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, child]) => child !== undefined)) as T;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

function dateString(value: unknown): string | undefined {
  return value instanceof Date ? value.toISOString() : stringValue(value);
}
