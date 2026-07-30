import type {
  AtomicAuthEventWrite,
  AtomicAuthenticationMethodRemovalInput,
  AtomicAuthenticationMethodRemovalResult,
  AtomicInvitationAcceptanceInput,
  AtomicInvitationAcceptanceResult,
  AtomicInvitationRevocationInput,
  AuthenticationMethodReference
} from "../auth-storage-atomic.js";
import {
  booleanValue,
  numberValue
} from "../database-row.js";
import {
  mapInvitation,
  mapOrganisationMember
} from "../database-mappers.js";
import type { Invitation } from "../types.js";
import type { PostgresQueryable, Row } from "./postgres-types.js";

export async function acceptPostgresInvitationAtomically(
  db: PostgresQueryable,
  input: AtomicInvitationAcceptanceInput
): Promise<AtomicInvitationAcceptanceResult | null> {
  const params: unknown[] = [
    input.operationId,
    input.tokenId,
    input.tokenHash,
    input.invitationId,
    input.userId,
    input.memberId,
    input.acceptedAt
  ];
  const eventWrite = appendEventWriteCtes(input.event, params, "upserted_member");
  const result = await db.query<Row>(
    `with locked_invitation as materialized (
       select invitation.*
       from own_auth_invitations invitation
       join own_auth_tokens token on token.id = invitation.token_id
       join own_auth_users auth_user on auth_user.id = $5
       join own_auth_organisations organisation on organisation.id = invitation.organisation_id
       where invitation.id = $4
         and invitation.status = 'pending'
         and invitation.expires_at > $7
         and token.id = $2
         and token.token_hash = $3
         and token.type = 'organisation_invite'
         and token.used_at is null
         and token.expires_at > $7
         and token.organisation_id = invitation.organisation_id
         and token.email is not null
         and token.email = invitation.email
         and auth_user.email = token.email
         and auth_user.disabled_at is null
         and organisation.disabled_at is null
       for update of invitation, token
     ), accepted_invitation as (
       update own_auth_invitations invitation
       set status = 'accepted', accepted_at = $7, operation_id = $1
       from locked_invitation locked
       where invitation.id = locked.id and invitation.status = 'pending'
       returning invitation.*
     ), claimed_token as (
       update own_auth_tokens token
       set used_at = $7
       from accepted_invitation invitation
       where token.id = invitation.token_id
         and token.id = $2
         and token.used_at is null
         and token.expires_at > $7
       returning token.id
     ), upserted_member as (
       insert into own_auth_organisation_members (
         id, organisation_id, user_id, role, status, joined_at,
         removed_at, created_at, updated_at
       )
       select
         $6, invitation.organisation_id, $5, invitation.role, 'active', $7,
         null, $7, $7
       from accepted_invitation invitation
       cross join claimed_token
       on conflict (organisation_id, user_id) do update set
         role = excluded.role,
         status = 'active',
         joined_at = coalesce(own_auth_organisation_members.joined_at, excluded.joined_at),
         removed_at = null,
         updated_at = excluded.updated_at
       returning own_auth_organisation_members.*
     ), ${eventWrite.sql}
     select
       to_jsonb(invitation) as invitation,
       to_jsonb(member) as member
     from accepted_invitation invitation
     cross join upserted_member member
     where ${eventWrite.completionPredicate}`,
    params
  );
  const row = result.rows[0];
  if (!row) return null;
  return {
    invitation: mapInvitation(asRow(row.invitation, "accepted invitation")),
    member: mapOrganisationMember(asRow(row.member, "accepted invitation member"))
  };
}

export async function revokePostgresInvitationAtomically(
  db: PostgresQueryable,
  input: AtomicInvitationRevocationInput
): Promise<Invitation<string> | null> {
  const params: unknown[] = [
    input.operationId,
    input.invitationId,
    input.revokedAt
  ];
  const eventWrite = appendEventWriteCtes(input.event, params, "revoked_invitation");
  const result = await db.query<Row>(
    `with revoked_invitation as (
       update own_auth_invitations
       set status = 'revoked', revoked_at = $3, operation_id = $1
       where id = $2 and status = 'pending'
       returning *
     ), consumed_token as (
       update own_auth_tokens token
       set used_at = coalesce(token.used_at, $3)
       from revoked_invitation invitation
       where token.id = invitation.token_id
       returning token.id
     ), ${eventWrite.sql}
     select to_jsonb(invitation) as invitation
     from revoked_invitation invitation
     where ${eventWrite.completionPredicate}`,
    params
  );
  const row = result.rows[0];
  return row
    ? mapInvitation(asRow(row.invitation, "revoked invitation"))
    : null;
}

export async function removePostgresAuthenticationMethodAtomically(
  db: PostgresQueryable,
  input: AtomicAuthenticationMethodRemovalInput
): Promise<AtomicAuthenticationMethodRemovalResult> {
  const stateSql = authenticationMethodSql(input.method, "$2");
  const mutationSql = authenticationMethodSql(input.method, "$3");

  while (true) {
    const state = await db.query<Row>(
      `select
         auth_user.auth_method_version,
         ${stateSql.targetExists} as target_exists,
         ${stateSql.hasRemaining} as has_remaining
       from own_auth_users auth_user
       where auth_user.id = $1`,
      [input.userId, input.method.id]
    );
    const row = state.rows[0];
    if (!row || !booleanValue(row.target_exists)) {
      return "not_found";
    }
    if (!booleanValue(row.has_remaining)) {
      return "last_method";
    }

    const params: unknown[] = [
      input.operationId,
      input.userId,
      input.method.id,
      numberValue(row.auth_method_version)
    ];
    const eventWrite = appendEventWriteCtes(input.event, params, "deleted_method");
    const removed = await db.query<Row>(
      `with locked_user as (
         update own_auth_users auth_user
         set auth_method_version = auth_user.auth_method_version + 1,
             auth_method_operation_id = $1
         where auth_user.id = $2
           and auth_user.auth_method_version = $4
           and ${mutationSql.targetExists}
           and ${mutationSql.hasRemaining}
         returning auth_user.id
       ), deleted_method as (
         delete from ${mutationSql.table} method
         using locked_user
         where method.id = $3 and method.user_id = locked_user.id
         returning method.id
       ), ${eventWrite.sql}
       select deleted_method.id
       from deleted_method
       where ${eventWrite.completionPredicate}`,
      params
    );
    if (removed.rows.length === 1) {
      return "removed";
    }
  }
}

interface AuthenticationMethodSql {
  table: "own_auth_accounts" | "own_auth_passkeys";
  targetExists: string;
  hasRemaining: string;
}

function authenticationMethodSql(
  method: AuthenticationMethodReference,
  targetPlaceholder: string
): AuthenticationMethodSql {
  const accountExclusion = method.kind === "account"
    ? `and account.id <> ${targetPlaceholder}`
    : "";
  const passkeyExclusion = method.kind === "passkey"
    ? `and passkey.id <> ${targetPlaceholder}`
    : "";
  const targetTable = method.kind === "account"
    ? "own_auth_accounts"
    : "own_auth_passkeys";
  const targetExists =
    `exists (
       select 1 from ${targetTable} target
       where target.id = ${targetPlaceholder} and target.user_id = auth_user.id
     )`;
  const hasRemaining =
    `(auth_user.password_hash is not null
      or auth_user.email is not null
      or auth_user.phone is not null
      or exists (
        select 1 from own_auth_accounts account
        where account.user_id = auth_user.id
          ${accountExclusion}
          and (
            account.provider in ('apple', 'github', 'google')
            or account.provider like 'saml.%'
          )
      )
      or exists (
        select 1 from own_auth_passkeys passkey
        where passkey.user_id = auth_user.id
          ${passkeyExclusion}
      ))`;
  return { table: targetTable, targetExists, hasRemaining };
}

interface EventWriteCtes {
  sql: string;
  completionPredicate: string;
}

function appendEventWriteCtes(
  write: AtomicAuthEventWrite,
  params: unknown[],
  sourceCte: string
): EventWriteCtes {
  const audit = write.auditEvent;
  const auditParams = [
    audit.id,
    audit.eventType,
    audit.actorUserId,
    audit.targetUserId,
    audit.organisationId,
    audit.apiKeyId,
    audit.ipAddress,
    audit.userAgent,
    JSON.stringify(audit.metadata),
    audit.createdAt
  ].map((value) => bind(params, value));
  const ctes = [
    `inserted_audit as (
       insert into own_auth_audit_events (
         id, event_type, actor_user_id, target_user_id, organisation_id,
         api_key_id, ip_address, user_agent, metadata, created_at
       )
       select
         ${auditParams[0]}, ${auditParams[1]}, ${auditParams[2]}, ${auditParams[3]},
         ${auditParams[4]}, ${auditParams[5]}, ${auditParams[6]}, ${auditParams[7]},
         ${auditParams[8]}::jsonb, ${auditParams[9]}
       from ${sourceCte}
       returning id
     )`
  ];

  if (!write.webhookEvent) {
    return {
      sql: ctes.join(", "),
      completionPredicate: "(select count(*) from inserted_audit) = 1"
    };
  }

  const event = write.webhookEvent;
  const eventParams = [
    event.id,
    event.type,
    event.version,
    event.payload,
    event.createdAt
  ].map((value) => bind(params, value));
  const deliveriesParam = bind(params, JSON.stringify(
    write.webhookDeliveries.map((delivery) => ({
      id: delivery.id,
      endpoint_id: delivery.endpointId,
      endpoint_url: delivery.url,
      created_at: delivery.createdAt.toISOString()
    }))
  ));
  ctes.push(
    `inserted_webhook_event as (
       insert into own_auth_webhook_events (
         id, event_type, version, payload, created_at
       )
       select
         ${eventParams[0]}, ${eventParams[1]}, ${eventParams[2]},
         ${eventParams[3]}, ${eventParams[4]}
       from inserted_audit
       returning id
     )`,
    `webhook_delivery_rows as (
       select *
       from jsonb_to_recordset(${deliveriesParam}::jsonb) as delivery(
         id text, endpoint_id text, endpoint_url text, created_at timestamptz
       )
     )`,
    `inserted_webhook_deliveries as (
       insert into own_auth_webhook_deliveries (
         id, event_id, endpoint_id, endpoint_url, status, attempts_in_cycle,
         total_attempts, next_attempt_at, created_at, updated_at
       )
       select
         delivery.id, event.id, delivery.endpoint_id, delivery.endpoint_url,
         'pending', 0, 0, delivery.created_at, delivery.created_at, delivery.created_at
       from webhook_delivery_rows delivery
       cross join inserted_webhook_event event
       returning id
     )`
  );
  return {
    sql: ctes.join(", "),
    completionPredicate:
      "(select count(*) from inserted_audit) = 1 " +
      "and (select count(*) from inserted_webhook_event) = 1 " +
      `and (select count(*) from inserted_webhook_deliveries) = ${write.webhookDeliveries.length}`
  };
}

function bind(params: unknown[], value: unknown): string {
  params.push(value);
  return `$${params.length}`;
}

function asRow(value: unknown, context: string): Row {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Postgres ${context} returned an invalid row`);
  }
  return value as Row;
}
