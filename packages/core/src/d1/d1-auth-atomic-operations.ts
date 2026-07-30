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
import type { DatabaseRow } from "../database-types.js";
import {
  mapInvitation,
  mapOrganisationMember
} from "../database-mappers.js";
import {
  invitationReturning,
  organisationMemberReturning
} from "../database-schema.js";
import type { Invitation } from "../types.js";
import type {
  D1DatabaseLike,
  D1PreparedStatementLike
} from "./d1-types.js";
import { toD1Value } from "./d1-values.js";

export async function acceptD1InvitationAtomically(
  db: D1DatabaseLike,
  input: AtomicInvitationAcceptanceInput
): Promise<AtomicInvitationAcceptanceResult | null> {
  const acceptedAt = input.acceptedAt.getTime();
  const guard = invitationGuard(input.invitationId, input.operationId);
  const statements = [
    statement(
      db,
      `update own_auth_invitations
       set status = 'accepted', accepted_at = ?, operation_id = ?
       where id = ?
         and status = 'pending'
         and expires_at > ?
         and exists (
           select 1
           from own_auth_tokens token
           join own_auth_users auth_user on auth_user.id = ?
           join own_auth_organisations organisation
             on organisation.id = own_auth_invitations.organisation_id
           where token.id = ?
             and token.id = own_auth_invitations.token_id
             and token.token_hash = ?
             and token.type = 'organisation_invite'
             and token.used_at is null
             and token.expires_at > ?
             and token.organisation_id = own_auth_invitations.organisation_id
             and token.email is not null
             and token.email = own_auth_invitations.email
             and auth_user.email = token.email
             and auth_user.disabled_at is null
             and organisation.disabled_at is null
         )
       returning ${invitationReturning}`,
      [
        acceptedAt,
        input.operationId,
        input.invitationId,
        acceptedAt,
        input.userId,
        input.tokenId,
        input.tokenHash,
        acceptedAt
      ]
    ),
    statement(
      db,
      `update own_auth_tokens
       set used_at = ?
       where id = ?
         and used_at is null
         and expires_at > ?
         and exists (
           select 1 from own_auth_invitations
           where id = ? and operation_id = ?
         )
       returning id`,
      [
        acceptedAt,
        input.tokenId,
        acceptedAt,
        input.invitationId,
        input.operationId
      ]
    ),
    statement(
      db,
      `insert into own_auth_organisation_members (
         id, organisation_id, user_id, role, status, joined_at,
         removed_at, created_at, updated_at
       )
       select
         ?, invitation.organisation_id, ?, invitation.role, 'active', ?,
         null, ?, ?
       from own_auth_invitations invitation
       where invitation.id = ? and invitation.operation_id = ?
         and exists (
           select 1 from own_auth_tokens token
           where token.id = invitation.token_id and token.used_at = ?
         )
       on conflict (organisation_id, user_id) do update set
         role = excluded.role,
         status = 'active',
         joined_at = coalesce(own_auth_organisation_members.joined_at, excluded.joined_at),
         removed_at = null,
         updated_at = excluded.updated_at
       returning ${organisationMemberReturning}`,
      [
        input.memberId,
        input.userId,
        acceptedAt,
        acceptedAt,
        acceptedAt,
        input.invitationId,
        input.operationId,
        acceptedAt
      ]
    ),
    ...eventStatements(db, input.event, guard),
    statement(
      db,
      "update own_auth_invitations set operation_id = null where id = ? and operation_id = ?",
      [input.invitationId, input.operationId]
    )
  ];
  const results = await db.batch<DatabaseRow>(statements);
  const invitationRow = results[0]?.results?.[0];
  const memberRow = results[2]?.results?.[0];
  if (!invitationRow || !memberRow) return null;
  return {
    invitation: mapInvitation(invitationRow),
    member: mapOrganisationMember(memberRow)
  };
}

export async function revokeD1InvitationAtomically(
  db: D1DatabaseLike,
  input: AtomicInvitationRevocationInput
): Promise<Invitation<string> | null> {
  const revokedAt = input.revokedAt.getTime();
  const guard = invitationGuard(input.invitationId, input.operationId);
  const statements = [
    statement(
      db,
      `update own_auth_invitations
       set status = 'revoked', revoked_at = ?, operation_id = ?
       where id = ? and status = 'pending'
       returning ${invitationReturning}`,
      [revokedAt, input.operationId, input.invitationId]
    ),
    statement(
      db,
      `update own_auth_tokens
       set used_at = coalesce(used_at, ?)
       where id = (
         select token_id from own_auth_invitations
         where id = ? and operation_id = ?
       )`,
      [revokedAt, input.invitationId, input.operationId]
    ),
    ...eventStatements(db, input.event, guard),
    statement(
      db,
      "update own_auth_invitations set operation_id = null where id = ? and operation_id = ?",
      [input.invitationId, input.operationId]
    )
  ];
  const results = await db.batch<DatabaseRow>(statements);
  const row = results[0]?.results?.[0];
  return row ? mapInvitation(row) : null;
}

export async function removeD1AuthenticationMethodAtomically(
  db: D1DatabaseLike,
  input: AtomicAuthenticationMethodRemovalInput
): Promise<AtomicAuthenticationMethodRemovalResult> {
  const stateSql = authenticationMethodSql(input.method, "?1");
  const mutationSql = authenticationMethodSql(input.method, "?4");

  while (true) {
    const state = await statement(
      db,
      `select
         auth_user.auth_method_version,
         ${stateSql.targetExists} as target_exists,
         ${stateSql.hasRemaining} as has_remaining
       from own_auth_users auth_user
       where auth_user.id = ?2`,
      [input.method.id, input.userId]
    ).first<DatabaseRow>();
    if (!state || !booleanValue(state.target_exists)) {
      return "not_found";
    }
    if (!booleanValue(state.has_remaining)) {
      return "last_method";
    }

    const expectedVersion = numberValue(state.auth_method_version);
    const guard = userGuard(input.userId, input.operationId);
    const statements = [
      statement(
        db,
        `update own_auth_users as auth_user
         set auth_method_version = auth_method_version + 1,
             auth_method_operation_id = ?1
         where auth_user.id = ?2
           and auth_user.auth_method_version = ?3
           and ${mutationSql.targetExists}
           and ${mutationSql.hasRemaining}
         returning id`,
        [
          input.operationId,
          input.userId,
          expectedVersion,
          input.method.id
        ]
      ),
      statement(
        db,
        `delete from ${mutationSql.table}
         where id = ? and user_id = ?
           and exists (
             select 1 from own_auth_users
             where id = ? and auth_method_operation_id = ?
           )
         returning id`,
        [
          input.method.id,
          input.userId,
          input.userId,
          input.operationId
        ]
      ),
      ...eventStatements(db, input.event, guard),
      statement(
        db,
        `update own_auth_users
         set auth_method_operation_id = null
         where id = ? and auth_method_operation_id = ?`,
        [input.userId, input.operationId]
      )
    ];
    const results = await db.batch<DatabaseRow>(statements);
    if (results[1]?.results?.[0]) {
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
  const table = method.kind === "account"
    ? "own_auth_accounts"
    : "own_auth_passkeys";
  return {
    table,
    targetExists:
      `exists (
         select 1 from ${table} target
         where target.id = ${targetPlaceholder} and target.user_id = auth_user.id
       )`,
    hasRemaining:
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
        ))`
  };
}

interface D1Guard {
  sql: string;
  values: readonly unknown[];
}

function invitationGuard(invitationId: string, operationId: string): D1Guard {
  return {
    sql:
      "exists (select 1 from own_auth_invitations where id = ? and operation_id = ?)",
    values: [invitationId, operationId]
  };
}

function userGuard(userId: string, operationId: string): D1Guard {
  return {
    sql:
      "exists (select 1 from own_auth_users where id = ? and auth_method_operation_id = ?)",
    values: [userId, operationId]
  };
}

function eventStatements(
  db: D1DatabaseLike,
  write: AtomicAuthEventWrite,
  guard: D1Guard
): D1PreparedStatementLike[] {
  const audit = write.auditEvent;
  const statements = [
    statement(
      db,
      `insert into own_auth_audit_events (
         id, event_type, actor_user_id, target_user_id, organisation_id,
         api_key_id, ip_address, user_agent, metadata, created_at
       )
       select ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
       where ${guard.sql}`,
      [
        audit.id,
        audit.eventType,
        audit.actorUserId,
        audit.targetUserId,
        audit.organisationId,
        audit.apiKeyId,
        audit.ipAddress,
        audit.userAgent,
        JSON.stringify(audit.metadata),
        audit.createdAt.getTime(),
        ...guard.values
      ]
    )
  ];
  if (!write.webhookEvent) return statements;

  const event = write.webhookEvent;
  statements.push(
    statement(
      db,
      `insert into own_auth_webhook_events (
         id, event_type, version, payload, created_at
       )
       select ?, ?, ?, ?, ?
       where ${guard.sql}`,
      [
        event.id,
        event.type,
        event.version,
        event.payload,
        event.createdAt.getTime(),
        ...guard.values
      ]
    ),
    ...write.webhookDeliveries.map((delivery) => statement(
      db,
      `insert into own_auth_webhook_deliveries (
         id, event_id, endpoint_id, endpoint_url, status, attempts_in_cycle,
         total_attempts, next_attempt_at, created_at, updated_at
       )
       select ?, ?, ?, ?, 'pending', 0, 0, ?, ?, ?
       where ${guard.sql}`,
      [
        delivery.id,
        event.id,
        delivery.endpointId,
        delivery.url,
        delivery.createdAt.getTime(),
        delivery.createdAt.getTime(),
        delivery.createdAt.getTime(),
        ...guard.values
      ]
    ))
  );
  return statements;
}

function statement(
  db: D1DatabaseLike,
  sql: string,
  values: readonly unknown[]
): D1PreparedStatementLike {
  return db.prepare(sql).bind(...values.map(toD1Value));
}
