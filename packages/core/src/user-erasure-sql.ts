import { AuthError } from "./errors.js";
import { createUuidV7 } from "./crypto.js";
import { mapUser } from "./database-mappers.js";
import { erasureSqlMatch } from "./user-erasure-sql-match.js";
import { erasureCloudWrites } from "./user-erasure-cloud.js";
import type { AtomicUserErasureInput, StoredUserErasure, UserErasureSubject } from "./user-erasure.js";

export interface ErasureSqlStatement { sql: string; values: unknown[] }
export interface ErasureSqlDatabase {
  dialect: "postgres" | "d1";
  read(sql: string, values?: unknown[]): Promise<Record<string, unknown>[]>;
  atomic(statements: ErasureSqlStatement[]): Promise<void>;
}

export const erasureUserTables = [
  "accounts", "sessions", "tokens", "sms_otps", "api_keys", "organisation_members",
  "oauth_transactions", "mfa_factors", "recovery_codes", "mfa_challenges", "passkeys",
  "webauthn_challenges", "authorization_interactions", "authorization_grants",
  "authorization_codes", "authorization_access_tokens", "authorization_refresh_tokens",
  "oidc_subjects", "saml_transactions", "scim_users", "device_authorizations"
] as const;

const json = (value: unknown) => typeof value === "string" ? JSON.parse(value) : value;
export function mapUserErasure(row: Record<string, unknown>): StoredUserErasure {
  return {
    operationId: String(row.operation_id),
    subject: row.subject === null ? null : json(row.subject) as UserErasureSubject,
    pendingStores: json(row.pending_stores) as string[],
    protectedUntil: Number(row.protected_until_ms),
    cloudEventId: row.cloud_event_id === null ? null : String(row.cloud_event_id),
    pendingCloudEvents: json(row.pending_cloud_events) as string[],
    cloudComplete: row.cloud_complete === true || row.cloud_complete === 1,
    createdAt: Number(row.created_at_ms),
    completedAt: row.completed_at_ms === null ? null : Number(row.completed_at_ms)
  };
}

/** Parameter markers are produced here, never interpolated from user input. */
export function erasureStatement(
  db: Pick<ErasureSqlDatabase, "dialect">, sql: string, values: unknown[] = []
): ErasureSqlStatement {
  let index = 0;
  return { sql: sql.replace(/\?/g, () => db.dialect === "postgres" ? `$${++index}` : `?${++index}`), values };
}

export async function prepareErasureSql(db: ErasureSqlDatabase, input: AtomicUserErasureInput): Promise<ErasureSqlStatement[]> {
  // A fresh internal write ID ensures ON CONFLICT cannot authorize another batch's deletes.
  const writeId = createUuidV7();
  const receiptGuard = () => `exists (select 1 from own_auth_user_erasures where operation_id = ? and write_id = '${writeId}' and subject is not null)`;
  const query = async (sql: string, values: unknown[] = []) => {
    const statement = erasureStatement(db, sql, values);
    return db.read(statement.sql, statement.values);
  };
  const userRow = (await query("select * from own_auth_users where id = ?", [input.userId]))[0];
  if (!userRow) throw new AuthError("user_not_found", "User not found", 404);
  const user = mapUser(userRow);
  if (user.updatedAt.getTime() !== input.expectedUpdatedAt.getTime()) {
    throw new AuthError("erasure_operation_conflict", "The account changed. Retry erasure.", 409);
  }
  const subject: UserErasureSubject = {
    userId: user.id, email: user.email, phone: user.phone, references: [user.id],
    identities: []
  };
  const organisations = await query(
    "select o.* from own_auth_organisations o where owner_user_id = ? or exists " +
    "(select 1 from own_auth_organisation_members m where m.organisation_id = o.id and m.user_id = ? and m.role = 'owner' and m.status = 'active')",
    [user.id, user.id]
  );
  const resolutions = new Map(input.organisations.map((item) => [item.organisationId, item]));
  if (resolutions.size !== input.organisations.length || [...resolutions.keys()].some((id) => !organisations.some((o) => o.id === id))) {
    throw new AuthError("validation_error", "Organisation resolutions must identify an owned organisation", 400);
  }
  const changes: ErasureSqlStatement[] = [];
  const guards: { sql: string; values: unknown[] }[] = [{
    sql: "(select count(*) from own_auth_organisations o where o.owner_user_id = ? or exists (select 1 from own_auth_organisation_members m where m.organisation_id = o.id and m.user_id = ? and m.role = 'owner' and m.status = 'active')) = ?",
    values: [user.id, user.id, organisations.length]
  }];
  const removedOrganisations: string[] = [];
  const transferredOrganisations: { organisationId: string; name: string; ownerUserId: string; newOwnerUserId: string }[] = [];
  const unresolved: string[] = [];
  for (const organisation of organisations) {
    guards.push({ sql: "exists (select 1 from own_auth_organisations where id = ? and owner_user_id = ? and name = ? and updated_at = ?)",
      values: [organisation.id, organisation.owner_user_id, organisation.name, organisation.updated_at] });
    const members = await query("select m.*, u.disabled_at as user_disabled_at from own_auth_organisation_members m join own_auth_users u on u.id = m.user_id where organisation_id = ?", [organisation.id]);
    const eligible = members.filter((m) => m.user_id !== user.id && m.status === "active" && !m.user_disabled_at);
    const otherOwners = eligible.filter((m) => m.role === "owner");
    const resolution = resolutions.get(String(organisation.id));
    if (resolution?.action === "delete") {
      if (resolution.confirmation !== "delete_organisation") throw new AuthError("validation_error", "Confirm organisation deletion", 400);
      removedOrganisations.push(String(organisation.id));
      subject.references.push(String(organisation.id));
      continue;
    }
    const replacement = resolution?.action === "transfer"
      ? eligible.find((m) => m.user_id === resolution.newOwnerUserId)
      : otherOwners[0];
    if (!replacement) {
      unresolved.push(String(organisation.id));
      continue;
    }
    guards.push({ sql: "exists (select 1 from own_auth_organisation_members m join own_auth_users u on u.id = m.user_id where m.id = ? and m.role = ? and m.status = 'active' and u.disabled_at is null)", values: [replacement.id, replacement.role] });
    changes.push(erasureStatement(db, "update own_auth_organisation_members set role = 'owner' where id = ? and " + receiptGuard(), [replacement.id, input.operationId]));
    transferredOrganisations.push({ organisationId: String(organisation.id), name: String(organisation.name),
      ownerUserId: String(organisation.owner_user_id === user.id ? replacement.user_id : organisation.owner_user_id), newOwnerUserId: String(replacement.user_id) });
    if (organisation.owner_user_id === user.id) {
      changes.push(erasureStatement(db, "update own_auth_organisations set owner_user_id = ? where id = ? and " + receiptGuard(), [replacement.user_id, organisation.id, input.operationId]));
    }
  }
  if (unresolved.length) throw new AuthError("user_erasure_ownership_required", "Choose another owner or confirm deletion for each organisation", 409, { organisationIds: unresolved });
  const date = (value: Date) => db.dialect === "postgres" ? value : value.getTime();
  const expiry = db.dialect === "postgres" ? "extract(epoch from expires_at) * 1000" : "expires_at";
  const protection = `(select max(deadline) from (
    select ? as deadline union all
    select max(${expiry}) from own_auth_tokens where user_id is null and (lower(email) = lower(u.email) or phone = u.phone) union all
    select max(${expiry}) from own_auth_sms_otps where user_id is null and phone = u.phone union all
    select max(${expiry}) from own_auth_oauth_transactions where user_id is null union all
    select max(${expiry}) from own_auth_saml_transactions where user_id is null
  ) request_authority)`;
  let predicate = "u.id = ? and u.updated_at = ?" + (db.dialect === "postgres"
    ? " and u.email is not distinct from ? and u.phone is not distinct from ?"
    : " and u.email is ? and u.phone is ?");
  const predicates: unknown[] = [user.id, date(input.expectedUpdatedAt), user.email, user.phone];
  if (input.sessionTokenHash) {
    predicate += " and u.disabled_at is null and exists (select 1 from own_auth_sessions s where s.user_id = u.id and s.token_hash = ? and s.revoked_at is null and s.expires_at > ? and s.idle_expires_at > ? and s.authenticated_at >= ? and s.authenticated_at <= ?" +
      " and (s.assurance_level = 'aal2' or (not exists (select 1 from own_auth_mfa_factors f where f.user_id = u.id and f.status = 'active') and not exists (select 1 from own_auth_passkeys p where p.user_id = u.id))))";
    predicates.push(input.sessionTokenHash, date(new Date(input.now)), date(new Date(input.now)), date(input.authenticatedAfter!), date(new Date(input.now)));
  }
  predicate += " and " + guards.map((guard) => { predicates.push(...guard.values); return guard.sql; }).join(" and ");
  const cloudWrites = erasureCloudWrites(input.cloudEvent, removedOrganisations, transferredOrganisations, input.now);
  const insert = erasureStatement(db,
    "insert into own_auth_user_erasures (operation_id, write_id, user_id, subject, pending_stores, protected_until_ms, cloud_event_id, pending_cloud_events, cloud_complete, created_at_ms) " +
    `select ?, ?, u.id, ?, ?, ${protection}, ?, ?, ?, ? from own_auth_users u where ` + predicate + " on conflict do nothing",
    [input.operationId, writeId, JSON.stringify(subject), JSON.stringify(input.pendingStores), input.protectedUntil,
      input.cloudEvent?.id ?? null, JSON.stringify(cloudWrites.filter((write) => write.priority).map((write) => write.event.id)),
      db.dialect === "postgres" ? false : 0, input.now, ...predicates]);
  const pg = db.dialect === "postgres";
  const receipt = "own_auth_user_erasures";
  const references = pg ? "select jsonb_array_elements_text(subject->'references') as id"
    : "select value as id from json_each(subject, '$.references')";
  const email = pg ? `${receipt}.subject->>'email'` : `json_extract(${receipt}.subject, '$.email')`;
  const phone = pg ? `${receipt}.subject->>'phone'` : `json_extract(${receipt}.subject, '$.phone')`;
  const contact = (prefix: string) => `(lower(${prefix}.email) = lower(${email}) or ${prefix}.phone = ${phone})`;
  const ownedIds = erasureUserTables.map((table) =>
    `select t.id from own_auth_${table} t where t.user_id = ${receipt}.user_id` +
    (table === "tokens" ? ` or (t.user_id is null and ${contact("t")})` :
      table === "sms_otps" ? ` or (t.user_id is null and t.phone = ${phone})` : ""))
    .concat(`select i.id from own_auth_invitations i where ${contact("i")}`,
      `select i.token_id as id from own_auth_invitations i where i.token_id is not null and ${contact("i")}`,
      `select c.id from own_auth_oauth_credentials c join own_auth_accounts a on a.id = c.account_id where a.user_id = ${receipt}.user_id`,
      `select w.id from own_auth_webauthn_challenges w join own_auth_mfa_challenges m on m.id = w.mfa_challenge_id where m.user_id = ${receipt}.user_id`);
  const referenceArray = (sql: string) => pg
    ? `(select coalesce(jsonb_agg(id), '[]'::jsonb) from (${sql}) ids)`
    : `json((select json_group_array(id) from (${sql}) ids))`;
  const identities = pg
    ? `(select coalesce(jsonb_agg(jsonb_build_object('provider', provider, 'providerAccountId', provider_account_id)), '[]'::jsonb) from own_auth_accounts where user_id = ${receipt}.user_id)`
    : `json((select json_group_array(json_object('provider', provider, 'providerAccountId', provider_account_id)) from own_auth_accounts where user_id = ${receipt}.user_id))`;
  // D1 limits compound SELECT terms more strictly than standalone SQLite.
  // Every capture still runs in the same atomic batch as deletion.
  const groups = pg ? [ownedIds] : Array.from({ length: Math.ceil(ownedIds.length / 4) }, (_, index) => ownedIds.slice(index * 4, index * 4 + 4));
  const captures = groups.map((group) => {
    const captured = pg
      ? `subject || jsonb_build_object('references', ${referenceArray(`${references} union ${group.join(" union ")}`)}, 'identities', ${identities})`
      : `json_set(subject, '$.references', ${referenceArray(`${references} union ${group.join(" union ")}`)}, '$.identities', ${identities})`;
    return erasureStatement(db, `update ${receipt} set subject = ${captured} where ${receiptGuard()}`, [input.operationId]);
  });
  const statements = [insert, ...captures, ...changes];
  const auditObject = pg ? "jsonb_build_object('apiKeyId', a.api_key_id, 'organisationId', a.organisation_id)"
    : "json_object('apiKeyId', a.api_key_id, 'organisationId', a.organisation_id)";
  const auditMatch = `a.actor_user_id = ${receipt}.user_id or a.target_user_id = ${receipt}.user_id or ` +
    erasureSqlMatch(db.dialect, auditObject, `${receipt}.subject`);
  const auditMetadata = erasureSqlMatch(db.dialect, "a.metadata", `${receipt}.subject`);
  const auditIds = `${references} union select a.id from own_auth_audit_events a where ` + auditMatch +
    ` or ${auditMetadata}`;
  statements.push(erasureStatement(db, `update ${receipt} set subject = ` +
    (pg ? `jsonb_set(subject, '{references}', ${referenceArray(auditIds)})` : `json_set(subject, '$.references', ${referenceArray(auditIds)})`) +
    ` where ${receiptGuard()}`, [input.operationId]));
  const metadataMatch = (column: string) => `exists (select 1 from ${receipt} e where e.operation_id = ? and ${erasureSqlMatch(db.dialect, column, "e.subject")})`;
  statements.push(erasureStatement(db,
    `delete from own_auth_audit_events where ${metadataMatch(pg ? "jsonb_build_object('id', own_auth_audit_events.id)" : "json_object('id', own_auth_audit_events.id)")} and ${receiptGuard()}`,
    [input.operationId, input.operationId]));
  for (const table of ["webhook_events", "cloud_outbox"]) {
    statements.push(erasureStatement(db, `delete from own_auth_${table} where ${metadataMatch("payload")} and ${receiptGuard()}`, [input.operationId, input.operationId]));
  }
  statements.push(erasureStatement(db,
    `delete from own_auth_cloud_commands where (${metadataMatch("payload")} or ${metadataMatch("result")}) and ${receiptGuard()}`,
    [input.operationId, input.operationId, input.operationId]));
  const remove = (table: string, column: string, ids: readonly string[]) => {
    if (ids.length) statements.push(erasureStatement(db,
      `delete from own_auth_${table} where ${column} in (${ids.map(() => "?").join(",")}) and ${receiptGuard()}`,
      [...ids, input.operationId]));
  };
  // Contact matches apply only to records without another user's ownership.
  for (const table of ["tokens", "sms_otps"]) {
    const contact = table === "tokens" ? "((email is not null and lower(email) = ?) or phone = ?)" : "phone = ?";
    const contacts = table === "tokens" ? [user.email?.toLowerCase() ?? null, user.phone] : [user.phone];
    statements.push(erasureStatement(db, `delete from own_auth_${table} where user_id is null and ${contact} and ${receiptGuard()}`, [...contacts, input.operationId]));
  }
  statements.push(erasureStatement(db,
    "delete from own_auth_tokens where id in (select token_id from own_auth_invitations where (lower(email) = ? or phone = ?)) and " + receiptGuard(),
    [user.email?.toLowerCase() ?? null, user.phone, input.operationId]));
  statements.push(erasureStatement(db, "delete from own_auth_invitations where (lower(email) = ? or phone = ?) and " + receiptGuard(),
    [user.email?.toLowerCase() ?? null, user.phone, input.operationId]));
  statements.push(erasureStatement(db, "update own_auth_api_keys set revoked_by = null where revoked_by = ? and " + receiptGuard(), [user.id, input.operationId]));
  // Device requests use SET NULL, so delete them before their owning rows disappear.
  remove("device_authorizations", "user_id", [user.id]);
  remove("tokens", "organisation_id", removedOrganisations);
  remove("organisations", "id", removedOrganisations);
  remove("users", "id", [user.id]);
  for (const { event, entity, priority } of cloudWrites) {
    const entityId = entity.id;
    statements.push(erasureStatement(db,
      "insert into own_auth_cloud_entity_versions (entity_type, entity_id, version) select ?, ?, 1 where " + receiptGuard() +
      " on conflict (entity_type, entity_id) do update set version = own_auth_cloud_entity_versions.version + 1", [entity.type, entityId, input.operationId]));
    const payload = db.dialect === "postgres"
      ? "jsonb_set(?::jsonb, '{entityVersion}', to_jsonb(v.version))"
      : "json_set(?, '$.entityVersion', v.version)";
    statements.push(erasureStatement(db,
      `insert into own_auth_cloud_outbox (id, event_type, payload, entity_version, priority, created_at, next_retry_at) select ?, ?, ${payload}, v.version, ?, ?, ? from own_auth_cloud_entity_versions v where v.entity_type = ? and v.entity_id = ? and ${receiptGuard()}`,
      [event.id, event.type, JSON.stringify(event), db.dialect === "postgres" ? priority : Number(priority),
        date(new Date(input.now)), date(new Date(input.now)), entity.type, entityId, input.operationId]));
  }
  return statements;
}
