import { auditEventColumns } from "../database-schema.js";
import { mapSamlConnection, mapSamlTransaction } from "../saml-database-mappers.js";
import {
  samlConnectionColumns,
  samlConnectionReturning,
  samlTransactionColumns,
  samlTransactionReturning
} from "../saml-database-schema.js";
import type {
  ConsumeSamlResponseInput,
  SamlIdentityCommit,
  SamlStorage
} from "../saml-storage.js";
import type { SamlConnection, SamlTransaction } from "../saml-types.js";
import { accountColumns, organisationMemberColumns, userColumns } from "../database-schema.js";
import { addInsertCte } from "./postgres-atomic.js";
import { PostgresStorageBase } from "./postgres-storage-base.js";
import { AuthError } from "../errors.js";
import type { PostgresQueryable, Row } from "./postgres-types.js";

export class PostgresSamlStorage extends PostgresStorageBase implements SamlStorage {
  constructor(db: PostgresQueryable) { super(db); }

  async createConnection(connection: SamlConnection): Promise<SamlConnection> {
    return mapSamlConnection(await this.insertOne(
      "own_auth_saml_connections",
      samlConnectionColumns,
      connection,
      samlConnectionReturning
    ));
  }

  async getConnectionById(id: string): Promise<SamlConnection | null> {
    const row = await this.selectOne(
      `${samlConnectionReturning} from own_auth_saml_connections where id = $1`,
      [id]
    );
    return row ? mapSamlConnection(row) : null;
  }

  async listConnectionsByOrganisationId(organisationId: string): Promise<SamlConnection[]> {
    const rows = await this.selectMany(
      `${samlConnectionReturning} from own_auth_saml_connections ` +
      "where organisation_id = $1 order by created_at asc",
      [organisationId]
    );
    return rows.map(mapSamlConnection);
  }

  async updateConnection(
    id: string,
    patch: Partial<SamlConnection>
  ): Promise<SamlConnection | null> {
    const safePatch = { ...patch, id: undefined, organisationId: undefined, key: undefined, idpEntityId: undefined };
    const row = await this.updateOne(
      "own_auth_saml_connections",
      samlConnectionColumns,
      id,
      safePatch,
      samlConnectionReturning
    );
    return row ? mapSamlConnection(row) : null;
  }

  async createTransaction(transaction: SamlTransaction): Promise<SamlTransaction> {
    return mapSamlTransaction(await this.insertOne(
      "own_auth_saml_transactions",
      samlTransactionColumns,
      transaction,
      samlTransactionReturning
    ));
  }

  async getTransactionByRelayStateHash(relayStateHash: string): Promise<SamlTransaction | null> {
    const row = await this.selectOne(
      `${samlTransactionReturning} from own_auth_saml_transactions where relay_state_hash = $1`,
      [relayStateHash]
    );
    return row ? mapSamlTransaction(row) : null;
  }

  async consumeResponse(input: ConsumeSamlResponseInput): Promise<SamlTransaction | null> {
    const result = await this.db.query<Row>(
      `with consumed as (
         update own_auth_saml_transactions
         set consumed_at = $3
         where relay_state_hash = $1 and request_id_hash = $2
           and consumed_at is null and expires_at > $3
         returning ${samlTransactionReturning}
       ), claimed as (
         insert into own_auth_saml_assertion_replays
           (assertion_hash, connection_id, consumed_at, expires_at)
         select $4, $5, $3, $6 from consumed
         on conflict (assertion_hash) do nothing
         returning assertion_hash
       )
       select ${samlTransactionReturning} from consumed cross join claimed`,
      [
        input.relayStateHash,
        input.requestIdHash,
        input.consumedAt,
        input.assertion.assertionHash,
        input.assertion.connectionId,
        input.assertion.expiresAt
      ]
    );
    return result.rows[0] ? mapSamlTransaction(result.rows[0]) : null;
  }

  async commitIdentity(input: SamlIdentityCommit): Promise<void> {
    const params: unknown[] = [];
    const ctes: string[] = [];
    let dependency: string | undefined;
    if (input.user) {
      dependency = addInsertCte(ctes, params, "saml_user", "own_auth_users", userColumns, input.user, undefined, input.authorityExpiresAt);
    }
    if (input.account) {
      dependency = addInsertCte(
        ctes, params, "saml_account", "own_auth_accounts", accountColumns, input.account, dependency, input.authorityExpiresAt
      );
    }
    if (input.membership) {
      dependency = addInsertCte(
        ctes, params, "saml_member", "own_auth_organisation_members",
        organisationMemberColumns, input.membership, dependency, input.authorityExpiresAt
      );
    }
    input.auditEvents.forEach((event, index) => {
      dependency = addInsertCte(
        ctes, params, `saml_audit_${index}`, "own_auth_audit_events",
        auditEventColumns, event, dependency, input.authorityExpiresAt
      );
    });
    if (ctes.length > 0) {
      const result = await this.db.query(`with ${ctes.join(", ")} select 1 from ${dependency}`, params);
      if (input.authorityExpiresAt && !result.rows.length) throw new AuthError("saml_transaction_invalid", "SAML request is invalid or expired", 400);
    }
  }

  async cleanup(expiredBefore: Date): Promise<{ transactions: number; assertions: number }> {
    const result = await this.db.query<{ kind: string }>(
      `with deleted_transactions as (
         delete from own_auth_saml_transactions where expires_at <= $1 returning 'transaction' as kind
       ), deleted_assertions as (
         delete from own_auth_saml_assertion_replays where expires_at <= $1 returning 'assertion' as kind
       )
       select kind from deleted_transactions union all select kind from deleted_assertions`,
      [expiredBefore]
    );
    return {
      transactions: result.rows.filter((row) => row.kind === "transaction").length,
      assertions: result.rows.filter((row) => row.kind === "assertion").length
    };
  }
}
