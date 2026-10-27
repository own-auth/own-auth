import { accountColumns, auditEventColumns, organisationMemberColumns, userColumns } from "../database-schema.js";
import { mapSamlConnection, mapSamlTransaction } from "../saml-database-mappers.js";
import {
  samlConnectionColumns,
  samlConnectionReturning,
  samlTransactionColumns,
  samlTransactionReturning
} from "../saml-database-schema.js";
import type { ConsumeSamlResponseInput, SamlIdentityCommit, SamlStorage } from "../saml-storage.js";
import type { SamlConnection, SamlTransaction } from "../saml-types.js";
import type { DatabaseRow } from "../database-types.js";
import { D1StorageBase } from "./d1-storage-base.js";
import type { D1DatabaseLike } from "./d1-types.js";
import { AuthError } from "../errors.js";

export class D1SamlStorage extends D1StorageBase implements SamlStorage {
  constructor(db: D1DatabaseLike) { super(db); }

  async createConnection(connection: SamlConnection): Promise<SamlConnection> {
    return mapSamlConnection(await this.insertOne(
      "own_auth_saml_connections", samlConnectionColumns, connection, samlConnectionReturning
    ));
  }

  async getConnectionById(id: string): Promise<SamlConnection | null> {
    const row = await this.selectOne(
      `${samlConnectionReturning} from own_auth_saml_connections where id = ?1`, [id]
    );
    return row ? mapSamlConnection(row) : null;
  }

  async listConnectionsByOrganisationId(organisationId: string): Promise<SamlConnection[]> {
    const rows = await this.selectMany(
      `${samlConnectionReturning} from own_auth_saml_connections ` +
      "where organisation_id = ?1 order by created_at asc",
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
      "own_auth_saml_connections", samlConnectionColumns, id, safePatch, samlConnectionReturning
    );
    return row ? mapSamlConnection(row) : null;
  }

  async createTransaction(transaction: SamlTransaction): Promise<SamlTransaction> {
    return mapSamlTransaction(await this.insertOne(
      "own_auth_saml_transactions", samlTransactionColumns, transaction, samlTransactionReturning
    ));
  }

  async getTransactionByRelayStateHash(relayStateHash: string): Promise<SamlTransaction | null> {
    const row = await this.selectOne(
      `${samlTransactionReturning} from own_auth_saml_transactions where relay_state_hash = ?1`,
      [relayStateHash]
    );
    return row ? mapSamlTransaction(row) : null;
  }

  async consumeResponse(input: ConsumeSamlResponseInput): Promise<SamlTransaction | null> {
    const insertReplay = this.prepare(
      `insert into own_auth_saml_assertion_replays
         (assertion_hash, connection_id, consumed_at, expires_at)
       select ?1, ?2, ?3, ?4
       where exists (
         select 1 from own_auth_saml_transactions
         where relay_state_hash = ?5 and request_id_hash = ?6
           and consumed_at is null and expires_at > ?3
       )
       returning assertion_hash`,
      [
        input.assertion.assertionHash,
        input.assertion.connectionId,
        input.consumedAt,
        input.assertion.expiresAt,
        input.relayStateHash,
        input.requestIdHash
      ]
    );
    const consume = this.prepare(
      `update own_auth_saml_transactions set consumed_at = ?3
       where relay_state_hash = ?1 and request_id_hash = ?2
         and consumed_at is null and expires_at > ?3
       returning ${samlTransactionReturning}`,
      [input.relayStateHash, input.requestIdHash, input.consumedAt]
    );
    let results;
    try {
      results = await this.db.batch<DatabaseRow>([insertReplay, consume]);
    } catch (error) {
      if (isAssertionReplayConflict(error)) return null;
      throw error;
    }
    const row = results[1]?.results?.[0];
    return row ? mapSamlTransaction(row) : null;
  }

  async commitIdentity(input: SamlIdentityCommit): Promise<void> {
    const statements = [];
    if (input.user) {
      statements.push(this.insertStatement("own_auth_users", userColumns, input.user, "id", input.authorityExpiresAt));
    }
    if (input.account) {
      statements.push(this.insertStatement("own_auth_accounts", accountColumns, input.account, "id", input.authorityExpiresAt));
    }
    if (input.membership) {
      statements.push(this.insertStatement(
        "own_auth_organisation_members", organisationMemberColumns, input.membership, "id", input.authorityExpiresAt
      ));
    }
    for (const event of input.auditEvents) {
      statements.push(this.insertStatement("own_auth_audit_events", auditEventColumns, event, "id", input.authorityExpiresAt));
    }
    if (statements.length > 0) {
      const results = await this.db.batch(statements);
      if (input.authorityExpiresAt && !results[0]?.results?.length) {
        throw new AuthError("saml_transaction_invalid", "SAML request is invalid or expired", 400);
      }
    }
  }

  async cleanup(expiredBefore: Date): Promise<{ transactions: number; assertions: number }> {
    const results = await this.db.batch<DatabaseRow>([
      this.prepare(
        "delete from own_auth_saml_transactions where expires_at <= ?1 returning id",
        [expiredBefore]
      ),
      this.prepare(
        "delete from own_auth_saml_assertion_replays where expires_at <= ?1 returning assertion_hash",
        [expiredBefore]
      )
    ]);
    return {
      transactions: results[0]?.results?.length ?? 0,
      assertions: results[1]?.results?.length ?? 0
    };
  }
}

function isAssertionReplayConflict(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return message.includes("UNIQUE constraint failed") &&
    message.includes("own_auth_saml_assertion_replays.assertion_hash");
}
