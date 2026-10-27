import { cloneStored, findStored, updateStoredEntity } from "./memory-storage-helpers.js";
import type { ConsumeSamlResponseInput, SamlIdentityCommit, SamlStorage } from "./saml-storage.js";
import type { SamlAssertionReplay, SamlConnection, SamlTransaction } from "./saml-types.js";
import type { Account, AuditEvent, OrganisationMember, User } from "./types.js";
import { assertIdentityAuthority } from "./identity-authority.js";

interface MemorySamlRecords {
  users: Map<string, User>;
  accounts: Map<string, Account>;
  members: Map<string, OrganisationMember<string>>;
  auditEvents: Map<string, AuditEvent>;
}

export class MemorySamlStorage implements SamlStorage {
  /** @internal */
  erasureMaps(): Map<string, any>[] { return [this.connections, this.transactions, this.assertions]; }
  private readonly connections = new Map<string, SamlConnection>();
  private readonly transactions = new Map<string, SamlTransaction>();
  private readonly assertions = new Map<string, SamlAssertionReplay>();

  constructor(private readonly records: MemorySamlRecords) {}

  async createConnection(connection: SamlConnection): Promise<SamlConnection> {
    if ([...this.connections.values()].some((candidate) =>
      candidate.key === connection.key ||
      (candidate.organisationId === connection.organisationId &&
       candidate.idpEntityId === connection.idpEntityId)
    )) {
      throw new Error("SAML connection already exists");
    }
    this.connections.set(connection.id, cloneStored(connection));
    return cloneStored(connection);
  }

  async getConnectionById(id: string): Promise<SamlConnection | null> {
    const connection = this.connections.get(id);
    return connection ? cloneStored(connection) : null;
  }

  async listConnectionsByOrganisationId(organisationId: string): Promise<SamlConnection[]> {
    return [...this.connections.values()]
      .filter((connection) => connection.organisationId === organisationId)
      .sort((left, right) => left.createdAt.getTime() - right.createdAt.getTime())
      .map(cloneStored);
  }

  async updateConnection(
    id: string,
    patch: Partial<SamlConnection>
  ): Promise<SamlConnection | null> {
    const {
      id: _id,
      organisationId: _organisationId,
      key: _key,
      idpEntityId: _idpEntityId,
      ...safePatch
    } = patch;
    return updateStoredEntity(this.connections, id, safePatch);
  }

  async createTransaction(transaction: SamlTransaction): Promise<SamlTransaction> {
    if ([...this.transactions.values()].some((candidate) =>
      candidate.requestIdHash === transaction.requestIdHash ||
      candidate.relayStateHash === transaction.relayStateHash
    )) {
      throw new Error("SAML transaction already exists");
    }
    this.transactions.set(transaction.id, cloneStored(transaction));
    return cloneStored(transaction);
  }

  async getTransactionByRelayStateHash(relayStateHash: string): Promise<SamlTransaction | null> {
    return findStored(
      this.transactions,
      (transaction) => transaction.relayStateHash === relayStateHash
    );
  }

  async consumeResponse(input: ConsumeSamlResponseInput): Promise<SamlTransaction | null> {
    const transaction = [...this.transactions.values()].find((candidate) =>
      candidate.relayStateHash === input.relayStateHash &&
      candidate.requestIdHash === input.requestIdHash &&
      !candidate.consumedAt &&
      candidate.expiresAt > input.consumedAt
    );
    if (!transaction || this.assertions.has(input.assertion.assertionHash)) return null;
    const consumed = updateStoredEntity(this.transactions, transaction.id, {
      consumedAt: input.consumedAt
    });
    this.assertions.set(input.assertion.assertionHash, cloneStored(input.assertion));
    return consumed;
  }

  async commitIdentity(input: SamlIdentityCommit): Promise<void> {
    assertIdentityAuthority(input.authorityExpiresAt);
    validateIdentityCommit(this.records, input);
    if (input.user) this.records.users.set(input.user.id, cloneStored(input.user));
    if (input.account) this.records.accounts.set(input.account.id, cloneStored(input.account));
    if (input.membership) {
      this.records.members.set(input.membership.id, cloneStored(input.membership));
    }
    for (const event of input.auditEvents) {
      this.records.auditEvents.set(event.id, cloneStored(event));
    }
  }

  async cleanup(expiredBefore: Date): Promise<{ transactions: number; assertions: number }> {
    const transactions = deleteExpired(this.transactions, expiredBefore);
    const assertions = deleteExpired(this.assertions, expiredBefore);
    return { transactions, assertions };
  }
}

function validateIdentityCommit(records: MemorySamlRecords, input: SamlIdentityCommit): void {
  if (input.user && [...records.users.values()].some((user) =>
    user.id === input.user?.id ||
    Boolean(user.email && input.user?.email && user.email === input.user.email) ||
    Boolean(user.phone && input.user?.phone && user.phone === input.user.phone)
  )) {
    throw new Error("SAML user already exists");
  }
  if (input.account && [...records.accounts.values()].some((account) =>
    account.id === input.account?.id ||
    (account.provider === input.account?.provider &&
     account.providerAccountId === input.account.providerAccountId)
  )) {
    throw new Error("SAML account already exists");
  }
  if (input.membership && [...records.members.values()].some((member) =>
    member.id === input.membership?.id ||
    (member.organisationId === input.membership?.organisationId &&
     member.userId === input.membership.userId)
  )) {
    throw new Error("SAML membership already exists");
  }
  if (input.auditEvents.some((event) => records.auditEvents.has(event.id))) {
    throw new Error("SAML audit event already exists");
  }
}

function deleteExpired<Entity extends { expiresAt: Date }>(
  records: Map<string, Entity>,
  expiredBefore: Date
): number {
  let deleted = 0;
  for (const [id, record] of records) {
    if (record.expiresAt <= expiredBefore) {
      records.delete(id);
      deleted += 1;
    }
  }
  return deleted;
}
