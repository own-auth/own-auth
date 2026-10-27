import type { AuthStorage } from "./storage.js";
import type {
  Account,
  AuditEvent,
  OrganisationMember,
  User
} from "./types.js";
import type {
  SamlAssertionReplay,
  SamlConnection,
  SamlTransaction
} from "./saml-types.js";

export interface ConsumeSamlResponseInput {
  relayStateHash: string;
  requestIdHash: string;
  assertion: SamlAssertionReplay;
  consumedAt: Date;
}

export interface SamlIdentityCommit {
  authorityExpiresAt?: Date;
  user?: User;
  account?: Account;
  membership?: OrganisationMember<string>;
  auditEvents: readonly AuditEvent[];
}

export interface SamlStorage {
  createConnection(connection: SamlConnection): Promise<SamlConnection>;
  getConnectionById(id: string): Promise<SamlConnection | null>;
  listConnectionsByOrganisationId(organisationId: string): Promise<SamlConnection[]>;
  updateConnection(
    id: string,
    patch: Partial<SamlConnection>
  ): Promise<SamlConnection | null>;
  createTransaction(transaction: SamlTransaction): Promise<SamlTransaction>;
  getTransactionByRelayStateHash(relayStateHash: string): Promise<SamlTransaction | null>;
  consumeResponse(input: ConsumeSamlResponseInput): Promise<SamlTransaction | null>;
  commitIdentity(input: SamlIdentityCommit): Promise<void>;
  cleanup(expiredBefore: Date): Promise<{ transactions: number; assertions: number }>;
}

export interface SamlCapableStorage extends AuthStorage {
  readonly samlStorage: SamlStorage;
}

export function isSamlCapableStorage(storage: AuthStorage): storage is SamlCapableStorage {
  const candidate = (storage as Partial<SamlCapableStorage>).samlStorage;
  return Boolean(candidate) && [
    "createConnection",
    "getConnectionById",
    "listConnectionsByOrganisationId",
    "updateConnection",
    "createTransaction",
    "getTransactionByRelayStateHash",
    "consumeResponse",
    "commitIdentity",
    "cleanup"
  ].every((method) => typeof candidate?.[method as keyof SamlStorage] === "function");
}
