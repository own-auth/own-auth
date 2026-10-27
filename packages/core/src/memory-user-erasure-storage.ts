import { AuthError } from "./errors.js";
import { matchesErasureIdentity, matchesErasureSubject } from "./user-erasure-subject.js";
import type { Account, Organisation, OrganisationMember, Session, User } from "./types.js";
import type { AtomicUserErasureInput, StoredUserErasure, UserErasureStorage, UserErasureSubject } from "./user-erasure.js";
import { cloudErasureSubject, isUserErasureProtected, requireResumableUserErasure } from "./user-erasure.js";
import type { CloudOutboxRecord } from "./cloud-storage.js";
import { erasureCloudWrites } from "./user-erasure-cloud.js";

export type ErasureMemoryMap = Map<string, any>;
export interface MemoryErasureRecords {
  users: Map<string, User>;
  accounts: Map<string, Account>;
  sessions: Map<string, Session>;
  organisations: Map<string, Organisation>;
  members: Map<string, OrganisationMember<string>>;
  maps: readonly ErasureMemoryMap[];
  cloudOutbox: Map<string, CloudOutboxRecord>;
  cloudVersions: Map<string, number>;
  webhookDeliveries: ErasureMemoryMap;
}

export class MemoryUserErasureStorage implements UserErasureStorage {
  private readonly operations = new Map<string, StoredUserErasure>();

  constructor(private readonly records: MemoryErasureRecords) {
    for (const map of records.maps) {
      const set = map.set.bind(map);
      map.set = (key, value) => {
        if (map === records.cloudOutbox && ["user.deleted", "org.deleted"].includes(value?.event?.type)) { set(key, value); return map; }
        const externalCloudActor = value?.event?.type === "audit.entry" &&
          (value?.event?.data?.metadata?.source === "cloud" || value?.event?.data?.metadata?.reason === "cloud_command");
        if (map === records.cloudOutbox &&
          [value?.event?.data?.userId, value?.event?.data?.recipientUserId, externalCloudActor ? null : value?.event?.meta?.userId]
            .some((id) => typeof id === "string" && !records.users.has(id))) {
          throw new AuthError("invalid_credentials", "Authentication request is no longer valid", 401);
        }
        if (value && typeof value === "object") {
          if (value.payloadHash && value.payload?.userId && !records.users.has(value.payload.userId)) {
            throw new AuthError("invalid_credentials", "Authentication request is no longer valid", 401);
          }
          // Audit actors can belong to the Cloud dashboard rather than the local user store.
          for (const field of ["userId", "targetUserId"]) {
            if (value[field] && !records.users.has(value[field])) throw new AuthError("invalid_credentials", "Authentication request is no longer valid", 401);
          }
          if (value.eventType && value.actorUserId && !records.users.has(value.actorUserId) &&
            value.metadata?.source !== "cloud" && value.metadata?.reason !== "cloud_command") {
            throw new AuthError("invalid_credentials", "Authentication request is no longer valid", 401);
          }
        }
        for (const record of this.operations.values()) {
          if (!isUserErasureProtected(record)) continue;
          if (value?.userId && value.userId !== record.subject.userId) {
            if (!record.subject.identities.some((identity) => identity.provider === value.provider && identity.providerAccountId === value.providerAccountId)) continue;
          }
          const personal = map === records.users || value?.keyHash && !value.userId ? { ...value, metadata: undefined } : value;
          if (record.subject.references.includes(key) ||
            matchesErasureSubject(personal, record.subject) || matchesErasureIdentity(personal ?? {}, record.subject)) {
            throw new AuthError("invalid_credentials", "Authentication request is no longer valid", 401);
          }
        }
        set(key, value);
        return map;
      };
    }
  }

  async eraseAtomically(input: AtomicUserErasureInput): Promise<StoredUserErasure> {
    const prior = this.operations.get(input.operationId);
    if (prior) return structuredClone(requireResumableUserErasure(prior, input.userId));
    const joined = [...this.operations.values()].find((op) => op.subject?.userId === input.userId);
    if (joined) return structuredClone(joined);
    const user = this.records.users.get(input.userId);
    if (!user) throw new AuthError("user_not_found", "User not found", 404);
    if (user.updatedAt.getTime() !== input.expectedUpdatedAt.getTime()) throw new AuthError("erasure_operation_conflict", "The account changed. Retry erasure.", 409);
    if (input.sessionTokenHash) {
      const activeMfa = this.records.maps.some((map) => [...map.values()].some((value) =>
        value?.userId === user.id && (value.status === "active" && typeof value.ciphertext === "string" || value.publicKey instanceof Uint8Array)));
      const session = [...this.records.sessions.values()].find((s) => s.tokenHash === input.sessionTokenHash && s.userId === user.id);
      if (user.disabledAt || !session || session.revokedAt || session.expiresAt.getTime() <= input.now ||
        session.idleExpiresAt.getTime() <= input.now || !Number.isFinite(session.authenticatedAt.getTime()) ||
        session.authenticatedAt.getTime() > input.now || session.authenticatedAt < input.authenticatedAfter! ||
        ((input.requireMfa || activeMfa) && session.assuranceLevel !== "aal2")) {
        throw new AuthError("reauthentication_required", "Sign in again before erasing this account", 401);
      }
    }
    const subject: UserErasureSubject = {
      userId: user.id, email: user.email, phone: user.phone, references: [user.id],
      identities: [...this.records.accounts.values()].filter((a) => a.userId === user.id)
        .map(({ provider, providerAccountId }) => ({ provider, providerAccountId }))
    };
    const resolutions = new Map(input.organisations.map((r) => [r.organisationId, r]));
    if (resolutions.size !== input.organisations.length) throw new AuthError("validation_error", "Duplicate organisation resolution", 400);
    const replacements: { organisation: Organisation; member: OrganisationMember<string> }[] = [];
    const removedOrgs = new Set<string>();
    const unresolved: string[] = [];
    const owned = [...this.records.organisations.values()].filter((org) => org.ownerUserId === user.id ||
      [...this.records.members.values()].some((m) => m.organisationId === org.id && m.userId === user.id && m.role === "owner" && m.status === "active"));
    if ([...resolutions.keys()].some((id) => !owned.some((o) => o.id === id))) throw new AuthError("validation_error", "Choose an owned organisation", 400);
    for (const organisation of owned) {
      const resolution = resolutions.get(organisation.id);
      if (resolution?.action === "delete") {
        if (resolution.confirmation !== "delete_organisation") throw new AuthError("validation_error", "Confirm organisation deletion", 400);
        removedOrgs.add(organisation.id);
        continue;
      }
      const member = [...this.records.members.values()].find((m) => m.organisationId === organisation.id &&
        m.userId !== user.id && m.status === "active" && !this.records.users.get(m.userId)?.disabledAt &&
        this.records.users.has(m.userId) && (resolution?.action === "transfer" ? m.userId === resolution.newOwnerUserId : m.role === "owner"));
      if (!member) { unresolved.push(organisation.id); continue; }
      replacements.push({ organisation, member });
    }
    if (unresolved.length) throw new AuthError("user_erasure_ownership_required", "Choose another owner or confirm organisation deletion", 409, { organisationIds: unresolved });
    subject.references.push(...removedOrgs);
    // Find the full dependency closure before changing any map.
    const removed = new Map<ErasureMemoryMap, Set<string>>();
    let changed = true;
    while (changed) {
      changed = false;
      for (const map of this.records.maps) for (const [id, value] of map) {
        if (removed.get(map)?.has(id)) continue;
        if (map === this.records.users && id !== user.id) continue;
        if (map === this.records.organisations && !removedOrgs.has(id)) continue;
        if (value && value.userId && value.userId !== user.id &&
          !(removedOrgs.has(value.organisationId) ||
            [value.grantId, value.accountId, value.connectionId, value.sessionId]
              .some((reference) => reference && subject.references.includes(reference)))) continue;
        const isInvitationToSomeoneElse = value && typeof value === "object" && "invitedByUserId" in value &&
          !(subject.email && value.email?.toLowerCase() === subject.email.toLowerCase()) &&
          !(subject.phone && value.phone === subject.phone) && !removedOrgs.has(value.organisationId);
        if (isInvitationToSomeoneElse) continue;
        const isSharedKey = value && typeof value === "object" && "keyHash" in value && !value.userId && !removedOrgs.has(value.organisationId);
        if (isSharedKey) continue;
        if (matchesErasureSubject(value, subject) || subject.references.includes(id)) {
          const ids = removed.get(map) ?? new Set<string>();
          ids.add(id); removed.set(map, ids);
          if (!subject.references.includes(id)) { subject.references.push(id); changed = true; }
        }
      }
    }
    let protectedUntil = input.protectedUntil;
    for (const map of this.records.maps) for (const value of map.values()) {
      if (value?.userId === null && value.expiresAt instanceof Date &&
        (value.stateHash || value.relayStateHash ||
          ((value.tokenHash && value.type || value.codeHash && value.phone) && matchesErasureSubject(value, subject)))) {
        protectedUntil = Math.max(protectedUntil, value.expiresAt.getTime());
      }
    }
    const snapshots = [...new Set<ErasureMemoryMap>([...this.records.maps, this.records.cloudVersions, this.operations])]
      .map((map) => ({ map, entries: [...map.entries()] }));
    try {
      for (const { organisation, member } of replacements) {
        this.records.members.set(member.id, { ...member, role: "owner" });
        if (organisation.ownerUserId === user.id) this.records.organisations.set(organisation.id, { ...organisation, ownerUserId: member.userId });
      }
      for (const map of this.records.maps) for (const [id, value] of map) {
        if (removed.get(map)?.has(id)) continue;
        if (value && typeof value === "object" && value.invitedByUserId === user.id) map.set(id, { ...value, invitedByUserId: null });
        if (value && typeof value === "object" && value.revokedBy === user.id) map.set(id, { ...value, revokedBy: null });
      }
      for (const [map, ids] of removed) for (const id of ids) map.delete(id);
      const cloudWrites = erasureCloudWrites(input.cloudEvent, [...removedOrgs], replacements.map(({ organisation, member }) => ({
        organisationId: organisation.id, name: organisation.name,
        ownerUserId: organisation.ownerUserId === user.id ? member.userId : organisation.ownerUserId, newOwnerUserId: member.userId
      })), input.now);
      const record: StoredUserErasure = {
        operationId: input.operationId, subject, pendingStores: [...input.pendingStores],
        protectedUntil, cloudEventId: input.cloudEvent?.id ?? null,
        pendingCloudEvents: cloudWrites.filter((write) => write.priority).map((write) => write.event.id),
        cloudComplete: false, createdAt: input.now, completedAt: null
      };
      for (const { event, entity, priority } of cloudWrites) {
        const key = `${entity.type}:${entity.id}`;
        const version = (this.records.cloudVersions.get(key) ?? 0) + 1;
        this.records.cloudVersions.set(key, version);
        const at = new Date(input.now);
        this.records.cloudOutbox.set(event.id, {
          id: event.id, event: { ...structuredClone(event), entityVersion: version },
          priority, createdAt: at, sentAt: null, ackAt: null, attempts: 0,
          nextRetryAt: at, leaseUntil: null
        });
      }
      this.operations.set(record.operationId, structuredClone(record));
      return structuredClone(record);
    } catch (error) {
      for (const { map, entries } of snapshots) {
        map.clear();
        for (const [key, value] of entries) Map.prototype.set.call(map, key, value);
      }
      throw error;
    }
  }

  async get(operationId: string): Promise<StoredUserErasure | null> {
    return structuredClone(this.operations.get(operationId) ?? null);
  }
  async findByUser(userId: string): Promise<StoredUserErasure | null> {
    return structuredClone([...this.operations.values()].find((op) => op.subject?.userId === userId) ?? null);
  }
  async settleStore(operationId: string, store: string): Promise<void> {
    const op = this.operations.get(operationId);
    if (op) op.pendingStores = op.pendingStores.filter((id) => id !== store);
  }
  async settleCloud(eventId: string): Promise<void> {
    const op = [...this.operations.values()].find((r) => r.cloudEventId === eventId || r.pendingCloudEvents.includes(eventId));
    if (op) {
      op.pendingCloudEvents = op.pendingCloudEvents.filter((id) => id !== eventId);
      op.cloudComplete = op.pendingCloudEvents.length === 0;
      this.records.cloudOutbox.delete(eventId);
    }
  }
  async isCloudErasure(eventId: string): Promise<boolean> {
    return [...this.operations.values()].some((r) => r.cloudEventId === eventId || r.pendingCloudEvents.includes(eventId));
  }
  async finish(operationId: string, now: number): Promise<StoredUserErasure | null> {
    const op = this.operations.get(operationId);
    if (op?.subject && !op.pendingStores.length && op.protectedUntil <= now) {
      for (const id of op.subject.references) for (const key of this.records.cloudVersions.keys()) {
        if (key.endsWith(`:${id}`)) this.records.cloudVersions.delete(key);
      }
      if (!op.cloudEventId || op.cloudComplete) { op.subject = null; op.completedAt = now; }
      else op.subject = cloudErasureSubject(op.subject.userId);
    }
    return this.get(operationId);
  }
  async assertIdentityAllowed(identity: Parameters<UserErasureStorage["assertIdentityAllowed"]>[0]): Promise<void> {
    for (const op of this.operations.values()) if (isUserErasureProtected(op) && matchesErasureIdentity(identity, op.subject)) {
      throw new AuthError("invalid_credentials", "Authentication request is no longer valid", 401);
    }
  }
  async authorizeWebhookSend(deliveryId: string, leaseToken: string): Promise<boolean> {
    const delivery = this.records.webhookDeliveries.get(deliveryId);
    if (!delivery || delivery.leaseToken !== leaseToken || delivery.status !== "processing") return false;
    delivery.sendStartedAt = new Date();
    return true;
  }
}
