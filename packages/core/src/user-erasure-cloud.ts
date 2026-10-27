import { createCloudEvent } from "./cloud-events.js";
import type { CloudEvent, CloudEventEntity } from "./cloud-types.js";

interface OwnershipTransfer { organisationId: string; name: string; ownerUserId: string; newOwnerUserId: string }
export interface ErasureCloudWrite { event: CloudEvent; entity: CloudEventEntity; priority: boolean }

/** Use the existing event protocol and outbox for every organisation decision. */
export function erasureCloudWrites(
  deletion: CloudEvent | null, deletedOrganisations: readonly string[],
  transfers: readonly OwnershipTransfer[], now: number
): ErasureCloudWrite[] {
  if (!deletion) return [];
  const at = new Date(now);
  const writes: ErasureCloudWrite[] = [{ event: deletion,
    entity: { type: "user", id: String(deletion.data.userId) }, priority: true }];
  for (const id of deletedOrganisations) writes.push({
    event: createCloudEvent(deletion.appId, { type: "org.deleted", data: { orgId: id } }, at),
    entity: { type: "org", id }, priority: true
  });
  for (const transfer of transfers) {
    const entity = { type: "org" as const, id: transfer.organisationId };
    writes.push({ entity, priority: false, event: createCloudEvent(deletion.appId, {
      type: "org.updated", data: { orgId: entity.id, name: transfer.name, ownerId: transfer.ownerUserId }
    }, at) });
    writes.push({ entity, priority: false, event: createCloudEvent(deletion.appId, {
      type: "org.member.added", data: { orgId: entity.id, userId: transfer.newOwnerUserId, role: "owner" }
    }, at) });
  }
  return writes;
}
