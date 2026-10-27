import type { OwnAuthEndpointDefinition } from "./contract-types.js";
import { objectSchema, stringSchema } from "./contract-schemas.js";

const result = objectSchema({
  operationId: stringSchema(), status: { enum: ["pending", "complete"] },
  local: { enum: ["pending", "complete"] }, cloud: { enum: ["not_configured", "pending", "complete"] },
  pendingLocalStores: { type: "array", items: stringSchema() }
}, ["operationId", "status", "local", "cloud", "pendingLocalStores"]);
const organisation = { anyOf: [
  objectSchema({ organisationId: stringSchema(), action: { const: "transfer" }, newOwnerUserId: stringSchema() },
    ["organisationId", "action", "newOwnerUserId"]),
  objectSchema({ organisationId: stringSchema(), action: { const: "delete" }, confirmation: { const: "delete_organisation" } },
    ["organisationId", "action", "confirmation"])
] };
const common = { operationId: stringSchema(), organisations: { type: "array", items: organisation } } as const;
const errors = ["validation_error", "invalid_session", "permission_denied", "rate_limited",
  "reauthentication_required", "user_erasure_unsupported", "user_erasure_ownership_required",
  "erasure_operation_conflict", "erasure_operation_closed", "erasure_operation_not_found", "user_not_found"] as const;

export const userErasureEndpoints = {
  eraseUser: {
    method: "POST", path: "/user/erase", summary: "Permanently erase your Own Auth account",
    request: objectSchema({ ...common, confirmation: { const: "erase" } }, ["operationId", "confirmation"]),
    response: result, errors, session: "required", pendingResponse: true
  },
  adminEraseUser: {
    method: "POST", path: "/admin/user/erase", summary: "Permanently erase an authorized user account",
    request: objectSchema({ ...common, userId: stringSchema(), reason: stringSchema() }, ["operationId", "userId", "reason"]),
    response: result, errors, session: "required", feature: "administration", pendingResponse: true
  },
  adminGetUserErasure: {
    method: "GET", path: "/admin/user-erasure", summary: "Inspect an authorized erasure operation",
    request: objectSchema({ operationId: stringSchema() }, ["operationId"]), requestTransport: "query",
    response: result, errors, session: "required", feature: "administration", pendingResponse: true
  },
  adminResumeUserErasure: {
    method: "POST", path: "/admin/user-erasure/resume", summary: "Resume an authorized erasure operation",
    request: objectSchema({ operationId: stringSchema() }, ["operationId"]),
    response: result, errors, session: "required", feature: "administration", pendingResponse: true
  }
} as const satisfies Record<string, Omit<OwnAuthEndpointDefinition, "id">>;
