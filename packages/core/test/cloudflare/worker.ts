import type { D1DatabaseLike } from "../../dist/d1/index.js";
import {
  conformanceErrorResponse,
  handleAuthRpc,
  handleAuthorizationStorageRpc,
  handleCloseLifecycle,
  handleDeviceAuthorizationStorageRpc,
  handleDpopCrypto,
  handleSamlEngineQualification,
  handleWebhookFlow,
  handleInspection,
  handleRateLimitRpc,
  handleSamlStorageRpc,
  handleSchemaInspection,
  handleStorageRpc,
  handleWebhookVerification
} from "./worker-conformance.js";
import {
  handleScimEngineQualification,
  handleScimStorageRpc
} from "./worker-scim-conformance.js";

interface Env {
  DB: D1DatabaseLike;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (request.method !== "POST") return new Response("Not found", { status: 404 });

    try {
      switch (path) {
        case "/conformance/auth":
          return await handleAuthRpc(request, env.DB);
        case "/conformance/authorization-storage":
          return await handleAuthorizationStorageRpc(request, env.DB);
        case "/conformance/device-authorization-storage":
          return await handleDeviceAuthorizationStorageRpc(request, env.DB);
        case "/conformance/storage":
          return await handleStorageRpc(request, env.DB);
        case "/conformance/rate-limit":
          return await handleRateLimitRpc(request, env.DB);
        case "/conformance/saml-storage":
          return await handleSamlStorageRpc(request, env.DB);
        case "/conformance/scim-storage":
          return await handleScimStorageRpc(request, env.DB);
        case "/conformance/inspect":
          return await handleInspection(request, env.DB);
        case "/conformance/schema":
          return await handleSchemaInspection(env.DB);
        case "/conformance/close":
          return await handleCloseLifecycle(env.DB);
        case "/conformance/dpop-crypto":
          return await handleDpopCrypto();
        case "/conformance/saml-engine":
          return await handleSamlEngineQualification();
        case "/conformance/scim-engine":
          return await handleScimEngineQualification(env.DB);
        case "/conformance/webhook-verifier":
          return await handleWebhookVerification(request);
        case "/conformance/webhook-flow":
          return await handleWebhookFlow(env.DB);
        default:
          return new Response("Not found", { status: 404 });
      }
    } catch (error) {
      return conformanceErrorResponse(error);
    }
  }
};
