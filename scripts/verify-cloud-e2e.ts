import { createHash } from "node:crypto";

import { createOwnAuth, InMemoryAuthStorage } from "../packages/core/src/index.js";
import { cloud } from "../packages/core/src/cloud.js";

const endpoint = required("OWN_AUTH_CLOUD_E2E_ENDPOINT").replace(/\/$/, "");
const cloudKey = required("OWN_AUTH_CLOUD_E2E_KEY");
const managementKey = required("OWN_AUTH_CLOUD_E2E_MANAGEMENT_KEY");
const appId = required("OWN_AUTH_CLOUD_E2E_APP_ID");
const recipient = required("OWN_AUTH_CLOUD_E2E_RECIPIENT");
const applicationUrl = required("OWN_AUTH_CLOUD_E2E_APPLICATION_URL");
const unique = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
const email = recipient;
const storage = new InMemoryAuthStorage();
const auth = createOwnAuth({
  storage,
  baseUrl: applicationUrl,
  tokenPepper: `cloud-e2e-${crypto.randomUUID()}-${crypto.randomUUID()}`,
  plugins: [cloud({ key: cloudKey, endpoint, flushMode: "manual" })]
});

let userId: string | null = null;
try {
  const signup = await auth.signUpEmailPassword({
    email,
    password: `Cloud-e2e-${crypto.randomUUID()}`,
    name: `Cloud E2E ${unique}`
  });
  userId = signup.user.id;
  const cleared = await auth.cloud.clearOutbox();
  if (cleared < 1) throw new Error("CLOUD_E2E_BACKFILL_PRECONDITION_FAILED");
  const backfill = await auth.cloud.backfill({ batchSize: 100 });
  if (!backfill.complete || backfill.sent < 1) {
    throw new Error("CLOUD_E2E_BACKFILL_FAILED");
  }
  await waitForCloudUser(userId, email);

  const delivery = await auth.requestMagicLink({ email });
  if (delivery.delivery.status === "failed") {
    throw new Error(`CLOUD_E2E_DELIVERY_FAILED:${delivery.delivery.reason}`);
  }
  assertFlush(await auth.cloud.flushOutbox({ limit: 500 }));
  await waitForDeliveryLog();
  await verifySecurityEndpoint(userId);
  await auth.cloud.eraseUser(userId);
  await waitForCloudUserErasure(userId);
  userId = null;

  console.info(JSON.stringify({
    ok: true,
    checks: [
      "backfill",
      "user_projection",
      "event_ingestion",
      "email_delivery",
      "security_parallelism",
      "user_erasure"
    ]
  }));
} finally {
  if (userId) {
    await auth.cloud.eraseUser(userId).catch(() => undefined);
    await managementRequest(`/users/${encodeURIComponent(userId)}/data`, {
      method: "DELETE"
    }).catch(() => undefined);
  }
  await auth.close();
}

async function waitForCloudUser(userId: string, expectedEmail: string): Promise<void> {
  await eventually(async () => {
    const response = await managementRequest(
      `/users/${encodeURIComponent(userId)}?appId=${encodeURIComponent(appId)}`
    );
    if (response.status === 404) return false;
    assertOk(response, "CLOUD_E2E_USER_LOOKUP_FAILED");
    const body = await response.json() as { user?: { email?: string; id?: string } };
    return body.user?.id === userId && body.user.email === expectedEmail;
  }, "CLOUD_E2E_USER_PROJECTION_TIMEOUT");
}

async function waitForCloudUserErasure(userId: string): Promise<void> {
  await eventually(async () => {
    const response = await managementRequest(
      `/users/${encodeURIComponent(userId)}?appId=${encodeURIComponent(appId)}`
    );
    if (response.status === 404) return true;
    assertOk(response, "CLOUD_E2E_USER_ERASURE_LOOKUP_FAILED");
    return false;
  }, "CLOUD_E2E_USER_ERASURE_TIMEOUT");
}

async function waitForDeliveryLog(): Promise<void> {
  await eventually(async () => {
    const response = await managementRequest(
      `/delivery/logs?appId=${encodeURIComponent(appId)}&channel=email&limit=25`
    );
    assertOk(response, "CLOUD_E2E_DELIVERY_LOG_FAILED");
    const body = await response.json() as {
      logs?: Array<{ recipient?: string; status?: string }>;
    };
    return Boolean(body.logs?.some((entry) =>
      entry.recipient === email && ["queued", "sent", "failed", "bounced"].includes(entry.status ?? "")
    ));
  }, "CLOUD_E2E_DELIVERY_LOG_TIMEOUT");
}

async function verifySecurityEndpoint(userId: string): Promise<void> {
  const wireAppId = cloudWireAppId(cloudKey);
  const calls = Array.from({ length: 20 }, (_, index) =>
    fetch(`${endpoint}/security/check`, {
      method: "POST",
      headers: cloudHeaders(cloudKey),
      body: JSON.stringify({
        action: "login",
        appId: wireAppId,
        ip: "198.51.100.24",
        userAgent: "Own Auth Cloud E2E",
        userId: `${userId}-${index}`,
        config: { botDetection: { enabled: false } }
      })
    })
  );
  const responses = await Promise.all(calls);
  for (const response of responses) {
    assertOk(response, "CLOUD_E2E_SECURITY_CHECK_FAILED");
    const body = await response.json() as { decision?: string };
    if (!body.decision || !["allow", "challenge", "deny"].includes(body.decision)) {
      throw new Error("CLOUD_E2E_SECURITY_DECISION_INVALID");
    }
  }
}

function managementRequest(path: string, init: RequestInit = {}) {
  const url = new URL(path, `${endpoint}/`);
  if (!url.searchParams.has("appId")) url.searchParams.set("appId", appId);
  return fetch(url, {
    ...init,
    headers: { ...cloudHeaders(managementKey), ...init.headers }
  });
}

function cloudHeaders(key: string): Record<string, string> {
  return {
    authorization: `Bearer ${key}`,
    "content-type": "application/json"
  };
}

async function eventually(
  check: () => Promise<boolean>,
  failure: string
): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (await check()) return;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(failure);
}

function assertFlush(result: { failed: number; remaining: number }): void {
  if (result.failed || result.remaining) {
    throw new Error(`CLOUD_E2E_OUTBOX_NOT_EMPTY:${result.failed}:${result.remaining}`);
  }
}

function assertOk(response: Response, code: string): void {
  if (!response.ok) throw new Error(`${code}:${response.status}`);
}

function cloudWireAppId(key: string): string {
  return `app_${createHash("sha256").update(key).digest("hex").slice(0, 24)}`;
}

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required.`);
  return value;
}
