import { describe, expect, it } from "vitest";
import {
  InMemoryAuthStorage,
  createOwnAuth,
  createOwnAuthPluginContractFingerprint,
  defineOwnAuthPlugin,
  type OwnAuthPluginDefinition
} from "../src/index.js";

describe("plugin runtime", () => {
  it("shares the plugin IP budget across IPv6 addresses in the same network", async () => {
    const plugin = defineOwnAuthPlugin({
      id: "ip-budget",
      version: "1.0.0",
      rateLimits: [{ id: "requests", limit: 2, windowMs: 60_000, key: "ip" }],
      endpoints: [{
        id: "read",
        method: "GET",
        summary: "Read plugin data",
        output: { type: "string" },
        rateLimit: "requests",
        handler: () => "ok"
      }]
    });
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "plugin-ip-budget",
      plugins: [plugin]
    });
    const endpoint = auth.findPluginEndpoint("/plugins/ip-budget/read", "GET")!;
    const execute = (ipAddress: string) =>
      auth.executePluginEndpoint(endpoint, undefined, null, { ipAddress });

    await expect(execute("2001:db8:1:2::1")).resolves.toBe("ok");
    await expect(execute("2001:db8:1:2::2")).resolves.toBe("ok");
    await expect(execute("2001:db8:1:2::3")).rejects.toMatchObject({ code: "rate_limited" });
    await expect(execute("2001:db8:1:3::1")).resolves.toBe("ok");
  });

  it("runs direct SDK calls through immutable before-hooks and redacted after-hooks", async () => {
    let beforeInput: unknown;
    let afterResult: unknown;
    const plugin = defineOwnAuthPlugin({
      id: "hook-audit",
      version: "1.0.0",
      beforeHooks: [{
        id: "before-sign-in",
        operations: ["signInEmailPassword"],
        run(context) {
          beforeInput = context.input;
        }
      }],
      afterHooks: [{
        id: "after-sign-in",
        operations: ["signInEmailPassword"],
        run(context) {
          afterResult = context.result;
        }
      }]
    });
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "plugin-hooks",
      plugins: [plugin]
    });
    await auth.signUpEmailPassword({
      email: "plugin@example.com",
      password: "correct-horse"
    });
    await auth.signInEmailPassword({
      email: "plugin@example.com",
      password: "correct-horse"
    });

    expect(beforeInput).toMatchObject({ password: "correct-horse" });
    expect(afterResult).toMatchObject({ sessionToken: "[redacted]" });
    expect(Object.isFrozen(beforeInput)).toBe(true);
  });

  it("fails direct SDK operations closed when a before-hook denies them", async () => {
    const plugin = defineOwnAuthPlugin({
      id: "access-policy",
      version: "1.0.0",
      errors: ["blocked"],
      beforeHooks: [{
        id: "block-create-user",
        operations: ["createUser"],
        run: () => ({ allow: false, error: "blocked", message: "Creation is blocked" })
      }]
    });
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "plugin-deny",
      plugins: [plugin]
    });

    await expect(auth.createUser({ email: "blocked@example.com" })).rejects.toMatchObject({
      code: "plugin.access-policy.blocked"
    });
  });

  it("fails closed when a before-hook times out", async () => {
    const plugin = defineOwnAuthPlugin({
      id: "slow-policy",
      version: "1.0.0",
      beforeHooks: [{
        id: "never-finishes",
        operations: ["createUser"],
        run: () => new Promise<never>(() => undefined)
      }]
    });
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "plugin-timeout",
      plugins: [plugin],
      pluginRuntime: { beforeHookTimeoutMs: 1 }
    });

    await expect(auth.createUser({ email: "timeout@example.com" })).rejects.toMatchObject({
      code: "plugin_hook_timeout"
    });
  });

  it("reports after-hook failures without rolling back completed auth work", async () => {
    const reported: Array<{ hookId: string; operation: string }> = [];
    const plugin = defineOwnAuthPlugin({
      id: "after-reporting",
      version: "1.0.0",
      afterHooks: [{
        id: "broken-reporter",
        operations: ["signUpEmailPassword"],
        run() {
          throw new Error("reporting failed");
        }
      }]
    });
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "plugin-after-hook",
      plugins: [plugin],
      pluginRuntime: {
        onAfterHookError(_error, details) {
          reported.push({ hookId: details.hookId, operation: details.operation });
        }
      }
    });

    await expect(auth.signUpEmailPassword({
      email: "after-hook@example.com",
      password: "correct-horse"
    })).resolves.toMatchObject({ status: "complete" });
    await expect(auth.storage.getUserByEmail("after-hook@example.com")).resolves.not.toBeNull();
    expect(reported).toEqual([{
      hookId: "broken-reporter",
      operation: "signUpEmailPassword"
    }]);
  });

  it("changes the plugin fingerprint when an endpoint contract changes", () => {
    const first = contractPlugin({ type: "string" });
    const second = contractPlugin({ type: "number" });

    expect(createOwnAuthPluginContractFingerprint([first])).not.toBe(
      createOwnAuthPluginContractFingerprint([second])
    );
  });

  it("includes client method mappings in the plugin fingerprint", () => {
    const first = mappedContractPlugin("read");
    const second = mappedContractPlugin("write");

    expect(createOwnAuthPluginContractFingerprint([first])).not.toBe(
      createOwnAuthPluginContractFingerprint([second])
    );
  });

  it.each([
    ["method", { method: "DELETE" }],
    ["session", { session: "create" }],
    ["handler", { handler: undefined }],
    ["input schema", { input: { type: "array", items: { type: "date" } } }],
    ["output schema", { output: { type: "object", properties: { ok: { oneOf: [] } } } }]
  ])("rejects an invalid plugin endpoint %s", (_label, override) => {
    const endpoint = {
      id: "read",
      method: "GET",
      summary: "Read plugin data",
      output: { type: "string" },
      handler: () => "ok",
      ...override
    };

    expect(() => defineOwnAuthPlugin({
      id: "invalid-contract",
      version: "1.0.0",
      endpoints: [endpoint]
    } as unknown as OwnAuthPluginDefinition)).toThrow();
  });

  it("isolates runtime behavior and fingerprints from caller mutation", async () => {
    const endpoint = {
      id: "read",
      method: "GET" as const,
      summary: "Read plugin data",
      output: {
        type: "object",
        properties: { value: { const: "original" } },
        required: ["value"],
        additionalProperties: false
      },
      handler: () => ({ value: "original" })
    };
    const plugin: OwnAuthPluginDefinition = {
      id: "runtime-owned",
      version: "1.0.0",
      clientMethods: { read: { endpoint: "read" } },
      endpoints: [endpoint]
    };
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      tokenPepper: "runtime-owned-plugin",
      plugins: [plugin]
    });
    const fingerprint = auth.pluginContractFingerprint;

    endpoint.handler = () => ({ value: "changed" });
    endpoint.output.properties.value.const = "changed";
    plugin.version = "2.0.0";
    const registered = auth.findPluginEndpoint("/plugins/runtime-owned/read", "GET");

    expect(registered).not.toBeNull();
    await expect(auth.executePluginEndpoint(registered!, undefined, null, {})).resolves.toEqual({
      value: "original"
    });
    expect(auth.pluginContractFingerprint).toBe(fingerprint);
    expect(createOwnAuthPluginContractFingerprint(auth.plugins)).toBe(fingerprint);
    expect(auth.plugins[0]).not.toBe(plugin);
    expect(Object.isFrozen(auth.plugins)).toBe(true);
    expect(Object.isFrozen(auth.plugins[0]?.endpoints?.[0]?.output)).toBe(true);
  });

  it("clones __proto__ as data without changing configuration prototypes", () => {
    const properties = JSON.parse(
      '{"__proto__":{"type":"string"}}'
    ) as Record<string, Record<string, unknown>>;
    const plugin = defineOwnAuthPlugin({
      id: "safe-clone",
      version: "1.0.0",
      endpoints: [{
        id: "read",
        method: "GET",
        summary: "Read plugin data",
        output: { type: "object", properties, additionalProperties: false },
        handler: () => ({ "__proto__": "safe" })
      }]
    });
    const clonedProperties = plugin.endpoints[0]?.output.properties as Record<string, unknown>;

    expect(Object.getPrototypeOf(clonedProperties)).toBe(Object.prototype);
    expect(Object.prototype.hasOwnProperty.call(clonedProperties, "__proto__")).toBe(true);
    expect(clonedProperties.__proto__).toEqual({ type: "string" });
  });
});

function contractPlugin(output: Record<string, unknown>) {
  return defineOwnAuthPlugin({
    id: "contract",
    version: "1.0.0",
    endpoints: [{
      id: "read",
      method: "GET",
      path: "/read",
      summary: "Read plugin data",
      output,
      handler: () => "ok"
    }]
  });
}

function mappedContractPlugin(endpoint: "read" | "write") {
  return defineOwnAuthPlugin({
    id: "mapped-contract",
    version: "1.0.0",
    clientMethods: { inspect: { endpoint } },
    endpoints: ["read", "write"].map((id) => ({
      id,
      method: "GET" as const,
      summary: `${id} plugin data`,
      output: { type: "string" },
      handler: () => id
    }))
  });
}
