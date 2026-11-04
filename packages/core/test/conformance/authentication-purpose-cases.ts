import { createOwnAuth, MemoryEmailProvider } from "../../src/index.js";
import type { AtomicAdapterCase, AtomicAdapterHarness } from "./atomic-adapter-cases.js";
import { assertConformanceEqual } from "./conformance-assertions.js";
import { createConformanceGoogleProvider } from "./conformance-oauth-provider.js";
import { uniqueConformanceEmail } from "./conformance-values.js";

const tokenPepper = "authentication-purpose-conformance";

export const authenticationPurposeAdapterCases: readonly AtomicAdapterCase[] = [
  {
    name: "shares an OAuth start budget across IPv6 address variants and engines",
    async run(harness) {
      const { auth } = await fixture(harness);
      const second = createOwnAuth({ storage: harness.storage[1], rateLimitStore: harness.rateLimits[1],
        tokenPepper, oauth: { adapters: [createConformanceGoogleProvider()] } });
      for (let index = 0; index < 20; index += 1) {
        await (index % 2 ? second : auth).createOAuthAuthorizationUrl({ provider: "google",
          request: { ipAddress: `2001:db8:abcd:12::${(index + 1).toString(16)}` } });
      }
      await rejectsToken(second.createOAuthAuthorizationUrl({ provider: "google",
        request: { ipAddress: "2001:0DB8:ABCD:0012:0:0:0:FFFF" } }), "rate_limited");
      await auth.createOAuthAuthorizationUrl({ provider: "google",
        request: { ipAddress: "2001:db8:abcd:13::1" } });
    }
  }
];

async function fixture({ storage, rateLimits }: AtomicAdapterHarness) {
  let exchanges = 0;
  const provider = createConformanceGoogleProvider();
  const exchange = provider.exchangeCode.bind(provider);
  provider.exchangeCode = async (input) => { exchanges += 1; return exchange(input); };
  const auth = createOwnAuth({
    storage: storage[0], rateLimitStore: rateLimits[0],
    tokenPepper, exposeRawTokens: true,
    emailProvider: new MemoryEmailProvider(), oauth: { adapters: [provider] },
    password: { hasher: {
      hash: async (password) => `fixture:${password}`,
      verify: async (password, hash) => hash === `fixture:${password}`,
      needsRehash: () => false
    } }
  });
  const email = uniqueConformanceEmail("purpose");
  const user = await auth.createUser({ email });
  await storage[0].updateUser(user.id, { emailVerifiedAt: new Date() });
  return { auth, storage: storage[0], email, user, providerCalls: () => exchanges };
}

async function rejectsToken(result: Promise<unknown>, code = "invalid_token") {
  try { await result; } catch (error) {
    assertConformanceEqual((error as { code?: string }).code, code, "rejected authentication proof");
    return;
  }
  throw new Error("Authentication accepted a proof for an invalid purpose or lifecycle state");
}
