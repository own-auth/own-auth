import { createOwnAuth, MemoryEmailProvider } from "../../src/index.js";
import { createOAuthBrowserBinding } from "../../src/oauth-derivation.js";
import { hashSecret } from "../../src/crypto.js";
import type { AtomicAdapterCase, AtomicAdapterHarness } from "./atomic-adapter-cases.js";
import { assertConformanceEqual, requireCompleteResult } from "./conformance-assertions.js";
import { createConformanceGoogleProvider } from "./conformance-oauth-provider.js";
import { uniqueConformanceEmail } from "./conformance-values.js";

const emailPurposes = ["magic_link", "email_verification", "password_reset"] as const;
type EmailPurpose = typeof emailPurposes[number];
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
  },
  ...emailPurposes.map((purpose): AtomicAdapterCase => ({
    name: `rejects a ${purpose} token for every other email purpose and session lookup`,
    async run(harness) {
      const { auth, storage, email, user } = await fixture(harness);
      const issued = purpose === "magic_link"
        ? await auth.requestMagicLink({ email })
        : purpose === "email_verification"
          ? await auth.requestEmailVerification({ email })
          : await auth.requestPasswordReset({ email });
      if (!issued.token) throw new Error("Expected a delivery token");
      for (const other of emailPurposes) {
        if (other === purpose) continue;
        await rejectsToken(verify(auth, other, issued.token));
        assertConformanceEqual(await storage.consumeToken(hashSecret(issued.token, tokenPepper), other, new Date()),
          null, "atomic storage consumption also requires the issued purpose");
      }
      assertConformanceEqual(await auth.getCurrentSession(issued.token), null,
        "email tokens cannot authenticate a session");
      assertConformanceEqual((await storage.getUserById(user.id))?.passwordHash, null,
        "using a token for another purpose cannot install a password");
      assertConformanceEqual((await storage.listSessionsByUserId(user.id)).length, 0,
        "using a token for another purpose cannot issue a session");
      if (purpose === "magic_link") {
        const signedIn = requireCompleteResult(await auth.verifyMagicLink({ token: issued.token }), "magic link");
        for (const other of emailPurposes) await rejectsToken(verify(auth, other, signedIn.sessionToken));
        assertConformanceEqual((await auth.getCurrentSession(signedIn.sessionToken))?.user.id, user.id,
          "rejected email attempts preserve the legitimate session");
      } else {
        await verify(auth, purpose, issued.token);
      }
      await rejectsToken(verify(auth, purpose, issued.token), "token_already_used");
    }
  })),
  {
    name: "rejects OAuth state as email authority without consuming the real OAuth transaction",
    async run(harness) {
      const { auth, storage, user, providerCalls } = await fixture(harness);
      const started = await auth.createOAuthAuthorizationUrl({ provider: "google" });
      for (const purpose of emailPurposes) await rejectsToken(verify(auth, purpose, started.state));
      assertConformanceEqual(await auth.getCurrentSession(started.state), null,
        "OAuth state cannot authenticate a session");
      assertConformanceEqual((await storage.listSessionsByUserId(user.id)).length, 0,
        "OAuth state cannot create an email session");
      assertConformanceEqual(providerCalls(), 0, "email verification cannot invoke a provider");
      requireCompleteResult(await auth.completeOAuthSignIn({
        provider: "google", browserBindingToken: started.browserBindingToken,
        callbackParameters: new URLSearchParams({ state: started.state, code: "synthetic-code" })
      }), "original OAuth transaction");
      assertConformanceEqual(providerCalls(), 1, "only the real callback exchanges a code");
    }
  },
  {
    name: "rejects self consistent browser proof and state that the server never issued",
    async run(harness) {
      const { auth, providerCalls } = await fixture(harness);
      const forged = createOAuthBrowserBinding();
      await rejectsToken(auth.completeOAuthSignIn({
        provider: "google", browserBindingToken: forged.browserBindingToken,
        callbackParameters: new URLSearchParams({ state: forged.state, code: "synthetic-code" })
      }), "oauth_transaction_invalid");
      assertConformanceEqual(providerCalls(), 0, "unissued state cannot reach the provider");
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

function verify(auth: ReturnType<typeof createOwnAuth>, purpose: EmailPurpose, token: string) {
  if (purpose === "magic_link") return auth.verifyMagicLink({ token });
  if (purpose === "email_verification") return auth.verifyEmail({ token });
  return auth.resetPassword({ token, newPassword: "replacement-password" });
}

async function rejectsToken(result: Promise<unknown>, code = "invalid_token") {
  try { await result; } catch (error) {
    assertConformanceEqual((error as { code?: string }).code, code, "rejected authentication proof");
    return;
  }
  throw new Error("Authentication accepted a proof for an invalid purpose or lifecycle state");
}
