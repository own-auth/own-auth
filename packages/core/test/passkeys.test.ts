import { beforeEach, describe, expect, it, vi } from "vitest";

const webAuthn = vi.hoisted(() => ({
  registrationChallenge: "registration-challenge",
  authenticationChallenge: "authentication-challenge",
  discoverable: true
}));

vi.mock("@simplewebauthn/server", () => ({
  async generateRegistrationOptions() {
    return { challenge: webAuthn.registrationChallenge };
  },
  async verifyRegistrationResponse() {
    return {
      verified: true,
      registrationInfo: {
        credential: {
          id: "credential-one",
          publicKey: new Uint8Array([1, 2, 3]),
          counter: 0,
          transports: ["internal"]
        },
        credentialDeviceType: "multiDevice",
        credentialBackedUp: true,
        userVerified: true,
        aaguid: "aaguid-one"
      }
    };
  },
  async generateAuthenticationOptions() {
    return { challenge: webAuthn.authenticationChallenge };
  },
  async verifyAuthenticationResponse() {
    return {
      verified: true,
      authenticationInfo: { userVerified: true, newCounter: 0 }
    };
  }
}));

import {
  InMemoryAuthStorage,
  MemoryEmailProvider,
  MemorySmsProvider,
  createOwnAuth,
  type OAuthProviderAdapter
} from "../src/index.js";
import {
  createTotpCode,
  requireCompleteSignIn,
  requireMfaSignIn
} from "./identity-test-helpers.js";

describe("passkeys", () => {
  beforeEach(() => {
    webAuthn.registrationChallenge = "registration-challenge";
    webAuthn.authenticationChallenge = "authentication-challenge";
    webAuthn.discoverable = true;
  });

  it("uses one credential path for registration, primary sign-in, and MFA", async () => {
    const auth = createPasskeyAuth();
    const signup = requireCompleteSignIn(await auth.signUpEmailPassword({
      email: "passkey@example.com",
      password: "correct-horse"
    }));
    const registration = await auth.beginPasskeyRegistration({
      sessionToken: signup.sessionToken
    });
    expect(registration.options.challenge).toBe("registration-challenge");

    const credential = await auth.completePasskeyRegistration({
      sessionToken: signup.sessionToken,
      response: registrationResponse("credential-one", "registration-challenge", true),
      name: "Laptop"
    });
    expect(credential).toMatchObject({
      name: "Laptop",
      discoverable: true,
      deviceType: "multiDevice"
    });

    await auth.signOut(signup.sessionToken);
    await auth.beginPasskeyAuthentication();
    const primary = await auth.completePasskeyAuthentication({
      response: authenticationResponse("credential-one", "authentication-challenge")
    });
    expect(primary.session).toMatchObject({
      assuranceLevel: "aal2",
      authenticationMethods: ["passkey"]
    });

    const enrollment = await auth.beginTotpEnrollment({
      sessionToken: primary.sessionToken
    });
    await auth.confirmTotpEnrollment({
      sessionToken: primary.sessionToken,
      factorId: enrollment.factorId,
      code: createTotpCode(enrollment.secret)
    });
    await auth.signOut(primary.sessionToken);
    const password = await auth.signInEmailPassword({
      email: "passkey@example.com",
      password: "correct-horse"
    });
    const challenge = requireMfaSignIn(password);
    expect(challenge.methods).toContain("passkey");

    webAuthn.authenticationChallenge = "mfa-passkey-challenge";
    await auth.beginPasskeyAuthentication({ mfaChallengeToken: challenge.challengeToken });
    const elevated = await auth.completePasskeyAuthentication({
      response: authenticationResponse("credential-one", "mfa-passkey-challenge")
    });
    expect(elevated.session).toMatchObject({
      assuranceLevel: "aal2",
      authenticationMethods: ["password", "passkey"]
    });
  });

  it("completes every supported first-factor challenge through the shared passkey path", async () => {
    const emailProvider = new MemoryEmailProvider();
    const smsProvider = new MemorySmsProvider();
    const auth = createOwnAuth({
      storage: new InMemoryAuthStorage(),
      emailProvider,
      smsProvider,
      tokenPepper: "passkey-cross-flow",
      oauth: { adapters: [crossFlowGoogleProvider()] },
      passkeys: {
        rpId: "example.com",
        rpName: "Example",
        origins: ["https://example.com"]
      }
    });
    const signup = await auth.signUpEmailPassword({
      email: "passkey-cross-flow@example.com",
      password: "correct-horse"
    });
    await auth.requestSmsOtp({
      phone: "+14155550199",
      purpose: "phone_verification",
      userId: signup.user.id
    });
    await auth.verifySmsOtp({
      phone: "+14155550199",
      purpose: "phone_verification",
      code: smsProvider.messages.at(-1)?.code ?? ""
    });
    await auth.linkOAuthProvider({
      actorUserId: signup.user.id,
      provider: "google",
      providerAccountId: "google-passkey-cross-flow",
      email: signup.user.email ?? undefined,
      emailVerified: true
    });
    await auth.beginPasskeyRegistration({ sessionToken: signup.sessionToken });
    await auth.completePasskeyRegistration({
      sessionToken: signup.sessionToken,
      response: registrationResponse("credential-one", "registration-challenge", true)
    });
    await auth.signOut(signup.sessionToken);

    await completePasskeyChallenge(auth, await auth.signInEmailPassword({
      email: "passkey-cross-flow@example.com",
      password: "correct-horse"
    }), "password", "password-passkey-challenge");

    await auth.requestMagicLink({ email: "passkey-cross-flow@example.com" });
    await completePasskeyChallenge(auth, await auth.verifyMagicLink({
      token: emailProvider.messages.at(-1)?.token ?? ""
    }), "magic_link", "magic-passkey-challenge");

    await auth.requestSmsOtp({ phone: "+14155550199" });
    await completePasskeyChallenge(auth, await auth.verifySmsOtp({
      phone: "+14155550199",
      code: smsProvider.messages.at(-1)?.code ?? ""
    }), "phone", "sms-passkey-challenge");

    await completePasskeyChallenge(auth, await auth.signInWithVerifiedExternalIdentity({
      provider: "google",
      providerAccountId: "google-passkey-cross-flow"
    }), "google", "trusted-passkey-challenge");

    const authorization = await auth.createOAuthAuthorizationUrl({ provider: "google" });
    await completePasskeyChallenge(auth, await auth.completeOAuthSignIn({
      provider: "google",
      browserBindingToken: authorization.browserBindingToken,
      callbackParameters: new URLSearchParams({
        state: new URL(authorization.url).searchParams.get("state") ?? "",
        code: "provider-code"
      })
    }), "google", "oauth-passkey-challenge");

    const oneTap = await auth.prepareGoogleOneTap();
    await completePasskeyChallenge(auth, await auth.signInWithGoogleOneTap({
      credential: "google-credential",
      nonce: oneTap.nonce
    }), "google", "one-tap-passkey-challenge");
  });

  it("consumes WebAuthn challenges before verification can be replayed", async () => {
    const auth = createPasskeyAuth();
    const signup = requireCompleteSignIn(await auth.signUpEmailPassword({
      email: "passkey-replay@example.com",
      password: "correct-horse"
    }));
    await auth.beginPasskeyRegistration({ sessionToken: signup.sessionToken });
    const response = registrationResponse(
      "credential-one",
      "registration-challenge",
      true
    );

    await auth.completePasskeyRegistration({
      sessionToken: signup.sessionToken,
      response
    });
    await expect(auth.completePasskeyRegistration({
      sessionToken: signup.sessionToken,
      response
    })).rejects.toMatchObject({ code: "passkey_invalid" });
  });

  it("does not let one WebAuthn credential belong to multiple users", async () => {
    const auth = createPasskeyAuth();
    const first = requireCompleteSignIn(await auth.signUpEmailPassword({
      email: "first-passkey-owner@example.com",
      password: "correct-horse"
    }));
    await auth.beginPasskeyRegistration({ sessionToken: first.sessionToken });
    await auth.completePasskeyRegistration({
      sessionToken: first.sessionToken,
      response: registrationResponse(
        "credential-one",
        "registration-challenge",
        true
      )
    });

    const second = requireCompleteSignIn(await auth.signUpEmailPassword({
      email: "second-passkey-owner@example.com",
      password: "correct-horse"
    }));
    webAuthn.registrationChallenge = "second-registration-challenge";
    await auth.beginPasskeyRegistration({ sessionToken: second.sessionToken });
    await expect(auth.completePasskeyRegistration({
      sessionToken: second.sessionToken,
      response: registrationResponse(
        "credential-one",
        "second-registration-challenge",
        true
      )
    })).rejects.toMatchObject({ code: "passkey_invalid" });

    await expect(auth.listPasskeys({ sessionToken: first.sessionToken }))
      .resolves.toHaveLength(1);
    await expect(auth.listPasskeys({ sessionToken: second.sessionToken }))
      .resolves.toHaveLength(0);
  });

  it("requires username-first authentication for non-discoverable credentials", async () => {
    const storage = new InMemoryAuthStorage();
    const auth = createPasskeyAuth(storage);
    const signup = requireCompleteSignIn(await auth.signUpEmailPassword({
      email: "hardware-key@example.com",
      password: "correct-horse"
    }));
    const now = new Date();
    await storage.createPasskeyCredential({
      id: "psk_hardware",
      userId: signup.user.id,
      credentialId: "credential-hardware",
      publicKey: new Uint8Array([1, 2, 3]),
      counter: 0,
      transports: ["usb"],
      deviceType: "multiDevice",
      backedUp: false,
      discoverable: false,
      name: "Hardware key",
      metadata: {},
      createdAt: now,
      updatedAt: now,
      lastUsedAt: null
    });

    await auth.beginPasskeyAuthentication();
    await expect(auth.completePasskeyAuthentication({
      response: authenticationResponse(
        "credential-hardware",
        "authentication-challenge"
      )
    })).rejects.toMatchObject({ code: "passkey_invalid" });

    webAuthn.authenticationChallenge = "username-first-challenge";
    await auth.beginPasskeyAuthentication({ userId: signup.user.id });
    await expect(auth.completePasskeyAuthentication({
      response: authenticationResponse("credential-hardware", "username-first-challenge")
    })).resolves.toMatchObject({ status: "complete" });
  });

  it("fails closed when a passkey is removed during zero-counter authentication", async () => {
    const storage = new InMemoryAuthStorage();
    const auth = createPasskeyAuth(storage);
    const signup = requireCompleteSignIn(await auth.signUpEmailPassword({
      email: "passkey-removal-race@example.com",
      password: "correct-horse"
    }));
    await auth.beginPasskeyRegistration({ sessionToken: signup.sessionToken });
    await auth.completePasskeyRegistration({
      sessionToken: signup.sessionToken,
      response: registrationResponse(
        "credential-one",
        "registration-challenge",
        true
      )
    });
    await auth.signOut(signup.sessionToken);
    await auth.beginPasskeyAuthentication();
    vi.spyOn(storage, "updatePasskeyCredential").mockResolvedValueOnce(null);

    await expect(auth.completePasskeyAuthentication({
      response: authenticationResponse(
        "credential-one",
        "authentication-challenge"
      )
    })).rejects.toMatchObject({ code: "passkey_invalid" });
  });

  it("lists, renames, and revokes only the current user's passkeys", async () => {
    const auth = createPasskeyAuth();
    const signup = requireCompleteSignIn(await auth.signUpEmailPassword({
      email: "passkey-management@example.com",
      password: "correct-horse"
    }));
    await auth.beginPasskeyRegistration({ sessionToken: signup.sessionToken });
    const passkey = await auth.completePasskeyRegistration({
      sessionToken: signup.sessionToken,
      response: registrationResponse("credential-one", "registration-challenge", true)
    });

    await expect(auth.listPasskeys({ sessionToken: signup.sessionToken })).resolves.toHaveLength(1);
    await expect(auth.renamePasskey({
      sessionToken: signup.sessionToken,
      passkeyId: passkey.id,
      name: "Phone"
    })).resolves.toMatchObject({ name: "Phone" });
    await auth.revokePasskey({
      sessionToken: signup.sessionToken,
      passkeyId: passkey.id
    });
    await expect(auth.listPasskeys({ sessionToken: signup.sessionToken })).resolves.toEqual([]);
  });

  it("does not count TOTP as a primary method when revoking the last passkey", async () => {
    const storage = new InMemoryAuthStorage();
    const auth = createPasskeyAuth(storage);
    const signup = requireCompleteSignIn(await auth.signUpEmailPassword({
      email: "totp-is-not-primary@example.com",
      password: "correct-horse"
    }));
    await auth.beginPasskeyRegistration({ sessionToken: signup.sessionToken });
    const passkey = await auth.completePasskeyRegistration({
      sessionToken: signup.sessionToken,
      response: registrationResponse("credential-one", "registration-challenge", true)
    });
    await storage.updateUser(signup.user.id, { email: null, passwordHash: null });
    const now = new Date();
    await storage.createTotpFactor({
      id: "totp_only_second_factor",
      userId: signup.user.id,
      status: "active",
      ciphertext: "ciphertext",
      nonce: "nonce",
      encryptionKeyId: "current",
      lastUsedTimestep: null,
      createdAt: now,
      updatedAt: now,
      disabledAt: null
    });

    await expect(auth.revokePasskey({
      sessionToken: signup.sessionToken,
      passkeyId: passkey.id
    })).rejects.toMatchObject({ code: "authentication_method_required" });
  });
});

function createPasskeyAuth(storage = new InMemoryAuthStorage()) {
  return createOwnAuth({
    storage,
    tokenPepper: "passkey-test-pepper",
    encryption: {
      current: { id: "current", key: new Uint8Array(32).fill(5) }
    },
    passkeys: {
      rpId: "example.com",
      rpName: "Example",
      origins: ["https://example.com"]
    }
  });
}

function registrationResponse(id: string, challenge: string, discoverable: boolean) {
  return {
    id,
    rawId: id,
    type: "public-key" as const,
    response: {
      clientDataJSON: clientData(challenge),
      attestationObject: "attestation"
    },
    clientExtensionResults: { credProps: { rk: discoverable } },
    authenticatorAttachment: "platform" as const
  };
}

function authenticationResponse(id: string, challenge: string) {
  return {
    id,
    rawId: id,
    type: "public-key" as const,
    response: {
      clientDataJSON: clientData(challenge),
      authenticatorData: "authenticator-data",
      signature: "signature",
      userHandle: null
    },
    clientExtensionResults: {},
    authenticatorAttachment: "platform" as const
  };
}

function clientData(challenge: string): string {
  return Buffer.from(JSON.stringify({ challenge })).toString("base64url");
}

async function completePasskeyChallenge(
  auth: ReturnType<typeof createOwnAuth>,
  firstFactor: { status: string; challengeToken?: string },
  expectedFirstFactor: string,
  challenge: string
): Promise<void> {
  expect(firstFactor.status).toBe("mfa_required");
  if (!firstFactor.challengeToken) throw new Error("Expected an MFA challenge token");
  webAuthn.authenticationChallenge = challenge;
  await auth.beginPasskeyAuthentication({
    mfaChallengeToken: firstFactor.challengeToken
  });
  const completed = await auth.completePasskeyAuthentication({
    response: authenticationResponse("credential-one", challenge)
  });
  expect(completed.session).toMatchObject({
    assuranceLevel: "aal2",
    authenticationMethods: [expectedFirstFactor, "passkey"]
  });
  await auth.signOut(completed.sessionToken);
}

function crossFlowGoogleProvider(): OAuthProviderAdapter {
  const identity = {
    provider: "google" as const,
    providerAccountId: "google-passkey-cross-flow",
    email: "passkey-cross-flow@example.com",
    emailVerified: true,
    name: null,
    imageUrl: null
  };
  return {
    provider: "google",
    redirectUri: "https://api.example.com/api/auth/oauth/google/callback",
    offlineAccess: false,
    async createAuthorizationUrl(input) {
      const url = new URL("https://accounts.example.test/authorize");
      url.searchParams.set("state", input.state);
      return url;
    },
    async exchangeCode() {
      return { identity, refreshToken: null, scopes: [] };
    },
    async verifyCredential() {
      return identity;
    }
  };
}
