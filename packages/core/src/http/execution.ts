import type { OwnAuth } from "../auth-engine.js";
import { AuthError } from "../errors.js";
import type { RequestContext } from "../types.js";
import type { UserErasureResult } from "../user-erasure.js";
import type {
  MfaRequiredResult,
  OAuthCompletionResult,
  SessionResult,
  SignInResult
} from "../auth-engine-types.js";
import { completeSamlResponse } from "../saml-internals.js";
import type { SamlCompletionResult } from "../saml-types.js";
import type {
  AuthSessionPayload,
  OwnAuthEndpointId,
  OwnAuthEndpointInputMap,
  OwnAuthEndpointOutputMap,
  SignInPayload
} from "./contract.js";
import {
  serializeAdministrationAuditEvent,
  serializeAdministrationSession,
  serializeAdministrationUser,
  serializeAuthSession,
  serializeDelivery,
  serializeMember,
  serializeOrganisation,
  serializePasskey,
  serializeUser
} from "./serializers.js";

export interface EndpointExecution<Body = unknown> {
  status?: 200 | 202;
  body: Body;
  setOAuthBrowser?: { state: string; token: string; expiresAt: Date };
  setSession?: { token: string; expiresAt: Date };
  setMfaChallenge?: { token: string; expiresAt: Date };
  clearSession?: boolean;
  clearMfaChallenge?: boolean;
  oauthCallback?: {
    destination: string | null;
    interactionMode: "redirect" | "popup";
    openerOrigin: string | null;
  };
  samlCallback?: { destination: string | null };
}

interface EndpointExecutionContext {
  auth: OwnAuth<string, string>;
  sessionToken: string | null;
  mfaChallengeToken: string | null;
  oauthBrowserToken: string | null;
  request: RequestContext;
}

type EndpointExecutor<Id extends OwnAuthEndpointId> = (
  context: EndpointExecutionContext,
  input: OwnAuthEndpointInputMap[Id]
) => Promise<EndpointExecution<OwnAuthEndpointOutputMap[Id]>>;

type EndpointExecutorMap = {
  [Id in OwnAuthEndpointId]: EndpointExecutor<Id>;
};

const endpointExecutors = {
  eraseUser: async ({ auth, sessionToken, request }, input) => {
    const body = await auth.eraseUser({ ...input, sessionToken: requireToken(sessionToken, "session"), request });
    return { ...userErasureExecution(body), clearSession: true, clearMfaChallenge: true };
  },
  adminEraseUser: async (context, input) => {
    const authorized = await administrationInput(context, input);
    const body = await context.auth.admin.eraseUser(authorized);
    return { ...userErasureExecution(body),
      ...(authorized.actorUserId === input.userId ? { clearSession: true, clearMfaChallenge: true } : {}) };
  },
  adminGetUserErasure: async (context, input) => {
    const body = await context.auth.admin.getUserErasure(await administrationInput(context, input));
    return userErasureExecution(body);
  },
  adminResumeUserErasure: async (context, input) => {
    const body = await context.auth.admin.resumeUserErasure(await administrationInput(context, input));
    return userErasureExecution(body);
  },
  signUpEmailPassword: async ({ auth, request }, input) =>
    signInExecution(await auth.signUpEmailPassword({ ...input, request })),

  signInEmailPassword: async ({ auth, request }, input) =>
    signInExecution(await auth.signInEmailPassword({ ...input, request })),

  getSession: async ({ auth, sessionToken }) => {
    const current = sessionToken ? await auth.getCurrentSession(sessionToken) : null;
    return { body: { session: current ? serializeAuthSession(current) : null } };
  },

  signOut: async ({ auth, sessionToken, request }) => {
    if (sessionToken) await auth.signOut(sessionToken, request);
    return {
      body: { success: true },
      clearSession: true,
      clearMfaChallenge: true
    };
  },

  changePassword: async ({ auth, sessionToken, request }, input) => {
    const user = await auth.changePassword({
      ...input,
      sessionToken: requireToken(sessionToken, "session"),
      request
    });
    return { body: { user: serializeUser(user) } };
  },

  requestMagicLink: async ({ auth, request }, input) => ({
    body: serializeDelivery(await auth.requestMagicLink({ ...input, request }))
  }),

  verifyMagicLink: async ({ auth, sessionToken, request }, input) =>
    signInExecution(await auth.verifyMagicLink({ ...input, sessionToken: sessionToken ?? undefined, request })),

  requestEmailVerification: async ({ auth, request }, input) => ({
    body: serializeDelivery(await auth.requestEmailVerification({ ...input, request }))
  }),

  verifyEmail: async ({ auth, sessionToken, request }, input) => {
    const user = await auth.verifyEmail({ ...input, sessionToken: sessionToken ?? undefined, request });
    const current = sessionToken ? await auth.getCurrentSession(sessionToken) : null;
    return { body: { user: serializeUser(user) }, clearSession: !!sessionToken && current?.user.id !== user.id };
  },

  requestPasswordReset: async ({ auth, request }, input) => ({
    body: serializeDelivery(await auth.requestPasswordReset({ ...input, request }))
  }),

  resetPassword: async ({ auth, sessionToken, request }, input) => ({
    body: { user: serializeUser(await auth.resetPassword({ ...input, sessionToken: sessionToken ?? undefined, request })) },
    clearSession: true,
    clearMfaChallenge: true
  }),

  requestSmsOtp: async ({ auth, sessionToken, request }, input) => {
    const userId = input.purpose === "phone_verification"
      ? (await auth.requireCurrentSession(requireToken(sessionToken, "session"))).user.id
      : undefined;
    return {
      body: serializeDelivery(await auth.requestSmsOtp({ ...input, userId, request }))
    };
  },

  verifySmsOtp: async ({ auth, request }, input) => {
    const result = await auth.verifySmsOtp({ ...input, request });
    return result.status === "verified"
      ? { body: { status: "verified", user: serializeUser(result.user) } }
      : signInExecution(result);
  },

  acceptInvite: async ({ auth, sessionToken, request }, input) => {
    const current = await auth.requireCurrentSession(requireToken(sessionToken, "session"));
    const result = await auth.acceptInvite({ ...input, userId: current.user.id, request });
    return {
      body: {
        organisation: serializeOrganisation(result.organisation),
        member: serializeMember(result.member)
      }
    };
  },

  oauthStart: async ({ auth, sessionToken, request }, input) => {
    const actorUserId = input.intent === "link"
      ? (await auth.requireCurrentSession(requireToken(sessionToken, "session"))).user.id
      : sessionToken ? (await auth.getCurrentSession(sessionToken))?.user.id : undefined;
    const result = await auth.createOAuthAuthorizationUrl({ ...input, actorUserId, request });
    return {
      body: { url: result.url, expiresAt: result.expiresAt.toISOString() },
      setOAuthBrowser: {
        state: result.state,
        token: result.browserBindingToken,
        expiresAt: result.expiresAt
      }
    };
  },

  oauthGoogleCallback: async (context, input) =>
    oauthExecution(await completeOAuth(context, "google", input)),

  oauthGitHubCallback: async (context, input) =>
    oauthExecution(await completeOAuth(context, "github", input)),

  oauthAppleCallback: async (context, input) =>
    oauthExecution(await completeOAuth(context, "apple", input)),

  oauthAppleCallbackPost: async (context, input) =>
    oauthExecution(await completeOAuth(context, "apple", input)),

  prepareGoogleOneTap: async ({ auth, request }) => {
    const result = await auth.prepareGoogleOneTap({ request });
    return { body: { nonce: result.nonce, expiresAt: result.expiresAt.toISOString() } };
  },

  signInGoogleOneTap: async ({ auth, request }, input) => {
    const result = await auth.signInWithGoogleOneTap({ ...input, request });
    if (result.status === "linked") {
      throw new AuthError("oauth_provider_error", "Google One Tap sign-in failed", 500);
    }
    return signInExecution(result);
  },

  unlinkOAuthProvider: async ({ auth, sessionToken, request }, input) => {
    const current = await auth.requireCurrentSession(requireToken(sessionToken, "session"));
    await auth.unlinkOAuthProvider({ ...input, actorUserId: current.user.id, request });
    return { body: { success: true } };
  },

  samlStart: async ({ auth, sessionToken, request }, input) => {
    const result = input.intent === "link"
      ? await auth.saml.createLinkUrl({
          connectionId: input.connectionId,
          destination: input.destination,
          actorUserId: (await auth.requireCurrentSession(
            requireToken(sessionToken, "session")
          )).user.id,
          request
        })
      : await auth.saml.createSignInUrl({
          connectionId: input.connectionId,
          destination: input.destination,
          request
        });
    return { body: { url: result.url, expiresAt: result.expiresAt.toISOString() } };
  },

  samlAcs: async ({ auth, request }, input) =>
    samlExecution(await auth.saml[completeSamlResponse]({
      samlResponse: input.SAMLResponse,
      relayState: input.RelayState,
      request
    })),

  samlMetadata: async ({ auth }, input) => ({
    body: await auth.saml.getMetadata(input)
  }),

  completeMfaTotp: async ({ auth, mfaChallengeToken, request }, input) =>
    completedMfaExecution(await auth.completeMfaWithTotp({
      ...input,
      challengeToken: requireToken(mfaChallengeToken, "MFA challenge"),
      request
    })),

  completeMfaRecovery: async ({ auth, mfaChallengeToken, request }, input) =>
    completedMfaExecution(await auth.completeMfaWithRecoveryCode({
      ...input,
      challengeToken: requireToken(mfaChallengeToken, "MFA challenge"),
      request
    })),

  beginTotpEnrollment: async ({ auth, sessionToken, request }) => ({
    body: await auth.beginTotpEnrollment({
      sessionToken: requireToken(sessionToken, "session"),
      request
    })
  }),

  confirmTotpEnrollment: async ({ auth, sessionToken, request }, input) => ({
    body: await auth.confirmTotpEnrollment({
      ...input,
      sessionToken: requireToken(sessionToken, "session"),
      request
    })
  }),

  disableTotp: async ({ auth, sessionToken, request }, input) => {
    await auth.disableTotp({
      ...input,
      sessionToken: requireToken(sessionToken, "session"),
      request
    });
    return { body: { success: true } };
  },

  regenerateRecoveryCodes: async ({ auth, sessionToken, request }, input) => ({
    body: {
      recoveryCodes: await auth.regenerateRecoveryCodes({
        ...input,
        sessionToken: requireToken(sessionToken, "session"),
        request
      })
    }
  }),

  beginPasskeyRegistration: async ({ auth, sessionToken, request }) => ({
    body: await auth.beginPasskeyRegistration({
      sessionToken: requireToken(sessionToken, "session"),
      request
    })
  }),

  completePasskeyRegistration: async ({ auth, sessionToken, request }, input) => ({
    body: {
      passkey: serializePasskey(await auth.completePasskeyRegistration({
        ...input,
        sessionToken: requireToken(sessionToken, "session"),
        request
      }))
    }
  }),

  beginPasskeyAuthentication: async ({ auth, mfaChallengeToken, request }, input) => ({
    body: await auth.beginPasskeyAuthentication({
      userId: input.userId,
      mfaChallengeToken: input.mfa
        ? requireToken(mfaChallengeToken, "MFA challenge")
        : undefined,
      request
    })
  }),

  completePasskeyAuthentication: async ({ auth, request }, input) =>
    completedMfaExecution(await auth.completePasskeyAuthentication({ ...input, request })),

  listPasskeys: async ({ auth, sessionToken }) => ({
    body: {
      passkeys: (await auth.listPasskeys({
        sessionToken: requireToken(sessionToken, "session")
      })).map(serializePasskey)
    }
  }),

  renamePasskey: async ({ auth, sessionToken, request }, input) => ({
    body: {
      passkey: serializePasskey(await auth.renamePasskey({
        ...input,
        sessionToken: requireToken(sessionToken, "session"),
        request
      }))
    }
  }),

  revokePasskey: async ({ auth, sessionToken, request }, input) => {
    await auth.revokePasskey({
      ...input,
      sessionToken: requireToken(sessionToken, "session"),
      request
    });
    return { body: { success: true } };
  },

  adminListUsers: async (context, input) => {
    const result = await context.auth.admin.listUsers(await administrationInput(context, {
      ...input,
      limit: optionalInteger(input.limit)
    }));
    return {
      body: {
        users: result.items.map(serializeAdministrationUser),
        nextCursor: result.nextCursor
      }
    };
  },

  adminGetUser: async (context, input) => ({
    body: {
      user: serializeAdministrationUser(
        await context.auth.admin.getUser(await administrationInput(context, input))
      )
    }
  }),

  adminListUserSessions: async (context, input) => ({
    body: {
      sessions: (await context.auth.admin.listUserSessions(
        await administrationInput(context, input)
      )).map(serializeAdministrationSession)
    }
  }),

  adminListUserAuditEvents: async (context, input) => {
    const result = await context.auth.admin.listUserAuditEvents(await administrationInput(context, {
      ...input,
      limit: optionalInteger(input.limit)
    }));
    return {
      body: {
        events: result.items.map(serializeAdministrationAuditEvent),
        nextCursor: result.nextCursor
      }
    };
  },

  adminDisableUser: async (context, input) => ({
    body: {
      user: serializeAdministrationUser(
        await context.auth.admin.disableUser(await administrationInput(context, input))
      )
    }
  }),

  adminEnableUser: async (context, input) => ({
    body: {
      user: serializeAdministrationUser(
        await context.auth.admin.enableUser(await administrationInput(context, input))
      )
    }
  }),

  adminRevokeUserSessions: async (context, input) => ({
    body: {
      revoked: await context.auth.admin.revokeUserSessions(
        await administrationInput(context, input)
      )
    }
  })
} satisfies EndpointExecutorMap;

export function executeEndpoint<Id extends OwnAuthEndpointId>(
  auth: OwnAuth<string, string>,
  endpointId: Id,
  rawInput: Record<string, unknown> | undefined,
  sessionToken: string | null,
  mfaChallengeToken: string | null,
  request: RequestContext,
  oauthBrowserToken: string | null
): Promise<EndpointExecution<OwnAuthEndpointOutputMap[Id]>> {
  const executor = endpointExecutors[endpointId] as unknown as EndpointExecutor<Id>;
  return executor(
    { auth, sessionToken, mfaChallengeToken, request, oauthBrowserToken },
    rawInput as unknown as OwnAuthEndpointInputMap[Id]
  );
}

function userErasureExecution(body: UserErasureResult): EndpointExecution<UserErasureResult> {
  return { body, status: body.status === "pending" ? 202 : 200 };
}

function signInExecution(result: SessionResult): EndpointExecution<AuthSessionPayload>;
function signInExecution(result: SignInResult): EndpointExecution<SignInPayload>;
function signInExecution(result: SignInResult): EndpointExecution<SignInPayload> {
  if (result.status === "complete") return completedSessionExecution(result);
  return {
    body: serializeMfaRequired(result),
    setMfaChallenge: { token: result.challengeToken, expiresAt: result.expiresAt }
  };
}

function completedMfaExecution(result: SessionResult): EndpointExecution<AuthSessionPayload> {
  return { ...completedSessionExecution(result), clearMfaChallenge: true };
}

function completedSessionExecution(result: SessionResult): EndpointExecution<AuthSessionPayload> {
  return {
    body: serializeAuthSession(result),
    setSession: { token: result.sessionToken, expiresAt: result.session.expiresAt }
  };
}

function oauthExecution(
  result: OAuthCompletionResult
): EndpointExecution<OwnAuthEndpointOutputMap["oauthGoogleCallback"]> {
  const callback = {
    destination: result.destination,
    interactionMode: result.interactionMode,
    openerOrigin: result.openerOrigin
  };
  if (result.status === "linked") {
    return { body: { status: "linked" }, oauthCallback: callback };
  }
  return { ...signInExecution(result), oauthCallback: callback };
}

function samlExecution(
  result: SamlCompletionResult
): EndpointExecution<OwnAuthEndpointOutputMap["samlAcs"]> {
  const callback = { destination: result.destination };
  if (result.status === "linked") {
    return { body: { status: "linked" }, samlCallback: callback };
  }
  return { ...signInExecution(result), samlCallback: callback };
}

async function completeOAuth(
  context: EndpointExecutionContext,
  provider: "google" | "github" | "apple",
  rawInput: Record<string, unknown> | undefined
): Promise<OAuthCompletionResult> {
  const parameters = new URLSearchParams();
  for (const [name, value] of Object.entries(rawInput ?? {})) {
    if (typeof value === "string") parameters.append(name, value);
  }
  return context.auth.completeOAuthSignIn({
    provider,
    callbackParameters: parameters,
    browserBindingToken: context.oauthBrowserToken ?? "",
    request: context.request
  });
}

function serializeMfaRequired(result: MfaRequiredResult): SignInPayload {
  return {
    status: "mfa_required",
    methods: [...result.methods],
    expiresAt: result.expiresAt.toISOString()
  };
}

function requireToken(token: string | null, kind: "session" | "MFA challenge"): string {
  if (!token) {
    const code = kind === "session" ? "invalid_session" : "mfa_challenge_invalid";
    throw new AuthError(code, `Invalid or expired ${kind}`, 401);
  }
  return token;
}

async function administrationInput<Input extends object>(
  context: EndpointExecutionContext,
  input: Input
): Promise<Input & { actorUserId: string; request: RequestContext }> {
  const current = await context.auth.requireCurrentSession(
    requireToken(context.sessionToken, "session")
  );
  return { ...input, actorUserId: current.user.id, request: context.request };
}

function optionalInteger(value: string | undefined): number | undefined {
  return value === undefined ? undefined : Number(value);
}
