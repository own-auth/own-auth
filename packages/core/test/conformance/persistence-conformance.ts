import { createTotpCode } from "../identity-test-helpers.js";
import {
  assertConformance,
  assertConformanceEqual,
  requireCompleteResult,
  requireConformanceValue
} from "./conformance-assertions.js";
import { uniqueConformancePhone } from "./conformance-values.js";
import type {
  PersistenceConformanceArtifacts,
  PersistenceConformanceAuth
} from "./persistence-conformance-contract.js";

export interface PersistenceConformanceHarness {
  auth: PersistenceConformanceAuth;
  inspect(artifacts: PersistenceConformanceArtifacts): Promise<Record<string, boolean>>;
}

export async function runPersistenceConformance(
  harness: PersistenceConformanceHarness
): Promise<PersistenceConformanceArtifacts> {
  const { auth } = harness;
  const suffix = crypto.randomUUID();
  const email = `persistence-${suffix}@example.com`;
  const invitedEmail = `invited-${suffix}@example.com`;
  const blockedEmail = `blocked-${suffix}@example.com`;
  const externalEmail = `external-${suffix}@example.com`;
  const password = `correct-horse-${suffix}`;
  const resetPassword = `new-password-${suffix}`;
  const phone = uniqueConformancePhone();
  const sessionTokens: string[] = [];

  const signup = await auth.signUpEmailPassword({ email, password });
  sessionTokens.push(signup.sessionToken);
  assertConformanceEqual(
    (await auth.requireCurrentSession(signup.sessionToken)).user.email,
    email,
    "persisted signup session email"
  );

  const passwordSignIn = requireCompleteResult(
    await auth.signInEmailPassword({ email, password }),
    "password sign-in"
  );
  sessionTokens.push(passwordSignIn.sessionToken);
  await auth.signOut(passwordSignIn.sessionToken);
  assertConformanceEqual(
    await auth.getCurrentSession(passwordSignIn.sessionToken),
    null,
    "signed-out session"
  );

  const verification = await auth.requestEmailVerification({ email });
  const verificationToken = requireConformanceValue(
    verification.token,
    "Email-verification token was not exposed"
  );
  const verifiedUser = await auth.verifyEmail({ token: verificationToken, sessionToken: signup.sessionToken });
  assertConformance(
    verifiedUser.emailVerifiedAt instanceof Date,
    "Email verification was not persisted"
  );

  const magicDelivery = await auth.requestMagicLink({ email });
  const magicToken = requireConformanceValue(
    magicDelivery.token,
    "Magic-link token was not exposed"
  );
  const magicSignIn = requireCompleteResult(
    await auth.verifyMagicLink({ token: magicToken }),
    "magic-link sign-in"
  );
  sessionTokens.push(magicSignIn.sessionToken);

  const resetDelivery = await auth.requestPasswordReset({ email });
  const resetToken = requireConformanceValue(
    resetDelivery.token,
    "Password-reset token was not exposed"
  );
  await auth.resetPassword({ token: resetToken, newPassword: resetPassword });
  assertConformanceEqual(
    await auth.getCurrentSession(signup.sessionToken),
    null,
    "password reset revoked the signup session"
  );
  const resetSignIn = requireCompleteResult(
    await auth.signInEmailPassword({ email, password: resetPassword }),
    "password-reset sign-in"
  );
  sessionTokens.push(resetSignIn.sessionToken);

  const phoneVerification = await auth.requestSmsOtp({
    phone,
    purpose: "phone_verification",
    userId: signup.user.id
  });
  const verificationCode = requireConformanceValue(
    phoneVerification.code,
    "Phone-verification code was not exposed"
  );
  await auth.verifySmsOtp({
    phone,
    purpose: "phone_verification",
    code: verificationCode
  });
  const phoneLogin = await auth.requestSmsOtp({ phone });
  const loginCode = requireConformanceValue(phoneLogin.code, "Phone-login code was not exposed");
  const phoneSignIn = requireCompleteResult(
    await auth.verifySmsOtp({ phone, code: loginCode }),
    "phone sign-in"
  );
  sessionTokens.push(phoneSignIn.sessionToken);

  const externalSignIn = requireCompleteResult(await auth.signInWithVerifiedExternalIdentity({
    provider: "google",
    providerAccountId: `google-${suffix}`,
    email: externalEmail,
    emailVerified: true
  }), "external-provider sign-in");
  sessionTokens.push(externalSignIn.sessionToken);

  const invited = await auth.signUpEmailPassword({
    email: invitedEmail,
    password: `invited-password-${suffix}`
  });
  const blocked = await auth.signUpEmailPassword({
    email: blockedEmail,
    password: `blocked-password-${suffix}`
  });
  sessionTokens.push(invited.sessionToken, blocked.sessionToken);

  const { organisation } = await auth.createOrganisation({
    name: `Persistence ${suffix}`,
    ownerUserId: signup.user.id
  });
  await assertRejectsWithCode(
    () => auth.listMembers({
      organisationId: organisation.id,
      actorUserId: blocked.user.id
    }),
    "permission_denied",
    "organisation member isolation"
  );

  const invitation = await auth.inviteMember({
    organisationId: organisation.id,
    email: invitedEmail,
    invitedByUserId: signup.user.id
  });
  const invitationToken = requireConformanceValue(
    invitation.token,
    "Invitation token was not exposed"
  );
  await auth.acceptInvite({ token: invitationToken, userId: invited.user.id });
  assertConformanceEqual(
    (await auth.listMembers({
      organisationId: organisation.id,
      actorUserId: signup.user.id
    })).length,
    2,
    "organisation member count"
  );

  const createdKey = await auth.createApiKey({
    name: "Persistence key",
    organisationId: organisation.id,
    actorUserId: signup.user.id,
    scopes: ["read users"]
  });
  const verifiedKey = await auth.verifyApiKey(createdKey.rawKey, ["read users"]);
  assertConformanceEqual(
    verifiedKey.organisation?.id,
    organisation.id,
    "verified API-key organisation"
  );
  const personalKey = await auth.createApiKey({
    name: "Personal persistence key",
    actorUserId: signup.user.id,
    scopes: ["read profile"]
  });
  await auth.verifyApiKey(personalKey.rawKey, ["read profile"]);
  const auditEvents = await auth.listAuditEvents({
    actorUserId: signup.user.id,
    organisationId: organisation.id
  });
  for (const expectedEvent of [
    "organisation.created",
    "member.invited",
    "invite.accepted",
    "api_key.created",
    "api_key.used"
  ]) {
    assertConformance(
      auditEvents.some((event) => event.eventType === expectedEvent),
      `Missing persisted audit event: ${expectedEvent}`
    );
  }

  const oauth = await auth.createOAuthAuthorizationUrl({ provider: "google" });
  const oauthState = requireConformanceValue(
    new URL(oauth.url).searchParams.get("state"),
    "OAuth state was not returned"
  );
  const passkey = await auth.beginPasskeyRegistration({
    sessionToken: resetSignIn.sessionToken
  });
  const webAuthnChallenge = passkey.options.challenge;

  const totp = await auth.beginTotpEnrollment({ sessionToken: resetSignIn.sessionToken });
  const totpCode = createTotpCode(totp.secret);
  const recovery = await auth.confirmTotpEnrollment({
    sessionToken: resetSignIn.sessionToken,
    factorId: totp.factorId,
    code: totpCode
  });
  assertConformance(recovery.recoveryCodes.length > 0, "Recovery codes were not generated");
  await auth.signOut(resetSignIn.sessionToken);
  const mfa = await auth.signInEmailPassword({ email, password: resetPassword });
  assertConformanceEqual(mfa.status, "mfa_required", "password sign-in MFA status");
  if (mfa.status !== "mfa_required") {
    throw new Error("Password sign-in did not return an MFA challenge");
  }
  const completedMfa = await auth.completeMfaWithRecoveryCode({
    challengeToken: mfa.challengeToken,
    code: recovery.recoveryCodes[0]!
  });
  sessionTokens.push(completedMfa.sessionToken);

  await auth.deleteOrganisation({
    organisationId: organisation.id,
    actorUserId: signup.user.id
  });
  await assertRejectsWithCode(
    () => auth.getOrganisation({
      organisationId: organisation.id,
      actorUserId: signup.user.id
    }),
    "organisation_not_found",
    "deleted organisation lookup"
  );

  const artifacts: PersistenceConformanceArtifacts = {
    passwords: [password, resetPassword],
    sessionTokens,
    emailTokens: [verificationToken, magicToken, resetToken, invitationToken],
    smsCodes: [verificationCode, loginCode],
    apiKeys: [createdKey.rawKey, personalKey.rawKey],
    totpSecrets: [totp.secret],
    recoveryCodes: recovery.recoveryCodes,
    oauthStates: [oauthState],
    mfaChallengeTokens: [mfa.challengeToken],
    webAuthnChallenges: [webAuthnChallenge],
    otherSecrets: [totpCode, oauth.browserBindingToken],
    organisationId: organisation.id,
    ownerUserId: signup.user.id,
    continuity: {
      email,
      sessionToken: completedMfa.sessionToken
    }
  };
  const inspection = await harness.inspect(artifacts);
  for (const [check, passed] of Object.entries(inspection)) {
    assertConformance(passed, `Persistence inspection failed: ${check}`);
  }

  const deletedAuditEvents = await auth.cleanupAuditLogs({
    olderThan: new Date(Date.now() + 1_000)
  });
  assertConformance(deletedAuditEvents > 0, "Audit-log cleanup did not remove any events");
  return artifacts;
}

async function assertRejectsWithCode(
  operation: () => Promise<unknown>,
  expectedCode: string,
  message: string
): Promise<void> {
  try {
    await operation();
  } catch (error) {
    assertConformanceEqual(errorCode(error), expectedCode, message);
    return;
  }
  throw new Error(`${message}. Expected rejection with ${expectedCode}`);
}

function errorCode(error: unknown): unknown {
  return typeof error === "object" && error !== null && "code" in error
    ? error.code
    : undefined;
}
