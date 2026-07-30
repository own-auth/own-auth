import type { createOwnAuth } from "../../src/index.js";

type Auth = ReturnType<typeof createOwnAuth>;

export const persistenceConformanceAuthMethods = [
  "acceptInvite",
  "beginPasskeyRegistration",
  "beginTotpEnrollment",
  "cleanupAuditLogs",
  "completeMfaWithRecoveryCode",
  "confirmTotpEnrollment",
  "createApiKey",
  "createOAuthAuthorizationUrl",
  "createOrganisation",
  "deleteOrganisation",
  "getCurrentSession",
  "getOrganisation",
  "inviteMember",
  "listAuditEvents",
  "listMembers",
  "requestEmailVerification",
  "requestMagicLink",
  "requestPasswordReset",
  "requestSmsOtp",
  "requireCurrentSession",
  "resetPassword",
  "signInEmailPassword",
  "signInWithVerifiedExternalIdentity",
  "signOut",
  "signUpEmailPassword",
  "unlinkOAuthProvider",
  "verifyApiKey",
  "verifyEmail",
  "verifyMagicLink",
  "verifySmsOtp"
] as const satisfies readonly (keyof Auth)[];

export type PersistenceConformanceAuth = Pick<
  Auth,
  typeof persistenceConformanceAuthMethods[number]
>;

export interface PersistenceConformanceArtifacts {
  passwords: string[];
  sessionTokens: string[];
  emailTokens: string[];
  smsCodes: string[];
  apiKeys: string[];
  totpSecrets: string[];
  recoveryCodes: string[];
  oauthStates: string[];
  mfaChallengeTokens: string[];
  webAuthnChallenges: string[];
  otherSecrets: string[];
  organisationId: string;
  ownerUserId: string;
  continuity: {
    email: string;
    sessionToken: string;
  };
}

export const persistenceArtifactArrayKeys = [
  "passwords",
  "sessionTokens",
  "emailTokens",
  "smsCodes",
  "apiKeys",
  "totpSecrets",
  "recoveryCodes",
  "oauthStates",
  "mfaChallengeTokens",
  "webAuthnChallenges",
  "otherSecrets"
] as const satisfies readonly (keyof PersistenceConformanceArtifacts)[];

interface PersistenceSecretCheck {
  name: string;
  table: string;
  column: string;
  values: readonly string[];
}

interface PersistenceRelationCheck {
  name: string;
  table: string;
  column: string;
  value: string;
  expectedRows: number;
}

interface PersistenceCounter {
  countExact(table: string, column: string, values: readonly string[]): Promise<number>;
  countWhere(table: string, column: string, value: string): Promise<number>;
}

export async function evaluatePersistenceChecks(
  artifacts: PersistenceConformanceArtifacts,
  counter: PersistenceCounter
): Promise<Record<string, boolean>> {
  const checks: Record<string, boolean> = {};
  for (const check of persistenceSecretChecks(artifacts)) {
    checks[check.name] = await counter.countExact(
      check.table,
      check.column,
      check.values
    ) === 0;
  }
  for (const check of persistenceRelationChecks(artifacts)) {
    checks[check.name] = await counter.countWhere(
      check.table,
      check.column,
      check.value
    ) === check.expectedRows;
  }
  return checks;
}

function persistenceSecretChecks(
  artifacts: PersistenceConformanceArtifacts
): PersistenceSecretCheck[] {
  return [
    secretCheck("passwordsAreHashed", "own_auth_users", "password_hash", artifacts.passwords),
    secretCheck(
      "sessionTokensAreHashed",
      "own_auth_sessions",
      "token_hash",
      artifacts.sessionTokens
    ),
    secretCheck("emailTokensAreHashed", "own_auth_tokens", "token_hash", artifacts.emailTokens),
    secretCheck("smsCodesAreHashed", "own_auth_sms_otps", "code_hash", artifacts.smsCodes),
    secretCheck("apiKeysAreHashed", "own_auth_api_keys", "key_hash", artifacts.apiKeys),
    secretCheck(
      "totpSecretsAreEncrypted",
      "own_auth_mfa_factors",
      "ciphertext",
      artifacts.totpSecrets
    ),
    secretCheck(
      "recoveryCodesAreHashed",
      "own_auth_recovery_codes",
      "code_hash",
      artifacts.recoveryCodes
    ),
    secretCheck(
      "oauthStatesAreHashed",
      "own_auth_oauth_transactions",
      "state_hash",
      artifacts.oauthStates
    ),
    secretCheck(
      "mfaChallengesAreHashed",
      "own_auth_mfa_challenges",
      "token_hash",
      artifacts.mfaChallengeTokens
    ),
    secretCheck(
      "webAuthnChallengesAreHashed",
      "own_auth_webauthn_challenges",
      "challenge_hash",
      artifacts.webAuthnChallenges
    )
  ];
}

function persistenceRelationChecks(
  artifacts: PersistenceConformanceArtifacts
): PersistenceRelationCheck[] {
  return [
    relationCheck("organisationWasDeleted", "own_auth_organisations", "id", artifacts.organisationId, 0),
    relationCheck(
      "organisationMembersWereDeleted",
      "own_auth_organisation_members",
      "organisation_id",
      artifacts.organisationId,
      0
    ),
    relationCheck(
      "organisationInvitationsWereDeleted",
      "own_auth_invitations",
      "organisation_id",
      artifacts.organisationId,
      0
    ),
    relationCheck(
      "organisationApiKeysWereDeleted",
      "own_auth_api_keys",
      "organisation_id",
      artifacts.organisationId,
      0
    ),
    relationCheck(
      "organisationTokensWereDeleted",
      "own_auth_tokens",
      "organisation_id",
      artifacts.organisationId,
      0
    ),
    relationCheck("ownerUserWasRetained", "own_auth_users", "id", artifacts.ownerUserId, 1)
  ];
}

export function persistenceSecrets(artifacts: PersistenceConformanceArtifacts): string[] {
  return persistenceArtifactArrayKeys.flatMap((key) => artifacts[key]);
}

function secretCheck(
  name: string,
  table: string,
  column: string,
  values: readonly string[]
): PersistenceSecretCheck {
  return { name, table, column, values };
}

function relationCheck(
  name: string,
  table: string,
  column: string,
  value: string,
  expectedRows: number
): PersistenceRelationCheck {
  return { name, table, column, value, expectedRows };
}
