export const coreMigrationFiles = [
  "001_initial.sql",
  "002_external_providers.sql",
  "003_oauth_transactions.sql",
  "004_mfa.sql",
  "005_oauth_credentials.sql",
  "006_passkeys.sql",
  "007_plugin_migrations.sql",
  "008_webhooks.sql",
  "009_custom_authorization.sql",
  "010_administration.sql",
  "011_authorization_server.sql"
] as const;

export const initialMigration = coreMigrationFiles[0];

export const databaseTables = {
  migrations: "own_auth_migrations",
  users: "own_auth_users",
  accounts: "own_auth_accounts",
  sessions: "own_auth_sessions",
  tokens: "own_auth_tokens",
  smsOtps: "own_auth_sms_otps",
  apiKeys: "own_auth_api_keys",
  organisations: "own_auth_organisations",
  organisationMembers: "own_auth_organisation_members",
  invitations: "own_auth_invitations",
  auditEvents: "own_auth_audit_events",
  rateLimits: "own_auth_rate_limits",
  oauthTransactions: "own_auth_oauth_transactions",
  oauthCredentials: "own_auth_oauth_credentials",
  mfaFactors: "own_auth_mfa_factors",
  recoveryCodes: "own_auth_recovery_codes",
  mfaChallenges: "own_auth_mfa_challenges",
  passkeys: "own_auth_passkeys",
  webAuthnChallenges: "own_auth_webauthn_challenges",
  pluginMigrations: "own_auth_plugin_migrations",
  webhookEvents: "own_auth_webhook_events",
  webhookDeliveries: "own_auth_webhook_deliveries",
  webhookAttempts: "own_auth_webhook_attempts",
  authorizationClients: "own_auth_authorization_clients",
  authorizationClientSecrets: "own_auth_authorization_client_secrets",
  authorizationInteractions: "own_auth_authorization_interactions",
  authorizationGrants: "own_auth_authorization_grants",
  authorizationCodes: "own_auth_authorization_codes",
  authorizationAccessTokens: "own_auth_authorization_access_tokens",
  authorizationRefreshTokens: "own_auth_authorization_refresh_tokens",
  oidcSubjects: "own_auth_oidc_subjects"
} as const;
