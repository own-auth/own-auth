import { createIdentityConflictError } from "../errors.js";

export async function withPostgresIdentityErrors<Value>(
  operation: () => Promise<Value>
): Promise<Value> {
  try {
    return await operation();
  } catch (error) {
    rethrowPostgresIdentityError(error);
  }
}

export function isPostgresUniqueConstraint(
  error: unknown,
  constraint: string
): boolean {
  const postgresError = asPostgresError(error);
  return postgresError?.code === "23505" && postgresError.constraint === constraint;
}

function rethrowPostgresIdentityError(error: unknown): never {
  const postgresError = asPostgresError(error);
  if (postgresError?.code !== "23505") {
    throw error;
  }

  if (postgresError.constraint === "own_auth_users_email_unique") {
    throw createIdentityConflictError("email");
  }
  if (postgresError.constraint === "own_auth_users_phone_unique") {
    throw createIdentityConflictError("phone");
  }
  if (postgresError.constraint === "own_auth_accounts_provider_account_unique") {
    throw createIdentityConflictError("providerAccount");
  }

  throw error;
}

function asPostgresError(error: unknown): { code?: string; constraint?: string } | null {
  return typeof error === "object" && error !== null
    ? error as { code?: string; constraint?: string }
    : null;
}
