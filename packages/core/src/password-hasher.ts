export const MAXIMUM_PASSWORD_INPUT_LENGTH = 4_096;

export interface PasswordHasher {
  hash(password: string): Promise<string>;
  verify(password: string, encodedHash: string): Promise<boolean>;
  needsRehash(encodedHash: string): boolean;
}

export function assertPasswordInputLength(password: string): void {
  if (password.length > MAXIMUM_PASSWORD_INPUT_LENGTH) {
    throw new Error("Password input is too long.");
  }
}

export function isPasswordInputTooLong(password: string): boolean {
  return password.length > MAXIMUM_PASSWORD_INPUT_LENGTH;
}
