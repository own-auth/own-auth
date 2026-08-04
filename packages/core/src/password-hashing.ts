import { argon2idAsync } from "@noble/hashes/argon2.js";
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { randomBytes, timingSafeEqual } from "node:crypto";
import {
  hashPbkdf2Password,
  isPbkdf2PasswordHash,
  pbkdf2PasswordNeedsRehash,
  verifyPbkdf2Password
} from "./password-hashing-pbkdf2.js";
import {
  assertPasswordInputLength,
  isPasswordInputTooLong,
  type PasswordHasher
} from "./password-hasher.js";

const ARGON2_MEMORY_COST = 19 * 1024;
const ARGON2_TIME_COST = 2;
const ARGON2_PARALLELISM = 1;
const ARGON2_HASH_LENGTH = 32;
const ARGON2_VERSION = 0x13;
const ARGON2_SALT_LENGTH = 16;
const ARGON2_MAX_MEMORY_BYTES = 64 * 1024 * 1024;
const ARGON2_MAX_TIME_COST = 10;
const ARGON2_MAX_PARALLELISM = 4;
const ARGON2_MAX_SALT_LENGTH = 64;
const ARGON2_MAX_HASH_LENGTH = 64;
const LEGACY_SCRYPT_VERSION = "scrypt";
const LEGACY_SCRYPT_N = 16384;
const LEGACY_SCRYPT_R = 8;
const LEGACY_SCRYPT_P = 1;
const LEGACY_SCRYPT_KEY_LENGTH = 64;

interface Argon2Parameters {
  memoryCost: number;
  timeCost: number;
  parallelism: number;
  hashLength: number;
  version: number;
}

interface ParsedArgon2idHash extends Omit<Argon2Parameters, "hashLength"> {
  salt: Uint8Array;
  hash: Uint8Array;
}

export const argon2idPasswordHasher: PasswordHasher = Object.freeze({
  hash: hashPassword,
  verify: verifyPassword,
  needsRehash: passwordNeedsRehash
});

const pbkdf2PasswordHasher: PasswordHasher = Object.freeze({
  hash: hashPbkdf2Password,
  verify: verifyPbkdf2CompatiblePassword,
  needsRehash: pbkdf2PasswordNeedsRehash
});

export function createPbkdf2PasswordHasher(): PasswordHasher {
  return pbkdf2PasswordHasher;
}

export async function hashPassword(password: string): Promise<string> {
  assertPasswordInputLength(password);
  const salt = randomBytes(ARGON2_SALT_LENGTH);
  const hash = await deriveArgon2id(password, salt, {
    memoryCost: ARGON2_MEMORY_COST,
    timeCost: ARGON2_TIME_COST,
    parallelism: ARGON2_PARALLELISM,
    hashLength: ARGON2_HASH_LENGTH,
    version: ARGON2_VERSION
  });

  return encodeArgon2idHash(salt, hash);
}

export async function verifyPassword(
  password: string,
  encodedHash: string
): Promise<boolean> {
  if (isPasswordInputTooLong(password)) {
    return false;
  }
  if (isPbkdf2PasswordHash(encodedHash)) {
    return verifyPbkdf2Password(password, encodedHash);
  }
  if (!encodedHash.startsWith("$argon2id$")) {
    return verifyLegacyScryptPassword(password, encodedHash);
  }

  try {
    const parsed = parseArgon2idHash(encodedHash);
    const actual = await deriveArgon2id(password, parsed.salt, {
      memoryCost: parsed.memoryCost,
      timeCost: parsed.timeCost,
      parallelism: parsed.parallelism,
      hashLength: parsed.hash.length,
      version: parsed.version
    });

    return equalBytes(actual, parsed.hash);
  } catch {
    return false;
  }
}

export function passwordNeedsRehash(encodedHash: string): boolean {
  if (isPbkdf2PasswordHash(encodedHash)) {
    return pbkdf2PasswordNeedsRehash(encodedHash);
  }
  if (!encodedHash.startsWith("$argon2id$")) {
    return true;
  }

  try {
    const parsed = parseArgon2idHash(encodedHash);
    return (
      parsed.memoryCost !== ARGON2_MEMORY_COST ||
      parsed.timeCost !== ARGON2_TIME_COST ||
      parsed.parallelism !== ARGON2_PARALLELISM ||
      parsed.hash.length !== ARGON2_HASH_LENGTH ||
      parsed.version !== ARGON2_VERSION
    );
  } catch {
    return true;
  }
}

async function verifyPbkdf2CompatiblePassword(
  password: string,
  encodedHash: string
): Promise<boolean> {
  if (!isPbkdf2PasswordHash(encodedHash)) {
    return verifyPassword(password, encodedHash);
  }
  return verifyPbkdf2Password(password, encodedHash);
}

async function deriveArgon2id(
  password: string,
  salt: Uint8Array,
  parameters: Argon2Parameters
): Promise<Uint8Array> {
  return argon2idAsync(password, salt, {
    m: parameters.memoryCost,
    t: parameters.timeCost,
    p: parameters.parallelism,
    dkLen: parameters.hashLength,
    version: parameters.version,
    maxmem: ARGON2_MAX_MEMORY_BYTES
  });
}

function encodeArgon2idHash(salt: Uint8Array, hash: Uint8Array): string {
  return [
    "",
    "argon2id",
    `v=${ARGON2_VERSION}`,
    `m=${ARGON2_MEMORY_COST},t=${ARGON2_TIME_COST},p=${ARGON2_PARALLELISM}`,
    encodeBase64(salt),
    encodeBase64(hash)
  ].join("$");
}

function parseArgon2idHash(encodedHash: string): ParsedArgon2idHash {
  const parts = encodedHash.split("$");
  if (parts.length !== 6 || parts[0] !== "" || parts[1] !== "argon2id") {
    throw new Error("Invalid Argon2id hash format.");
  }

  const versionMatch = /^v=(\d+)$/.exec(parts[2] ?? "");
  const parametersMatch = /^m=(\d+),t=(\d+),p=(\d+)$/.exec(parts[3] ?? "");
  if (!versionMatch || !parametersMatch) {
    throw new Error("Invalid Argon2id parameters.");
  }

  const version = parseInteger(versionMatch[1]);
  const memoryCost = parseInteger(parametersMatch[1]);
  const timeCost = parseInteger(parametersMatch[2]);
  const parallelism = parseInteger(parametersMatch[3]);
  const salt = decodeBase64(parts[4] ?? "");
  const hash = decodeBase64(parts[5] ?? "");

  if (
    version !== ARGON2_VERSION ||
    memoryCost < 8 * parallelism ||
    memoryCost * 1024 > ARGON2_MAX_MEMORY_BYTES ||
    timeCost < 1 ||
    timeCost > ARGON2_MAX_TIME_COST ||
    parallelism < 1 ||
    parallelism > ARGON2_MAX_PARALLELISM ||
    salt.length < 8 ||
    salt.length > ARGON2_MAX_SALT_LENGTH ||
    hash.length < 4 ||
    hash.length > ARGON2_MAX_HASH_LENGTH
  ) {
    throw new Error("Unsupported Argon2id parameters.");
  }

  return {
    version,
    memoryCost,
    timeCost,
    parallelism,
    salt,
    hash
  };
}

async function verifyLegacyScryptPassword(
  password: string,
  encodedHash: string
): Promise<boolean> {
  const parts = encodedHash.split("$");
  if (parts.length !== 6) {
    return false;
  }

  const [version, nValue, rValue, pValue, salt, key] = parts;
  if (
    version !== LEGACY_SCRYPT_VERSION ||
    nValue !== String(LEGACY_SCRYPT_N) ||
    rValue !== String(LEGACY_SCRYPT_R) ||
    pValue !== String(LEGACY_SCRYPT_P) ||
    !salt ||
    !key
  ) {
    return false;
  }

  try {
    const encodedSalt = Buffer.from(salt, "base64url");
    const expected = Buffer.from(key, "base64url");
    if (
      encodedSalt.length !== 16 ||
      expected.length !== LEGACY_SCRYPT_KEY_LENGTH ||
      encodedSalt.toString("base64url") !== salt ||
      expected.toString("base64url") !== key
    ) {
      return false;
    }

    const actual = await scryptAsync(password, salt, {
      N: LEGACY_SCRYPT_N,
      r: LEGACY_SCRYPT_R,
      p: LEGACY_SCRYPT_P,
      dkLen: LEGACY_SCRYPT_KEY_LENGTH,
      maxmem: 32 * 1024 * 1024
    });
    return equalBytes(actual, expected);
  } catch {
    return false;
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

function parseInteger(value: string | undefined): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error("Invalid integer.");
  }

  return parsed;
}

function encodeBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64").replace(/=+$/u, "");
}

function decodeBase64(value: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(value)) {
    throw new Error("Invalid base64 value.");
  }

  const bytes = Buffer.from(value, "base64");
  if (encodeBase64(bytes) !== value.replace(/=+$/u, "")) {
    throw new Error("Invalid base64 value.");
  }

  return bytes;
}
