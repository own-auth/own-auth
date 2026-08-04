import { decodeBase64Url, encodeBase64Url } from "./encoding.js";
import {
  assertPasswordInputLength,
  isPasswordInputTooLong
} from "./password-hasher.js";

const VERSION = "pbkdf2-sha256";
const ITERATIONS = 600_000;
const MIN_ITERATIONS = 100_000;
const MAX_ITERATIONS = 2_000_000;
const SALT_LENGTH = 16;
const HASH_LENGTH = 32;
const MAX_ENCODED_PART_LENGTH = 64;

interface ParsedPbkdf2Hash {
  iterations: number;
  salt: Uint8Array;
  hash: Uint8Array;
}

interface WebCryptoLike {
  getRandomValues<T extends ArrayBufferView>(array: T): T;
  subtle: {
    importKey(
      format: "raw",
      keyData: Uint8Array,
      algorithm: { name: "PBKDF2" },
      extractable: false,
      keyUsages: ["deriveBits"]
    ): Promise<unknown>;
    deriveBits(
      algorithm: {
        name: "PBKDF2";
        hash: "SHA-256";
        salt: Uint8Array;
        iterations: number;
      },
      baseKey: unknown,
      length: number
    ): Promise<ArrayBuffer>;
  };
}

export function isPbkdf2PasswordHash(encodedHash: string): boolean {
  return encodedHash.startsWith(`${VERSION}$`);
}

export async function hashPbkdf2Password(password: string): Promise<string> {
  assertPasswordInputLength(password);
  const salt = getWebCrypto().getRandomValues(new Uint8Array(SALT_LENGTH));
  const hash = await derivePbkdf2(password, salt, ITERATIONS, HASH_LENGTH);
  return `${VERSION}$${ITERATIONS}$${encodeBase64Url(salt)}$${encodeBase64Url(hash)}`;
}

export async function verifyPbkdf2Password(
  password: string,
  encodedHash: string
): Promise<boolean> {
  if (isPasswordInputTooLong(password)) {
    return false;
  }

  try {
    const parsed = parsePbkdf2Hash(encodedHash);
    const actual = await derivePbkdf2(
      password,
      parsed.salt,
      parsed.iterations,
      parsed.hash.length
    );
    return equalBytes(actual, parsed.hash);
  } catch {
    return false;
  }
}

export function pbkdf2PasswordNeedsRehash(encodedHash: string): boolean {
  try {
    const parsed = parsePbkdf2Hash(encodedHash);
    return (
      parsed.iterations !== ITERATIONS ||
      parsed.salt.length !== SALT_LENGTH ||
      parsed.hash.length !== HASH_LENGTH
    );
  } catch {
    return true;
  }
}

async function derivePbkdf2(
  password: string,
  salt: Uint8Array,
  iterations: number,
  hashLength: number
): Promise<Uint8Array> {
  const webCrypto = getWebCrypto();
  const key = await webCrypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await webCrypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    key,
    hashLength * 8
  );
  return new Uint8Array(bits);
}

function parsePbkdf2Hash(encodedHash: string): ParsedPbkdf2Hash {
  const parts = encodedHash.split("$");
  if (parts.length !== 4 || parts[0] !== VERSION) {
    throw new Error("Invalid PBKDF2 hash format.");
  }

  const iterations = parseInteger(parts[1]);
  const saltValue = parts[2] ?? "";
  const hashValue = parts[3] ?? "";
  const salt = decodeBase64Url(saltValue);
  const hash = decodeBase64Url(hashValue);
  if (
    iterations < MIN_ITERATIONS ||
    iterations > MAX_ITERATIONS ||
    salt.length < SALT_LENGTH ||
    salt.length > MAX_ENCODED_PART_LENGTH ||
    hash.length < HASH_LENGTH ||
    hash.length > MAX_ENCODED_PART_LENGTH ||
    encodeBase64Url(salt) !== saltValue ||
    encodeBase64Url(hash) !== hashValue
  ) {
    throw new Error("Unsupported PBKDF2 parameters.");
  }
  return { iterations, salt, hash };
}

function getWebCrypto(): WebCryptoLike {
  const candidate = (globalThis as { crypto?: WebCryptoLike }).crypto;
  if (!candidate?.subtle || typeof candidate.getRandomValues !== "function") {
    throw new Error("Web Crypto is required for PBKDF2 password hashing.");
  }
  return candidate;
}

function parseInteger(value: string | undefined): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error("Invalid integer.");
  }
  return parsed;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
