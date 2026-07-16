import { AuthError } from "./errors.js";
import { decodeBase64Url, encodeBase64Url } from "./encoding.js";

export type EncryptionPurpose =
  | "totp"
  | "oauth-refresh"
  | "authorization-request";

export interface EncryptionKeyInput {
  id: string;
  key: string | Uint8Array;
}

export interface EncryptionKeyRingOptions {
  current: EncryptionKeyInput;
  previous?: EncryptionKeyInput[];
}

export interface EncryptedValue {
  ciphertext: string;
  nonce: string;
  encryptionKeyId: string;
}

export interface DecryptedValue {
  plaintext: string;
  needsRotation: boolean;
}

const purposeLabels: Record<EncryptionPurpose, string> = {
  totp: "own-auth:totp:v1",
  "oauth-refresh": "own-auth:oauth-refresh:v1",
  "authorization-request": "own-auth:authorization-request:v1"
};

export class EncryptionKeyRing {
  readonly currentKeyId: string;
  private readonly keys: ReadonlyMap<string, Uint8Array>;

  constructor(options: EncryptionKeyRingOptions) {
    const entries = [options.current, ...(options.previous ?? [])];
    const keys = new Map<string, Uint8Array>();
    for (const entry of entries) {
      validateKeyId(entry.id);
      if (keys.has(entry.id)) {
        throw new Error(`Duplicate encryption key ID: ${entry.id}`);
      }
      keys.set(entry.id, decodeKey(entry.key));
    }
    this.currentKeyId = options.current.id;
    this.keys = keys;
  }

  async encrypt(
    plaintext: string,
    purpose: EncryptionPurpose,
    metadata: Record<string, string>
  ): Promise<EncryptedValue> {
    const rawKey = this.keys.get(this.currentKeyId);
    if (!rawKey) {
      throw unavailableKey();
    }
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const key = await derivePurposeKey(rawKey, purpose);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: authenticatedMetadata(metadata) },
      key,
      new TextEncoder().encode(plaintext)
    );
    return {
      ciphertext: encodeBase64Url(new Uint8Array(ciphertext)),
      nonce: encodeBase64Url(nonce),
      encryptionKeyId: this.currentKeyId
    };
  }

  async decrypt(
    value: EncryptedValue,
    purpose: EncryptionPurpose,
    metadata: Record<string, string>
  ): Promise<DecryptedValue> {
    const rawKey = this.keys.get(value.encryptionKeyId);
    if (!rawKey) {
      throw unavailableKey();
    }
    try {
      const key = await derivePurposeKey(rawKey, purpose);
      const plaintext = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: decodeBase64Url(value.nonce),
          additionalData: authenticatedMetadata(metadata)
        },
        key,
        decodeBase64Url(value.ciphertext)
      );
      return {
        plaintext: new TextDecoder().decode(plaintext),
        needsRotation: value.encryptionKeyId !== this.currentKeyId
      };
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError("encrypted_data_invalid", "Encrypted authentication data is invalid", 500);
    }
  }
}

export function createEncryptionKeyRing(
  options?: EncryptionKeyRingOptions
): EncryptionKeyRing | null {
  return options ? new EncryptionKeyRing(options) : null;
}

export function requireEncryptionKeyRing(
  keyRing: EncryptionKeyRing | null,
  feature: string
): EncryptionKeyRing {
  if (!keyRing) {
    throw new AuthError(
      "encryption_not_configured",
      `${feature} requires encryption configuration`,
      500
    );
  }
  return keyRing;
}

function validateKeyId(id: string): void {
  if (id.trim().length === 0 || id.length > 64) {
    throw new Error("Encryption key IDs must be non-empty and at most 64 characters");
  }
}

function decodeKey(value: string | Uint8Array): Uint8Array {
  const key = typeof value === "string" ? decodeBase64Url(value) : new Uint8Array(value);
  if (key.byteLength !== 32) {
    throw new Error("Encryption keys must contain exactly 32 bytes");
  }
  return key;
}

async function derivePurposeKey(
  rawKey: Uint8Array,
  purpose: EncryptionPurpose
) {
  const keyMaterial = await crypto.subtle.importKey("raw", rawKey, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: new TextEncoder().encode(purposeLabels[purpose])
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function authenticatedMetadata(metadata: Record<string, string>): Uint8Array {
  const sorted = Object.fromEntries(
    Object.entries(metadata).sort(([left], [right]) => left.localeCompare(right))
  );
  return new TextEncoder().encode(JSON.stringify(sorted));
}

function unavailableKey(): AuthError {
  return new AuthError(
    "encryption_key_unavailable",
    "The required authentication encryption key is unavailable",
    500
  );
}
