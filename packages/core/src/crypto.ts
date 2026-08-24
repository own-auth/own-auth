import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual
} from "node:crypto";

export {
  hashPassword,
  passwordNeedsRehash,
  verifyPassword
} from "./password-hashing.js";

export function randomBase64Url(byteLength = 32): string {
  return randomBytes(byteLength).toString("base64url");
}

export function randomNumericCode(length = 6): string {
  const digits: string[] = [];

  while (digits.length < length) {
    const value = randomBytes(1)[0] ?? 0;
    if (value < 250) {
      digits.push(String(value % 10));
    }
  }

  return digits.join("");
}

export function createId(prefix: string): string {
  return `${prefix}_${randomBase64Url(16)}`;
}

export function createUuidV7(now = Date.now()): string {
  const bytes = randomBytes(16);
  let timestamp = BigInt(now);
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(timestamp & 0xffn);
    timestamp >>= 8n;
  }
  bytes[6] = 0x70 | ((bytes[6] ?? 0) & 0x0f);
  bytes[8] = 0x80 | ((bytes[8] ?? 0) & 0x3f);
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-` +
    `${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function hashSecret(secret: string, pepper?: string): string {
  if (pepper && pepper.length > 0) {
    return createHmac("sha256", pepper).update(secret).digest("hex");
  }

  return createHash("sha256").update(secret).digest("hex");
}

export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);

  return left.length === right.length && timingSafeEqual(left, right);
}
