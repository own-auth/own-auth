export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

export function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+={0,2}$/u.test(value) || value.length % 4 === 1) {
    throw new Error("Invalid base64url value");
  }
  const unpadded = value.replace(/=+$/u, "");
  const padded = unpadded
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(unpadded.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function encodeHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function encodeOAuthBasicCredentials(
  identifier: string,
  secret: string
): string {
  return `Basic ${btoa(`${encodeURIComponent(identifier)}:${encodeURIComponent(secret)}`)}`;
}
