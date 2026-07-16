import type { CryptoKey, JWK, JWTPayload } from "jose";
import { decodeBase64Url, encodeBase64Url } from "./encoding.js";
import type {
  AuthorizationServerPreviousSigningKeyInput,
  AuthorizationServerSigningKeyInput
} from "./authorization-server-types.js";

const signingAlgorithm = "RS256";
type JoseModule = typeof import("jose");
let joseModule: Promise<JoseModule> | null = null;

export interface AuthorizationServerSigningKeys {
  current: AuthorizationServerSigningKeyInput;
  previous: readonly AuthorizationServerPreviousSigningKeyInput[];
}

interface LoadedSigningKeys {
  privateKey: CryptoKey;
  currentPublicJwk: JWK;
  previousPublicJwks: JWK[];
}

export class AuthorizationServerSigner {
  private readonly keys: AuthorizationServerSigningKeys;
  private loading: Promise<LoadedSigningKeys> | null = null;

  constructor(keys: AuthorizationServerSigningKeys) {
    validateSigningKeyIds(keys);
    this.keys = keys;
  }

  async signIdToken(payload: JWTPayload): Promise<string> {
    const [jose, loaded] = await Promise.all([loadJose(), this.load()]);
    return new jose.SignJWT(payload)
      .setProtectedHeader({
        alg: signingAlgorithm,
        kid: this.keys.current.id,
        typ: "JWT"
      })
      .sign(loaded.privateKey);
  }

  async jwks(): Promise<{ keys: JWK[] }> {
    const loaded = await this.load();
    return {
      keys: [loaded.currentPublicJwk, ...loaded.previousPublicJwks]
        .map((key) => ({ ...key }))
    };
  }

  private load(): Promise<LoadedSigningKeys> {
    this.loading ??= loadSigningKeys(this.keys);
    return this.loading;
  }
}

export async function calculateAccessTokenHash(accessToken: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(accessToken))
  );
  return encodeBase64Url(digest.slice(0, digest.length / 2));
}

async function loadSigningKeys(
  keys: AuthorizationServerSigningKeys
): Promise<LoadedSigningKeys> {
  const jose = await loadJose();
  const privateKey = await jose.importPKCS8(
    keys.current.privateKey,
    signingAlgorithm,
    { extractable: true }
  );
  const privateJwk = await jose.exportJWK(privateKey);
  const currentPublicJwk = publicRsaJwk(privateJwk, keys.current.id);
  const previousPublicJwks = await Promise.all(
    keys.previous.map(async (key) =>
      publicRsaJwk(await jose.exportJWK(
        await jose.importSPKI(key.publicKey, signingAlgorithm, { extractable: true })
      ), key.id)
    )
  );
  return { privateKey, currentPublicJwk, previousPublicJwks };
}

function loadJose(): Promise<JoseModule> {
  joseModule ??= import("jose");
  return joseModule;
}

function publicRsaJwk(jwk: JWK, id: string): JWK {
  if (jwk.kty !== "RSA" || !jwk.n || !jwk.e) {
    throw new Error("Authorization server signing keys must be RSA keys");
  }
  if (decodeBase64Url(jwk.n).byteLength < 256) {
    throw new Error("Authorization server RSA signing keys must be at least 2048 bits");
  }
  return {
    kty: "RSA",
    n: jwk.n,
    e: jwk.e,
    alg: signingAlgorithm,
    use: "sig",
    kid: id
  };
}

function validateSigningKeyIds(keys: AuthorizationServerSigningKeys): void {
  const ids = new Set<string>();
  for (const key of [keys.current, ...keys.previous]) {
    const id = key.id.trim();
    if (!id || id !== key.id || id.length > 64) {
      throw new Error("Authorization server signing key IDs must be 1 to 64 characters");
    }
    if (ids.has(id)) {
      throw new Error(`Duplicate authorization server signing key ID: ${id}`);
    }
    ids.add(id);
  }
  if (!keys.current.privateKey.trim()) {
    throw new Error("authorizationServer.signingKeys.current.privateKey is required");
  }
  for (const key of keys.previous) {
    if (!key.publicKey.trim()) {
      throw new Error(
        `authorizationServer.signingKeys.previous public key is required for ${key.id}`
      );
    }
  }
}
