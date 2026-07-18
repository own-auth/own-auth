import type { AuthEngineContext } from "./auth-engine-context.js";
import type { StoredDeviceAuthorizationRequest } from "./authorization-server-device-types.js";
import { requireEncryptionKeyRing } from "./encryption.js";

const feature = "OAuth device authorization server";
const purpose = "authorization-request";

export function encryptDeviceAuthorizationRequest(
  ctx: AuthEngineContext,
  deviceAuthorizationId: string,
  authorizationClientId: string,
  request: StoredDeviceAuthorizationRequest
) {
  return requireEncryptionKeyRing(ctx.encryption, feature).encrypt(
    JSON.stringify(request),
    purpose,
    metadata(deviceAuthorizationId, authorizationClientId)
  );
}

export async function decryptDeviceAuthorizationRequest(
  ctx: AuthEngineContext,
  input: {
    id: string;
    authorizationClientId: string;
    requestCiphertext: string;
    requestNonce: string;
    encryptionKeyId: string;
  }
): Promise<StoredDeviceAuthorizationRequest> {
  const decrypted = await requireEncryptionKeyRing(ctx.encryption, feature).decrypt(
    {
      ciphertext: input.requestCiphertext,
      nonce: input.requestNonce,
      encryptionKeyId: input.encryptionKeyId
    },
    purpose,
    metadata(input.id, input.authorizationClientId)
  );
  return JSON.parse(decrypted.plaintext) as StoredDeviceAuthorizationRequest;
}

function metadata(
  deviceAuthorizationId: string,
  authorizationClientId: string
) {
  return {
    authorizationClientId,
    deviceAuthorizationId,
    recordType: "device_authorization_request"
  };
}
