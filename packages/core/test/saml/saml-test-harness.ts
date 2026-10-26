import {
  createOwnAuth,
  InMemoryAuthStorage,
  type Organisation,
  type OwnAuth,
  type PublicSamlConnection,
  type SamlCompletionResult,
  type SamlProvider
} from "../../src/index.js";
import type { SamlVerifiedAssertion } from "../../src/saml.js";
import { completeSamlResponse } from "../../src/saml-internals.js";
import { SamlProtocolError } from "../../src/saml.js";

export interface SamlTestHarness {
  auth: OwnAuth;
  storage: InMemoryAuthStorage;
  provider: FakeSamlProvider;
  ownerId: string;
  organisation: Organisation;
  connection: PublicSamlConnection;
  complete(): Promise<SamlCompletionResult>;
}

export async function createSamlHarness(): Promise<SamlTestHarness> {
  const storage = new InMemoryAuthStorage();
  const provider = new FakeSamlProvider();
  const auth = createOwnAuth({
    storage,
    saml: provider,
    scim: {},
    tokenPepper: "saml-test-pepper",
    baseUrl: "https://app.example.com",
    redirectAllowlist: ["https://app.example.com"]
  });
  const owner = await auth.signUpEmailPassword({
    email: "owner@example.com",
    password: "secure-password"
  });
  const { organisation } = await auth.createOrganisation({
    name: "Acme",
    ownerUserId: owner.user.id
  });
  const connection = await auth.saml.createConnection({
    organisationId: organisation.id,
    actorUserId: owner.user.id,
    name: "Acme Identity",
    idpEntityId: "https://idp.example.com/metadata",
    ssoUrl: "https://idp.example.com/sso",
    idpCertificates: ["trusted-certificate"],
    attributeMapping: { email: "email", name: "name" },
    jitProvisioning: { enabled: true, defaultRole: "member" }
  });
  return {
    auth,
    storage,
    provider,
    ownerId: owner.user.id,
    organisation,
    connection,
    complete: () => provider.complete(auth)
  };
}

export class FakeSamlProvider implements SamlProvider {
  readonly kind = "own-auth-saml" as const;
  readonly basePath = "/api/auth";
  readonly clockSkewMs = 120_000;
  readonly responseTtlMs = 300_000;
  requestId: string | null = null;
  relayState: string | null = null;
  assertionNumber = 0;
  assertionId: string | null = null;
  failure: Error | null = null;
  email = "saml.user@example.com";
  nameId = "subject-123";

  async createAuthorizeUrl(input: Parameters<SamlProvider["createAuthorizeUrl"]>[0]) {
    this.requestId = input.requestId;
    this.relayState = input.relayState;
    return `https://idp.example.com/sso?RelayState=${encodeURIComponent(input.relayState)}`;
  }

  async verifyResponse(input: Parameters<SamlProvider["verifyResponse"]>[0]) {
    if (this.failure) throw this.failure;
    const requestId = required(this.requestId);
    if (!input.acceptsRequestId(requestId)) {
      throw new SamlProtocolError("saml_response_invalid", "Request does not match");
    }
    this.assertionNumber += 1;
    return {
      assertionId: this.assertionId ?? `_assertion_${this.assertionNumber}`,
      issuer: input.connection.idpEntityId,
      nameId: this.nameId,
      attributes: {
        email: this.email,
        name: "SAML User"
      },
      inResponseTo: requestId,
      recipient: input.connection.acsUrl,
      expiresAt: new Date(Date.now() + 300_000)
    } satisfies SamlVerifiedAssertion;
  }

  createMetadata(connection: Parameters<SamlProvider["createMetadata"]>[0]): string {
    return `<EntityDescriptor ID="${connection.spEntityId}" data-connection="${connection.idpEntityId}"/>`;
  }

  complete(auth: OwnAuth): Promise<SamlCompletionResult> {
    return auth.saml[completeSamlResponse]({
      samlResponse: "signed-response",
      relayState: required(this.relayState)
    });
  }
}

export function required<Value>(value: Value | null): Value {
  if (value === null) throw new Error("Expected test value");
  return value;
}
