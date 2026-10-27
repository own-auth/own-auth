import { generateKeyPairSync } from "node:crypto";
import { signXml } from "@node-saml/node-saml/lib/xml.js";
import { describe, expect, it } from "vitest";
import { SamlProtocolError } from "../../src/saml-protocol-error.js";
import { createSaml } from "../../src/saml.js";
import type { SamlProtocolConnection } from "../../src/saml-types.js";

const acsUrl = "https://app.example.com/api/auth/saml/acs";
const idpEntityId = "https://idp.example.com/metadata";
const requestId = "_request_123";
const spEntityId = "https://app.example.com/api/auth/saml/metadata";

const trustedKeys = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" }
});
const attackerKeys = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" }
});

const connection: SamlProtocolConnection = {
  acsUrl,
  idpCertificates: [trustedKeys.publicKey],
  idpEntityId,
  spEntityId,
  ssoUrl: "https://idp.example.com/sso"
};

describe("SAML protocol qualification", () => {
  it("accepts a response signed by the configured IdP key", async () => {
    const result = await verify(signResponse(responseXml()));

    expect(result.nameId).toBe("subject-123");
    expect(result.attributes.email).toBe("user@example.com");
  });

  it("accepts an assertion signed by the configured IdP key", async () => {
    const result = await verify(signAssertion(responseXml()));

    expect(result.assertionId).toBe("_assertion_123");
    expect(result.attributes.name).toBe("Test User");
  });

  it("accepts the active certificate during IdP key rotation", async () => {
    const result = await createSaml().verifyResponse({
      acceptsRequestId: (value) => value === requestId,
      connection: {
        ...connection,
        idpCertificates: [attackerKeys.publicKey, trustedKeys.publicKey]
      },
      requestCreatedAt: new Date(),
      samlResponse: encode(signAssertion(responseXml()))
    });

    expect(result.nameId).toBe("subject-123");
  });

  it("rejects unsigned assertion substitution", async () => {
    const signed = signAssertion(responseXml());
    const maliciousAssertion = assertionXml({
      assertionId: "_attacker_assertion",
      email: "attacker@example.com"
    });
    const wrapped = signed.replace("</samlp:Response>", `${maliciousAssertion}</samlp:Response>`);

    await expect(verify(wrapped)).rejects.toMatchObject({
      code: "saml_response_invalid"
    });
  });

  it("rejects duplicate XML IDs before signature verification", async () => {
    const duplicated = responseXml().replace(
      'ID="_assertion_123"',
      'ID="_response_123"'
    );

    await expect(verify(duplicated)).rejects.toThrow("duplicate ID");
  });

  it("rejects a signed assertion whose XML end tag contains trailing content", async () => {
    const signed = signAssertion(responseXml());
    const malformed = signed.replace("</saml:NameID>", "</saml:NameID\n trailing>");
    await expect(verify(malformed)).rejects.toThrow("not valid XML");
  });

  it("rejects duplicate XML attributes before signature verification", async () => {
    const malformed = responseXml().replace('Version="2.0"', 'Version="2.0" Version="2.0"');
    await expect(verify(malformed)).rejects.toThrow("not valid XML");
  });

  it("ignores embedded key information and enforces the configured IdP key", async () => {
    const signedByAttacker = signAssertion(responseXml(), attackerKeys);

    await expect(verify(signedByAttacker)).rejects.toMatchObject({
      code: "saml_response_invalid"
    });
  });

  it("preserves text across XML comments instead of truncating the identity", async () => {
    const result = await verify(
      signAssertion(responseXml({ email: "admin@example.com<!-- -->.evil" }))
    );

    expect(result.attributes.email).toBe("admin@example.com.evil");
  });

  it("rejects critical elements in an unexpected namespace", async () => {
    const malformed = responseXml().replace(
      "<saml:NameID>",
      '<saml:NameID xmlns:saml="urn:attacker">'
    );

    await expect(verify(malformed)).rejects.toThrow("invalid namespace");
  });

  it("rejects DTD and entity declarations before XML parsing", async () => {
    const xml = responseXml().replace(
      "<samlp:Response",
      '<!DOCTYPE x [<!ENTITY secret "subject-123">]><samlp:Response'
    );

    await expect(verify(xml)).rejects.toThrow("forbidden document declaration");
  });

  it("rejects SHA-1 signatures with a specific server-side diagnostic", async () => {
    const weak = signAssertion(responseXml(), trustedKeys, "sha1");

    await expect(verify(weak)).rejects.toEqual(
      expect.objectContaining<Pick<SamlProtocolError, "code">>({
        code: "saml_signature_algorithm_unsupported"
      })
    );
  });

  it("rejects decoded responses over the configured size limit", async () => {
    const provider = createSaml({ maxResponseBytes: 128 });

    await expect(
      provider.verifyResponse({
        acceptsRequestId: (value) => value === requestId,
        connection,
        requestCreatedAt: new Date(),
        samlResponse: encode(responseXml())
      })
    ).rejects.toThrow("size limit");
  });
});

async function verify(xml: string) {
  return createSaml().verifyResponse({
    acceptsRequestId: (value) => value === requestId,
    connection,
    requestCreatedAt: new Date(),
    samlResponse: encode(xml)
  });
}

function signResponse(xml: string): string {
  return sign(xml, "Response", trustedKeys);
}

function signAssertion(
  xml: string,
  keys = trustedKeys,
  algorithm: "sha1" | "sha256" = "sha256"
): string {
  return sign(xml, "Assertion", keys, algorithm);
}

function sign(
  xml: string,
  element: "Assertion" | "Response",
  keys: typeof trustedKeys,
  algorithm: "sha1" | "sha256" = "sha256"
): string {
  return signXml(
    xml,
    `//*[local-name(.)='${element}']`,
    {
      action: "after",
      reference: `//*[local-name(.)='${element}']/*[local-name(.)='Issuer']`
    },
    {
      digestAlgorithm: algorithm,
      privateKey: keys.privateKey,
      publicCert: keys.publicKey,
      signatureAlgorithm: algorithm
    }
  );
}

function responseXml(options: { email?: string } = {}): string {
  const now = new Date();
  const issueInstant = now.toISOString();
  const notBefore = new Date(now.getTime() - 60_000).toISOString();
  const notOnOrAfter = new Date(now.getTime() + 5 * 60_000).toISOString();
  return [
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response_123" Version="2.0" IssueInstant="${issueInstant}" Destination="${acsUrl}" InResponseTo="${requestId}">`,
    `<saml:Issuer>${idpEntityId}</saml:Issuer>`,
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>',
    assertionXml({
      email: options.email,
      issueInstant,
      notBefore,
      notOnOrAfter
    }),
    "</samlp:Response>"
  ].join("");
}

function assertionXml(options: {
  assertionId?: string;
  email?: string;
  issueInstant?: string;
  notBefore?: string;
  notOnOrAfter?: string;
} = {}): string {
  const issueInstant = options.issueInstant ?? new Date().toISOString();
  const notBefore = options.notBefore ?? new Date(Date.now() - 60_000).toISOString();
  const notOnOrAfter =
    options.notOnOrAfter ?? new Date(Date.now() + 5 * 60_000).toISOString();
  return [
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${options.assertionId ?? "_assertion_123"}" Version="2.0" IssueInstant="${issueInstant}">`,
    `<saml:Issuer>${idpEntityId}</saml:Issuer>`,
    "<saml:Subject>",
    "<saml:NameID>subject-123</saml:NameID>",
    '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">',
    `<saml:SubjectConfirmationData InResponseTo="${requestId}" Recipient="${acsUrl}" NotOnOrAfter="${notOnOrAfter}"/>`,
    "</saml:SubjectConfirmation>",
    "</saml:Subject>",
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">`,
    `<saml:AudienceRestriction><saml:Audience>${spEntityId}</saml:Audience></saml:AudienceRestriction>`,
    "</saml:Conditions>",
    `<saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="_session_123">`,
    '<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>',
    "</saml:AuthnStatement>",
    "<saml:AttributeStatement>",
    `<saml:Attribute Name="email"><saml:AttributeValue>${options.email ?? "user@example.com"}</saml:AttributeValue></saml:Attribute>`,
    '<saml:Attribute Name="name"><saml:AttributeValue>Test User</saml:AttributeValue></saml:Attribute>',
    "</saml:AttributeStatement>",
    "</saml:Assertion>"
  ].join("");
}

function encode(xml: string): string {
  return Buffer.from(xml, "utf8").toString("base64");
}
