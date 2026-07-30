import { describe, expect, it } from "vitest";
import { readAuthorizationClientCredentials } from "../src/authorization-server-http-input.js";
import { encodeOAuthBasicCredentials } from "../src/encoding.js";

describe("OAuth HTTP Basic credentials", () => {
  it("round-trips application/x-www-form-urlencoded client credentials", () => {
    const request = new Request("https://auth.example.com/oauth/token", {
      headers: {
        authorization: encodeOAuthBasicCredentials(
          "client id+plus",
          "secret value+plus"
        )
      }
    });

    expect(readAuthorizationClientCredentials(request, new URLSearchParams())).toEqual({
      clientId: "client id+plus",
      clientSecret: "secret value+plus",
      clientAuthenticationMethod: "client_secret_basic"
    });
  });

  it("decodes standards-compliant plus and percent encoding from other clients", () => {
    const credentials = btoa("client+id:secret%2Bvalue");
    const request = new Request("https://auth.example.com/oauth/token", {
      headers: { authorization: `Basic ${credentials}` }
    });

    expect(readAuthorizationClientCredentials(request, new URLSearchParams())).toEqual({
      clientId: "client id",
      clientSecret: "secret+value",
      clientAuthenticationMethod: "client_secret_basic"
    });
  });
});
