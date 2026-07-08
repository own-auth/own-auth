import { createOwnAuth } from "own-auth";

const auth = createOwnAuth({
  exposeRawTokens: process.env.NODE_ENV !== "production",
  tokenPepper: process.env.OWN_AUTH_TOKEN_PEPPER
});

const signup = await auth.signUpEmailPassword({
  email: "user@example.com",
  password: "secure-password"
});

const organisation = await auth.createOrganisation({
  name: "Example Org",
  ownerUserId: signup.user.id
});

const apiKey = await auth.createApiKey({
  name: "Local script",
  organisationId: organisation.organisation.id,
  actorUserId: signup.user.id,
  scopes: ["read users"]
});

console.log({
  userId: signup.user.id,
  sessionToken: signup.sessionToken,
  organisationId: organisation.organisation.id,
  apiKey: apiKey.rawKey
});
