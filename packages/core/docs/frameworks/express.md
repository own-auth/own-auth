# Express

Use Own Auth from Express 5 routes. Complete the [Quickstart](https://own-auth.com/docs/quickstart) first so the shared `auth` instance and database tables are ready.

## Install

```bash
npm install own-auth express cookie-parser
npm install --save-dev @types/express @types/cookie-parser
```

## Complete Server

This server provides signup, signin, current-session, and signout routes. Express 5 forwards errors thrown by async handlers to the final error middleware.

```ts server.ts
import cookieParser from "cookie-parser";
import express, {
  type NextFunction,
  type Request,
  type Response,
} from "express";
import { AuthError } from "own-auth";

import { auth } from "./auth";

type Credentials = {
  email: string;
  password: string;
  name?: string;
};

const app = express();
const sessionCookieName = "own_auth_session";
const sessionCookieOptions = {
  httpOnly: true,
  path: "/",
  sameSite: "lax" as const,
  secure: process.env.NODE_ENV === "production",
};

app.use(express.json());
app.use(cookieParser());

function readSessionToken(request: Request): string | undefined {
  return request.cookies[sessionCookieName];
}

function setSessionCookie(
  response: Response,
  token: string,
  expires: Date,
) {
  response.cookie(sessionCookieName, token, {
    ...sessionCookieOptions,
    expires,
  });
}

app.post("/auth/signup", async (request, response) => {
  const result = await auth.signUpEmailPassword(
    request.body as Credentials,
  );

  setSessionCookie(response, result.sessionToken, result.session.expiresAt);
  return response.status(201).json({ user: result.user });
});

app.post("/auth/signin", async (request, response) => {
  const result = await auth.signInEmailPassword(
    request.body as Credentials,
  );

  setSessionCookie(response, result.sessionToken, result.session.expiresAt);
  return response.json({ user: result.user });
});

app.get("/auth/session", async (request, response) => {
  const sessionToken = readSessionToken(request);
  const current = sessionToken
    ? await auth.getCurrentSession(sessionToken)
    : null;

  if (!current) {
    return response.status(401).json({ error: "Unauthorized" });
  }

  return response.json({
    session: current.session,
    user: current.user,
  });
});

app.post("/auth/signout", async (request, response) => {
  const sessionToken = readSessionToken(request);

  if (sessionToken) {
    await auth.signOut(sessionToken);
  }

  response.clearCookie(sessionCookieName, sessionCookieOptions);
  return response.status(204).send();
});

app.use(
  (
    error: unknown,
    _request: Request,
    response: Response,
    _next: NextFunction,
  ) => {
    if (error instanceof AuthError) {
      return response.status(error.statusCode).json({
        error: {
          code: error.code,
          message: error.safeMessage,
        },
      });
    }

    console.error(error);
    return response.status(500).json({
      error: {
        code: "internal_error",
        message: "Authentication failed",
      },
    });
  },
);

app.listen(3000);
```

The browser receives only the `HttpOnly` session cookie. Raw session tokens are not returned in the JSON responses.
