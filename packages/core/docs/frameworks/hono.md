# Hono

Use Own Auth from a Hono server running on Node.js. Complete the [Quickstart](https://own-auth.com/docs/quickstart) first so the shared `auth` instance and database tables are ready.

## Install

```bash
npm install own-auth hono @hono/node-server
```

## Complete Server

This server provides signup, signin, current-session, and signout routes using Hono's cookie helpers.

```ts server.ts
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import {
  deleteCookie,
  getCookie,
  setCookie,
} from "hono/cookie";
import { AuthError } from "own-auth";

import { auth } from "./auth";

type Credentials = {
  email: string;
  password: string;
  name?: string;
};

const app = new Hono();
const sessionCookieName = "own_auth_session";
const sessionCookieOptions = {
  httpOnly: true,
  path: "/",
  sameSite: "Lax" as const,
  secure: process.env.NODE_ENV === "production",
};

app.post("/auth/signup", async (context) => {
  const body = await context.req.json<Credentials>();
  const result = await auth.signUpEmailPassword(body);

  setCookie(context, sessionCookieName, result.sessionToken, {
    ...sessionCookieOptions,
    expires: result.session.expiresAt,
  });

  return context.json({ user: result.user }, 201);
});

app.post("/auth/signin", async (context) => {
  const body = await context.req.json<Credentials>();
  const result = await auth.signInEmailPassword(body);

  setCookie(context, sessionCookieName, result.sessionToken, {
    ...sessionCookieOptions,
    expires: result.session.expiresAt,
  });

  return context.json({ user: result.user });
});

app.get("/auth/session", async (context) => {
  const sessionToken = getCookie(context, sessionCookieName);
  const current = sessionToken
    ? await auth.getCurrentSession(sessionToken)
    : null;

  if (!current) {
    return context.json({ error: "Unauthorized" }, 401);
  }

  return context.json({
    session: current.session,
    user: current.user,
  });
});

app.post("/auth/signout", async (context) => {
  const sessionToken = getCookie(context, sessionCookieName);

  if (sessionToken) {
    await auth.signOut(sessionToken);
  }

  deleteCookie(context, sessionCookieName, {
    path: sessionCookieOptions.path,
    secure: sessionCookieOptions.secure,
  });

  return context.body(null, 204);
});

app.onError((error) => {
  if (error instanceof AuthError) {
    return Response.json(
      {
        error: {
          code: error.code,
          message: error.safeMessage,
        },
      },
      { status: error.statusCode },
    );
  }

  console.error(error);
  return Response.json(
    {
      error: {
        code: "internal_error",
        message: "Authentication failed",
      },
    },
    { status: 500 },
  );
});

serve({
  fetch: app.fetch,
  port: 3000,
});
```

The browser receives only the `HttpOnly` session cookie. Raw session tokens are not returned in the JSON responses.
