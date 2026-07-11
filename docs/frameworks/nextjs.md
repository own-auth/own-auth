# Next.js

Use Own Auth from Next.js App Router Route Handlers. Complete the [Quickstart](https://own-auth.com/docs/quickstart) first so the shared `auth` instance and database tables are ready.

The example exposes four routes:

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/auth/signup` | Create a user and session |
| `POST` | `/api/auth/signin` | Sign in and create a session |
| `GET` | `/api/auth/session` | Return the current user and session |
| `POST` | `/api/auth/signout` | Revoke the session and clear the cookie |

## Session Cookie

Keep cookie handling in one server-only helper. Next.js allows Route Handlers to read, set, and delete cookies through `cookies()`.

```ts lib/session-cookie.ts
import { cookies } from "next/headers";

const sessionCookieName = "own_auth_session";
const sessionCookieOptions = {
  httpOnly: true,
  path: "/",
  sameSite: "lax" as const,
  secure: process.env.NODE_ENV === "production",
};

export async function readSessionToken() {
  return (await cookies()).get(sessionCookieName)?.value;
}

export async function setSessionCookie(token: string, expires: Date) {
  (await cookies()).set(sessionCookieName, token, {
    ...sessionCookieOptions,
    expires,
  });
}

export async function clearSessionCookie() {
  (await cookies()).delete(sessionCookieName);
}
```

## Auth Errors

Return the safe status and message supplied by Own Auth. Unknown errors continue to Next.js error handling.

```ts lib/auth-error-response.ts
import { AuthError } from "own-auth";

export function authErrorResponse(error: unknown): Response {
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

  throw error;
}
```

## Sign Up

```ts app/api/auth/signup/route.ts
import { auth } from "@/auth";
import { authErrorResponse } from "@/lib/auth-error-response";
import { setSessionCookie } from "@/lib/session-cookie";

type SignUpBody = {
  email: string;
  password: string;
  name?: string;
};

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as SignUpBody;
    const result = await auth.signUpEmailPassword(body);

    await setSessionCookie(result.sessionToken, result.session.expiresAt);

    return Response.json({ user: result.user }, { status: 201 });
  } catch (error) {
    return authErrorResponse(error);
  }
}
```

## Sign In

```ts app/api/auth/signin/route.ts
import { auth } from "@/auth";
import { authErrorResponse } from "@/lib/auth-error-response";
import { setSessionCookie } from "@/lib/session-cookie";

type SignInBody = {
  email: string;
  password: string;
};

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as SignInBody;
    const result = await auth.signInEmailPassword(body);

    await setSessionCookie(result.sessionToken, result.session.expiresAt);

    return Response.json({ user: result.user });
  } catch (error) {
    return authErrorResponse(error);
  }
}
```

## Current Session

```ts app/api/auth/session/route.ts
import { auth } from "@/auth";
import { readSessionToken } from "@/lib/session-cookie";

export async function GET() {
  const sessionToken = await readSessionToken();
  const current = sessionToken
    ? await auth.getCurrentSession(sessionToken)
    : null;

  if (!current) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  return Response.json({
    session: current.session,
    user: current.user,
  });
}
```

## Sign Out

```ts app/api/auth/signout/route.ts
import { auth } from "@/auth";
import {
  clearSessionCookie,
  readSessionToken,
} from "@/lib/session-cookie";

export async function POST() {
  const sessionToken = await readSessionToken();

  if (sessionToken) {
    await auth.signOut(sessionToken);
  }

  await clearSessionCookie();
  return new Response(null, { status: 204 });
}
```

The browser receives only the `HttpOnly` session cookie. Raw session tokens are not returned in the JSON responses.
