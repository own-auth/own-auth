# Cloudflare D1

Use the D1 adapter when Own Auth runs in a Cloudflare Worker. Postgres remains the default setup; D1 is selected explicitly through the Worker's database binding.

## Configure Wrangler

Add a D1 binding and enable Node.js compatibility:

```jsonc
{
  "compatibility_flags": ["nodejs_compat"],
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "my-app-auth",
      "database_id": "your-d1-database-id",
      "migrations_dir": "migrations"
    }
  ]
}
```

## Generate migrations

Generate versioned D1 migration files into the directory configured in Wrangler:

```bash
npx own-auth generate --dialect d1 --out-dir migrations
```

Own Auth writes one numbered file per migration so Wrangler applies them in order. Running the command again leaves matching files unchanged and fails if an existing generated file was edited.

Apply the files with Wrangler:

```bash
npx wrangler d1 migrations apply DB --local
npx wrangler d1 migrations apply DB --remote
```

Wrangler owns migration tracking and applies each migration transactionally. Own Auth does not run D1 migrations while handling application requests.

## Create the auth instance

Pass the Worker's D1 binding to `createD1Persistence`:

```ts auth.ts
import {
  createOwnAuth,
  createPbkdf2PasswordHasher,
} from "own-auth";
import {
  createD1Persistence,
  type D1DatabaseLike,
} from "own-auth/d1";

interface Env {
  DB: D1DatabaseLike;
  OWN_AUTH_TOKEN_PEPPER: string;
}

export function createAuth(env: Env) {
  return createOwnAuth({
    ...createD1Persistence(env.DB),
    tokenPepper: env.OWN_AUTH_TOKEN_PEPPER,
    password: {
      hasher: createPbkdf2PasswordHasher(),
    },
  });
}
```

`createD1Persistence` supplies both `storage` and `rateLimitStore`, so authentication data and rate-limit counters use the same D1 database.

Cloudflare owns the D1 binding lifecycle. `auth.close()` has nothing to close when the application supplies D1 persistence.

The configured hasher uses PBKDF2-HMAC-SHA256 through native Web Crypto instead of running Own Auth's default JavaScript Argon2id implementation against the Worker's request CPU budget.

Existing Argon2id and scrypt hashes remain readable and are replaced with PBKDF2 after a successful sign in, but their first verification still runs the original algorithm. Reset existing passwords before moving entirely to a Worker that cannot complete that verification within its CPU limit.

## Use from a Worker

```ts worker.ts
import { createAuth } from "./auth";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const auth = createAuth(env);
    const sessionToken = request.headers.get("authorization")?.replace("Bearer ", "");
    const current = sessionToken
      ? await auth.getCurrentSession(sessionToken)
      : null;

    return Response.json({ user: current?.user ?? null });
  },
};
```

## Plugin migrations

Configured plugins must provide D1 SQL. Migration generation fails before deployment when one does not. See [Plugins](/docs/plugins) for the dialect-specific migration format.

## Storage format

The D1 adapter uses the same public Own Auth types and methods as Postgres. Internally, dates are stored as Unix milliseconds, booleans as `0` or `1`, JSON and string arrays as text, and passkey public keys as blobs. Conversion happens inside the adapter.
