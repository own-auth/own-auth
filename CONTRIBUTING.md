# Contributing

Thanks for helping improve Own Auth.

## Setup

```bash
pnpm install
pnpm test
pnpm build
```

The API server requires Postgres:

```bash
createdb own_auth_dev
export DATABASE_URL=postgres://localhost:5432/own_auth_dev
psql "$DATABASE_URL" -f packages/core/migrations/001_initial.sql
pnpm dev
```

## Tests

Run everything:

```bash
pnpm test
```

Run the real Postgres integration test:

```bash
createdb own_auth_test
pnpm --filter own-auth test:integration
```

The integration test uses `OWN_AUTH_TEST_DATABASE_URL` first, then `DATABASE_URL`, then `postgres://localhost:5432/own_auth_test`.

## Pull Requests

- Keep changes small and focused.
- Add or update tests for auth behavior, storage behavior, or security-sensitive changes.
- Keep runtime storage durable. The API should require Postgres through `DATABASE_URL`.
- Do not commit secrets, `.env` files, or generated local databases.

## Release

Releases are maintainer operations. Prepare the release before publishing:

1. Set the same version in `package.json` and `packages/core/package.json`.
2. Add the matching base-version section to `CHANGELOG.md`.
3. Commit and push the release commit to `main`.
4. Make sure the working tree is clean and local `main` matches `origin/main`.

Stable versions use the `x.y.z` format and npm's `latest` tag:

```bash
pnpm release:stable
```

Prereleases use the `x.y.z-next.n` format and npm's `next` tag:

```bash
pnpm release:next
```

Both commands:

1. validate the channel, versions, changelog, branch, npm version, and Git tags
2. run the complete `release:check` suite
3. publish from `packages/core` with npm browser authentication
4. verify the exact npm version and dist-tag
5. create and push the matching annotated Git tag

A prerelease fails if publishing it changes npm's `latest` tag. npm package
versions cannot be overwritten.

### Release Recovery

If npm publishing succeeds but registry verification or Git tagging is interrupted,
do not publish the version again. Verify the published package:

```bash
pnpm release:verify
```

Then create or push the matching Git tag:

```bash
pnpm release:tag
```

The tag command is idempotent when the local and remote tags point to the release
commit. It fails instead of replacing a conflicting tag. Run recovery before moving
local `main` away from the published release commit.
