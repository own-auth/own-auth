import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createServer } from "node:https";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createRequire } from "node:module";
import { createOwnAuth, createOwnAuthHandler, InMemoryAuthStorage } from "../packages/core/dist/index.js";

// Supply a package.json beside an existing Playwright installation when it is external to this workspace.
const playwright = createRequire(resolve(process.argv[2] ?? "package.json"))("playwright");
const directory = await mkdtemp(join(tmpdir(), "own-auth-browser-"));
const results = [];
try {
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-keyout", join(directory, "key.pem"), "-out", join(directory, "cert.pem"),
    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"
  ], { stdio: "ignore" });
  const tls = {
    key: await readFile(join(directory, "key.pem")),
    cert: await readFile(join(directory, "cert.pem"))
  };
  for (const engine of ["chromium", "firefox", "webkit"]) {
    const browser = await playwright[engine].launch({ headless: true });
    try {
      for (const width of [1280, 390]) {
        const scenarios = [
          { provider: "google" }, { provider: "github" }, { provider: "apple" },
          { provider: "apple", post: true }, { provider: "google", link: true },
          { provider: "google", popup: true }, { provider: "apple", post: true, popup: true },
          { provider: "google", parallel: true }
        ];
        for (const scenario of scenarios) {
          try {
            await runScenario(browser, tls, width, scenario);
          } catch (cause) {
            throw new Error(`Browser scenario failed: ${JSON.stringify({ engine, width, ...scenario })}`, { cause });
          }
          results.push({ engine, version: browser.version(), width, ...scenario });
        }
      }
    } finally {
      await browser.close();
    }
  }
  console.log(JSON.stringify({ passed: results.length, failures: 0, results }, null, 2));
} finally {
  await rm(directory, { recursive: true, force: true });
}

async function runScenario(browser, tls, width, scenario) {
  const fixture = await createFixture(tls, scenario);
  const contexts = await Promise.all([0, 1].map(() => browser.newContext({
    ignoreHTTPSErrors: true, viewport: { width, height: 900 }
  })));
  const errors = [];
  for (const context of contexts) {
    context.on("page", (page) => page.on("pageerror", (error) => errors.push(error.message)));
  }
  try {
    const [page, other] = await Promise.all(contexts.map((context) => context.newPage()));
    await Promise.all([page.goto(fixture.origin), other.goto(fixture.origin)]);
    let actor;
    if (scenario.link) {
      actor = await page.evaluate(async () => {
        const response = await fetch("/api/auth/sign-up/email", {
          method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ email: "link-owner@example.test", password: "correct-horse" })
        });
        return { status: response.status, body: await response.json() };
      });
      assert.equal(actor.status, 200, "browser signup establishes the linking session");
    }
    const start = async () => {
      const result = await page.evaluate(async (input) => {
        const response = await fetch("/api/auth/oauth/start", {
          method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(input)
        });
        return { status: response.status, body: await response.json() };
      }, {
        provider: scenario.provider, intent: scenario.link ? "link" : "sign_in",
        mode: scenario.popup ? "popup" : "redirect",
        ...(scenario.popup ? { openerOrigin: fixture.origin } : {})
      });
      assert.equal(result.status, 200, JSON.stringify(result.body));
      const state = new URL(result.body.url).searchParams.get("state");
      const name = `__Host-own_auth_oauth_${state}`;
      const cookie = (await contexts[0].cookies(fixture.origin)).find((candidate) => candidate.name === name);
      assert.ok(cookie, "browser accepts the proof cookie");
      assert.equal(cookie.httpOnly, true);
      assert.equal(cookie.secure, true);
      assert.equal(cookie.sameSite, "None");
      assert.equal(cookie.path, "/");
      assert.ok(cookie.expires > Date.now() / 1000);
      assert.equal(await page.evaluate((key) => document.cookie.includes(key), name), false);
      return { url: result.body.url, state, name };
    };
    const first = await start();
    const pending = scenario.parallel ? [await start(), first] : [first];

    // Profile B receives the exact provider callback, but has no initiating cookie.
    await other.goto(first.url);
    const rejected = other.waitForResponse((response) => response.url().includes("/callback"));
    await other.getByText("Continue", { exact: true }).click();
    assert.equal((await rejected).status(), 400);
    assert.equal(fixture.exchanges.length, 0);
    assert.equal((await contexts[1].cookies()).some((cookie) => cookie.name === "own_auth_session"), false);
    assert.equal((await fixture.storage.listUsers()).length, scenario.link ? 1 : 0);

    for (const transaction of pending) {
      if (scenario.popup) {
        await page.evaluate((url) => { document.querySelector("a").href = url; }, transaction.url);
        const opened = page.waitForEvent("popup");
        await page.getByText("Open provider", { exact: true }).click();
        const popup = await opened;
        await popup.getByText("Continue", { exact: true }).click();
        await page.waitForFunction(() => window.messages.length === 1);
        const messages = await page.evaluate(() => window.messages);
        assert.equal(messages[0].origin, fixture.origin);
        assert.equal(messages[0].data.source, "own-auth");
        assert.equal(messages[0].data.status, "complete");
        assert.equal(await other.evaluate(() => window.messages?.length ?? 0), 0);
      } else {
        await page.goto(transaction.url);
        const completed = page.waitForResponse((response) => response.url().includes("/callback"));
        await page.getByText("Continue", { exact: true }).click();
        const response = await completed;
        assert.ok(response.status() < 400, `callback returned ${response.status()}`);
        assert.equal(new URL(response.headers().location).searchParams.get("own_auth_status"),
          scenario.link ? "linked" : "complete", response.headers().location);
        await page.waitForURL((url) => url.searchParams.get("own_auth_status") === (scenario.link ? "linked" : "complete"));
      }
      const callback = fixture.callbacks.findLast((entry) => entry.state === transaction.state);
      assert.equal(callback.method, scenario.post ? "POST" : "GET");
      assert.equal(callback.cookieSent, true, "real navigation delivers the proof cookie");
      assert.ok(callback.setCookies.some((value) => value.startsWith(`${transaction.name}=;`) && value.includes("Max-Age=0")));
      const cookies = await contexts[0].cookies(fixture.origin);
      assert.equal(cookies.some((cookie) => cookie.name === transaction.name), false, "completed proof cookie removed");
      if (scenario.parallel && transaction !== first) {
        assert.equal(cookies.some((cookie) => cookie.name === first.name), true, "other attempt remains usable");
      }
      const account = await fixture.storage.getAccountByProvider(scenario.provider, transaction.state);
      assert.ok(account, "callback links the proved provider account");
      if (scenario.link) assert.equal(account.userId, actor.body.user.id);
      else {
        const sessionCookie = cookies.find((cookie) => cookie.name === "own_auth_session");
        assert.ok(sessionCookie, "browser accepts the session cookie");
        const current = await fixture.auth.getCurrentSession(decodeURIComponent(sessionCookie.value));
        assert.equal(current?.user.id, account.userId);
      }
    }
    assert.deepEqual(errors, [], "no browser script errors");
  } finally {
    await Promise.all(contexts.map((context) => context.close()));
    await fixture.close();
  }
}

async function createFixture(tls, scenario) {
  const storage = new InMemoryAuthStorage();
  const exchanges = [];
  const callbacks = [];
  let origin;
  let providerOrigin;
  let auth;
  let handler;
  const options = {
    storage, tokenPepper: "local-browser-fixture",
    encryption: { current: { id: "test", key: new Uint8Array(32).fill(4) } },
    oauth: { adapters: [{
      provider: scenario.provider, redirectUri: "https://localhost/unused", offlineAccess: false,
      async createAuthorizationUrl({ state }) {
        return new URL(`/authorize?state=${state}`, providerOrigin);
      },
      async exchangeCode({ callbackParameters }) {
        const state = callbackParameters.get("state");
        exchanges.push(state);
        return {
          identity: { provider: scenario.provider, providerAccountId: state,
            email: `browser-${state.slice(0, 24)}@example.test`, emailVerified: true, name: null, imageUrl: null },
          refreshToken: null, scopes: []
        };
      }
    }] }
  };
  const server = createServer(tls, async (req, res) => {
    try {
      const url = new URL(req.url, origin);
      if (!url.pathname.startsWith("/api/auth/")) {
        res.setHeader("content-type", "text/html");
        res.end('<!doctype html><title>Local auth fixture</title><a target="_blank" rel="opener">Open provider</a><script>window.messages=[];addEventListener("message",e=>window.messages.push({origin:e.origin,data:e.data}));</script>');
        return;
      }
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = chunks.length ? Buffer.concat(chunks).toString() : undefined;
      const response = await handler(new Request(url, { method: req.method, headers: req.headers, body }));
      const setCookies = response.headers.getSetCookie();
      if (url.pathname.endsWith("/callback")) {
        const state = url.searchParams.get("state") ?? new URLSearchParams(body).get("state");
        callbacks.push({ state, method: req.method,
          cookieSent: (req.headers.cookie ?? "").includes(`__Host-own_auth_oauth_${state}=`), setCookies });
      }
      for (const [key, value] of response.headers) if (key !== "set-cookie") res.setHeader(key, value);
      if (setCookies.length) res.setHeader("set-cookie", setCookies);
      res.writeHead(response.status);
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (error) {
      res.writeHead(500).end(String(error));
    }
  });
  const provider = createServer(tls, (req, res) => {
    if (req.url === "/favicon.ico") {
      res.writeHead(204).end();
      return;
    }
    const state = new URL(req.url, providerOrigin).searchParams.get("state");
    assert.match(state ?? "", /^[a-f0-9]{64}$/);
    res.setHeader("content-type", "text/html");
    res.end(`<!doctype html><title>Synthetic provider</title><form method="${scenario.post ? "POST" : "GET"}" action="${origin}/api/auth/oauth/${scenario.provider}/callback"><input type="hidden" name="state" value="${state}"><input type="hidden" name="code" value="fixture-code"><button>Continue</button></form>`);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `https://localhost:${server.address().port}`;
  await new Promise((resolve) => provider.listen(0, "127.0.0.1", resolve));
  providerOrigin = `https://127.0.0.1:${provider.address().port}`;
  auth = createOwnAuth({ ...options, redirectAllowlist: [origin] });
  handler = createOwnAuthHandler(auth);
  return { origin, storage, auth, callbacks, exchanges, async close() {
    await Promise.all([server, provider].map((service) => new Promise((resolve) => service.close(resolve))));
    await auth.close();
  } };
}
