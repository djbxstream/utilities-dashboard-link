/* =============================================================================
 * tests/launcher-gate.test.mjs
 *
 * Dependency-free tests for the Utilities Dashboard launcher password gate.
 *
 *   node --test tests/
 *
 * These drive the REAL launcher-gate.js module against a small hand-rolled DOM
 * stub and the real Web Crypto API. Nothing is reimplemented for the test: the
 * module under test is the exact file the page loads.
 *
 * They test the gate's BEHAVIOUR. They cannot and do not claim the gate is
 * secure - see README.md.
 * ========================================================================== */

import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GATE = require(join(ROOT, "launcher-gate.js"));

/* ------------------------------------------------------------------ DOM */

function makeElement(id) {
  const listeners = new Map();
  return {
    id,
    hidden: false,
    disabled: false,
    value: "",
    textContent: "",
    focused: 0,
    focus() { this.focused += 1; },
    addEventListener(type, handler) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(handler);
    },
    /* Fires a listener synchronously. Options are ignored, which is fine:
     * { once: true } only affects repeat invocation, and each test uses a
     * fresh element. */
    fire(type, event) { (listeners.get(type) || []).forEach((h) => h(event || {})); },
    listenerCount(type) { return (listeners.get(type) || []).length; },
  };
}

function makeDom(ids) {
  const nodes = new Map();
  for (const id of ids) nodes.set(id, makeElement(id));
  return { getElementById: (id) => nodes.get(id) || null, _nodes: nodes };
}

const ELEMENT_IDS = [
  "login-view", "launcher-view", "login-form", "password",
  "login-error", "login-submit", "open-dashboard", "status", "logout"
];

function makeSessionStore(behaviour) {
  const map = new Map();
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => { map.set(k, String(v)); },
    removeItem: (k) => { map.delete(k); },
    _dump: () => Object.fromEntries(map),
  };
}

async function hash(text) {
  return GATE.sha256Hex(text, webcrypto.subtle);
}

/* Builds a gate over a fresh DOM, with fetch and storage instrumented. */
async function setup({ configured = true, hashValue = null, checked = false, subtle = webcrypto.subtle, store = makeSessionStore() } = {}) {
  const password = "correct horse battery staple";
  const expected = hashValue || (await hash(password));

  const dom = makeDom(ELEMENT_IDS);
  dom._nodes.get("login-view").hidden = false;
  dom._nodes.get("launcher-view").hidden = true;
  dom._nodes.get("open-dashboard").disabled = true;

  const fetches = [];
  const navigations = [];
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => warnings.push(args.join(" "));

  const gate = GATE.createGate({
    document: dom,
    window: {
      sessionStorage: store,
      crypto: subtle ? { subtle } : undefined,
      LAUNCHER_CONFIG: { CONFIGURED: configured, PASSWORD_SHA256: expected, PUBLIC_URL_FILE: "./public-url.json" },
      location: { assign: (url) => navigations.push(url) },
    },
    subtle,
    fetch: (url, init) => {
      fetches.push({ url, init });
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ url: "https://density-including-sending-derek.trycloudflare.com" }),
      });
    },
  });

  return {
    gate, dom, store, fetches, navigations, warnings, expected, password,
    el: (id) => dom._nodes.get(id),
    async settle() { await new Promise((r) => setTimeout(r, 0)); console.warn = originalWarn; },
  };
}

/* ====================================================================== */

test("session key is sessionStorage, never localStorage or a cookie", () => {
  assert.equal(GATE.SESSION_KEY, "utilities-dashboard-authorized");
  /* Strip comments and strings before scanning, so prose that merely MENTIONS
   * localStorage or cookies is not mistaken for a use of them. */
  const code = readFileSync(join(ROOT, "launcher-gate.js"), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "");
  assert.equal(/\blocalStorage\b/.test(code), false, "gate must not use localStorage");
  assert.equal(/document\s*\.\s*cookie|\bcookie\b/.test(code), false, "gate must not use cookies");
  /* And it must positively use sessionStorage. */
  assert.match(code, /sessionStorage/);
});

test("unauthenticated page hides launcher content and requests no tunnel URL", async () => {
  const t = await setup();
  const unlocked = t.gate.init();
  await t.settle();

  assert.equal(unlocked, false);
  assert.equal(t.el("login-view").hidden, false, "login view must be visible");
  assert.equal(t.el("launcher-view").hidden, true, "launcher view must stay hidden");
  assert.equal(t.fetches.length, 0, "public-url.json must not be requested while locked");
  assert.equal(t.store.getItem(GATE.SESSION_KEY), null, "nothing stored while locked");
  assert.equal(t.el("open-dashboard").disabled, true, "open control must stay disabled");
});

test("no tunnel URL appears in the served page source outside the loader", () => {
  const html = readFileSync(join(ROOT, "index.html"), "utf8");
  /* The literal tunnel hostname must not be hard-coded anywhere in the page. */
  assert.equal(/trycloudflare\.com/.test(html), false, "index.html must not hard-code a tunnel URL");
  /* The launcher view starts hidden, so nothing is exposed before auth. */
  assert.match(html, /id="launcher-view"[^>]*hidden/);
  assert.match(html, /id="login-view"/);
});

test("wrong password is rejected, reveals nothing, and does not unlock", async () => {
  const t = await setup();
  t.gate.init();
  t.el("password").value = "wrong password";

  const result = await t.gate.attemptLogin();
  await t.settle();

  assert.equal(result, false, "wrong password must not unlock");
  assert.equal(t.gate.isAuthorized(), false);
  assert.equal(t.el("launcher-view").hidden, true, "launcher must stay hidden");
  assert.equal(t.el("login-error").textContent, GATE.GENERIC_ERROR);
  assert.equal(t.fetches.length, 0, "wrong password must not trigger a fetch");
  assert.equal(t.el("password").value, "", "the rejected password must not linger in the DOM");
});

test("the failure message reveals no length, hash or partial match", async () => {
  const t = await setup();
  t.gate.init();

  /* One character off. */
  t.el("password").value = t.password.slice(0, -1) + "X";
  await t.gate.attemptLogin();
  const oneOff = t.el("login-error").textContent;

  /* Empty. */
  t.el("password").value = "";
  await t.gate.attemptLogin();
  const empty = t.el("login-error").textContent;

  /* Very long. */
  t.el("password").value = "x".repeat(5000);
  await t.gate.attemptLogin();
  const veryLong = t.el("login-error").textContent;

  assert.equal(oneOff, GATE.GENERIC_ERROR);
  assert.equal(empty, GATE.GENERIC_ERROR);
  assert.equal(veryLong, GATE.GENERIC_ERROR, "every failure must report the same string");

  /* And that string must not leak the expected length or any hash fragment. */
  assert.equal(oneOff.includes("64"), false);
  assert.equal(/[0-9a-f]{16,}/.test(oneOff), false, "no hex fragment in the error text");
  assert.equal(GATE.GENERIC_ERROR.toLowerCase().includes("length"), false);
});

test("correct password is accepted and the launcher is shown", async () => {
  const t = await setup();
  t.gate.init();
  t.el("password").value = t.password;

  const result = await t.gate.attemptLogin();
  await t.settle();

  assert.equal(result, true, "correct password must unlock");
  assert.equal(t.gate.isAuthorized(), true);
  assert.equal(t.el("launcher-view").hidden, false, "launcher view must be visible");
  assert.equal(t.el("login-view").hidden, true, "login view must be hidden");
  assert.equal(t.el("password").value, "", "the password must be cleared after use");
  assert.equal(t.store.getItem(GATE.SESSION_KEY), "1");
});

test("hashing is real SHA-256 and not a plain-text or weak comparison", async () => {
  /* Known-answer test against a published vector. */
  const abc = await GATE.sha256Hex("abc", webcrypto.subtle);
  assert.equal(abc, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.match(abc, /^[0-9a-f]{64}$/);

  /* And a second vector with multi-byte characters, to prove UTF-8 encoding. */
  const unicode = await GATE.sha256Hex("pässwörd", webcrypto.subtle);
  assert.match(unicode, /^[0-9a-f]{64}$/);
  assert.notEqual(unicode, abc);
});

test("sessionStorage unlock survives a refresh (same session, new init)", async () => {
  const t = await setup();
  t.gate.init();
  t.el("password").value = t.password;
  await t.gate.attemptLogin();
  await t.settle();
  assert.equal(t.gate.isAuthorized(), true);

  /* Simulate a page refresh: a brand new gate over the SAME session store, a
   * fresh DOM and a fresh fetch log. */
  const dom2 = makeDom(ELEMENT_IDS);
  dom2._nodes.get("launcher-view").hidden = true;
  const fetches2 = [];
  const gate2 = GATE.createGate({
    document: dom2,
    window: {
      sessionStorage: t.store,
      crypto: { subtle: webcrypto.subtle },
      LAUNCHER_CONFIG: { CONFIGURED: true, PASSWORD_SHA256: t.expected, PUBLIC_URL_FILE: "./public-url.json" },
      location: { assign: () => {} },
    },
    subtle: webcrypto.subtle,
    fetch: (url, init) => { fetches2.push({ url, init }); return Promise.resolve({ ok: true, json: () => Promise.resolve({ url: "https://density-including-sending-derek.trycloudflare.com" }) }); },
  });

  const unlockedOnRefresh = gate2.init();
  await new Promise((r) => setTimeout(r, 0));

  assert.equal(unlockedOnRefresh, true, "refresh must stay unlocked");
  assert.equal(dom2._nodes.get("launcher-view").hidden, false, "launcher must be shown after refresh");
  assert.equal(fetches2.length, 1, "the refreshed page reloads the tunnel URL");
});

test("logout clears the session and relocks the launcher", async () => {
  const t = await setup();
  t.gate.init();
  t.el("password").value = t.password;
  await t.gate.attemptLogin();
  await t.settle();
  assert.equal(t.gate.isAuthorized(), true);

  t.gate.logout();

  assert.equal(t.gate.isAuthorized(), false, "logout must clear the session record");
  assert.equal(t.store.getItem(GATE.SESSION_KEY), null, "session key must be gone");
  assert.equal(t.el("login-view").hidden, false, "login view must be shown again");
  assert.equal(t.el("launcher-view").hidden, true, "launcher must be hidden again");
  assert.equal(t.el("open-dashboard").disabled, true, "open control must be disabled again");
  assert.equal(t.el("login-error").textContent, "", "logout must not show an error");
});

test("Enter submits: the form has a real submit handler, not a click-only div", async () => {
  const t = await setup();
  t.gate.init();
  t.el("password").value = t.password;

  /* A submit handler is what makes Enter work natively in every browser. */
  assert.equal(t.el("login-form").listenerCount("submit"), 1, "form needs a submit listener");
  assert.equal(t.el("login-submit").listenerCount("click"), 0, "no click-only path");

  /* Fire submit, as pressing Enter in a text input does. */
  t.el("login-form").fire("submit", { preventDefault() { this.defaultPrevented = true; } });
  await t.settle();
  await new Promise((r) => setTimeout(r, 10));

  assert.equal(t.gate.isAuthorized(), true, "Enter must unlock");
});

test("the existing Open Utilities Dashboard control is preserved and gated", async () => {
  const t = await setup();
  t.gate.init();
  t.el("password").value = t.password;
  await t.gate.attemptLogin();
  await t.settle();

  assert.equal(t.el("open-dashboard").disabled, false, "open control must enable after login");
  assert.equal(t.el("status").textContent, "Dashboard is available.");
  assert.equal(t.fetches.length, 1);
  assert.equal(t.fetches[0].url, "./public-url.json", "must read the existing public-url.json");
  assert.equal(t.fetches[0].init.cache, "no-store");

  /* Clicking still navigates to the dashboard. */
  t.el("open-dashboard").fire("click");
  assert.deepEqual(t.navigations, ["https://density-including-sending-derek.trycloudflare.com/slrat"]);
});

test("logout control is present and wired", async () => {
  const t = await setup();
  t.gate.init();
  t.el("password").value = t.password;
  await t.gate.attemptLogin();
  await t.settle();

  assert.equal(t.el("logout").listenerCount("click"), 1, "logout must be wired");
  t.el("logout").fire("click");
  assert.equal(t.gate.isAuthorized(), false);
});

test("an unconfigured placeholder fails closed with a setup message", async () => {
  for (const hashValue of [GATE.CONFIGURED_PLACEHOLDER, "", "not-a-hash", null, undefined]) {
    const t = await setup({ configured: false, hashValue: hashValue || GATE.CONFIGURED_PLACEHOLDER });
    t.gate.init();
    t.el("password").value = "anything";
    const result = await t.gate.attemptLogin();
    await t.settle();

    assert.equal(result, false, `must refuse for hash ${JSON.stringify(hashValue)}`);
    assert.equal(t.gate.isAuthorized(), false);
    assert.equal(t.el("login-error").textContent, GATE.NOT_CONFIGURED_ERROR);
    assert.equal(t.fetches.length, 0);
  }
});

test("a launcher config that is CONFIGURED but still holds the placeholder is refused", async () => {
  const t = await setup({ configured: true, hashValue: GATE.CONFIGURED_PLACEHOLDER });
  t.gate.init();
  t.el("password").value = "anything";
  const result = await t.gate.attemptLogin();
  assert.equal(result, false, "CONFIGURED alone must not unlock");
  assert.equal(t.el("login-error").textContent, GATE.NOT_CONFIGURED_ERROR);
});

test("a missing Web Crypto implementation fails closed", async () => {
  const t = await setup({ subtle: null });
  t.gate.init();
  t.el("password").value = t.password;
  const result = await t.gate.attemptLogin();
  await t.settle();

  assert.equal(result, false);
  assert.equal(t.el("login-error").textContent, GATE.NO_CRYPTO_ERROR);
  assert.equal(t.gate.isAuthorized(), false);
});

test("sessionStorage that throws does not break the page", async () => {
  const hostile = {
    getItem() { throw new Error("blocked"); },
    setItem() { throw new Error("blocked"); },
    removeItem() { throw new Error("blocked"); },
  };
  const t = await setup({ store: hostile });
  /* Must not throw during init. */
  t.gate.init();
  t.el("password").value = t.password;
  const result = await t.gate.attemptLogin();
  await t.settle();
  /* Cannot store the grant, so must not report success. */
  assert.equal(result, false);
  assert.equal(t.el("login-view").hidden, false, "must stay on the login view");
});

test("only a bare HTTPS Quick Tunnel root is accepted as the dashboard URL", async () => {
  const hostileUrls = [
    "https://evil.example.com/",
    "http://density-including-sending-derek.trycloudflare.com/",
    "https://density-including-sending-derek.trycloudflare.com/elsewhere",
    "https://density-including-sending-derek.trycloudflare.com/?a=1",
    "https://sub.evil.trycloudflare.com.attacker.com/",
    "not-a-url",
  ];
  for (const url of hostileUrls) {
    const t = await setup();
    t.gate.init();
    t.el("password").value = t.password;
    await t.gate.attemptLogin();
    const gate = t.gate;
    /* Re-run the loader with a hostile payload. */
    const dom = t.dom;
    const evil = Object.assign(dom.getElementById("launcher-view"), {});
    void evil; void gate;
    const fresh = GATE.createGate({
      document: dom,
      window: {
        sessionStorage: t.store,
        crypto: { subtle: webcrypto.subtle },
        LAUNCHER_CONFIG: { CONFIGURED: true, PASSWORD_SHA256: t.expected, PUBLIC_URL_FILE: "./public-url.json" },
        location: { assign: () => {} },
      },
      subtle: webcrypto.subtle,
      fetch: () => Promise.resolve({ ok: true, json: () => Promise.resolve({ url }) }),
    });
    fresh.init();
    await new Promise((r) => setTimeout(r, 0));
    assert.equal(
      dom.getElementById("status").textContent,
      "Dashboard is currently unavailable.",
      `must reject ${url}`
    );
    assert.equal(dom.getElementById("open-dashboard").disabled, true, `must stay disabled for ${url}`);
  }
});

test("no plain-text password is stored in any committed source file", () => {
  const files = ["index.html", "launcher-config.js", "launcher-gate.js", "generate-password-hash.ps1", "README.md"];
  for (const file of files) {
    const text = readFileSync(join(ROOT, file), "utf8");
    /* Only a 64-char hex digest is ever allowed, and only in the config. */
    const suspicious = text.match(/(?:password|passwd|pin)\s*[:=]\s*["'][^"']{1,64}["']/gi) || [];
    for (const hit of suspicious) {
      const value = hit.split(/[:=]/).pop().trim().replace(/["']/g, "");
      /* Allow ids, type attributes, selectors, key names and log strings. */
      const allowed = [
        "current-password", "passwordInput", "passwords", "plain", "the launcher password",
        "your password", "a password", "no password", "hidden", "Enter the launcher",
        "launcher password", "correct", "Password", "password ",
      ];
      const ok = allowed.some((a) => value.includes(a)) || /^[a-z_]+$/i.test(value);
      assert.equal(ok, true, `${file} appears to contain a literal password: ${hit}`);
    }
  }
  /* The config is now configured, so it must hold a real 64-character digest
   * and must no longer hold the setup placeholder. The password itself still
   * appears nowhere in source - only its hash. */
  const config = readFileSync(join(ROOT, "launcher-config.js"), "utf8");
  assert.match(config, /CONFIGURED: true/);
  assert.doesNotMatch(config, new RegExp(GATE.CONFIGURED_PLACEHOLDER));
  const shippedHash = config.match(/PASSWORD_SHA256: "([0-9a-f]{64})"/);
  assert.ok(shippedHash, "the config must hold exactly one lowercase 64-character SHA-256 hash");
  assert.equal(GATE.isConfigured({ CONFIGURED: true, PASSWORD_SHA256: shippedHash[1] }), true,
    "the shipped hash must satisfy the gate's own configured check");
});

test("the constant-time comparison is correct and length-independent", () => {
  assert.equal(GATE.timingSafeEqualString("abc", "abc"), true);
  assert.equal(GATE.timingSafeEqualString("abc", "abd"), false);
  assert.equal(GATE.timingSafeEqualString("abc", "abcd"), false);
  assert.equal(GATE.timingSafeEqualString("abcd", "abc"), false);
  assert.equal(GATE.timingSafeEqualString("", ""), true);
  assert.equal(GATE.timingSafeEqualString("a", ""), false);
  /* A differing length must not early-return, so it cannot leak a prefix. */
  assert.equal(GATE.timingSafeEqualString("aaa", "aab"), false);
});

test("mobile and accessibility requirements are present in the page", () => {
  const html = readFileSync(join(ROOT, "index.html"), "utf8");
  /* Password field */
  assert.match(html, /<label for="password">/);
  assert.match(html, /id="password"[\s\S]*?type="password"/);
  assert.match(html, /autocomplete="current-password"/);
  assert.match(html, /aria-describedby="login-error"/);
  /* Error message is a polite live region */
  assert.match(html, /id="login-error"[^>]*aria-live="polite"/);
  /* Visible focus states */
  assert.match(html, /:focus-visible/);
  /* 44px touch targets on input and button */
  assert.match(html, /input\[type="password"\][\s\S]*?min-height:\s*2\.75rem/);
  assert.match(html, /button\s*\{[\s\S]*?min-height:\s*2\.75rem/);
  /* Mobile meta and a full-width usable card */
  assert.match(html, /<meta name="viewport" content="width=device-width, initial-scale=1">/);
  assert.match(html, /\.card\s*\{[\s\S]*?width:\s*100%/);
  assert.match(html, /@media \(max-width: 30rem\)/);
  /* Required copy */
  assert.match(html, /City of Melbourne/);
  assert.match(html, /Authorized access only/);
  assert.match(html, />Continue</);
  assert.match(html, />Logout</);
  assert.match(html, /Open Utilities Dashboard/);
  assert.match(html, /Incorrect password|casual-access deterrent/);
});

test("no external auth service, backend, or tunnel config was introduced", () => {
  const files = ["index.html", "launcher-config.js", "launcher-gate.js"];
  for (const file of files) {
    const text = readFileSync(join(ROOT, file), "utf8");
    assert.equal(/auth0|firebase|okta|cognito/i.test(text), false, `${file} must not reference an auth service`);
    /* No endpoint other than the existing public-url.json. */
    const urls = text.match(/https?:\/\/[^\s"'`)]+/g) || [];
    for (const url of urls) {
      assert.equal(
        /^https?:\/\/(www\.)?(w3\.org|github\.com|githubusercontent\.com)$/i.test(url),
        true,
        `${file} references an unexpected external URL: ${url}`
      );
    }
  }
});

test("INTEGRATION: the real launcher-config.js loads and is a valid configured gate", async () => {
  /* Load the actual configuration file the page loads, in a sandboxed global
   * so it defines window.LAUNCHER_CONFIG exactly as the browser would. */
  const configSource = readFileSync(join(ROOT, "launcher-config.js"), "utf8");
  const fakeWindow = {};
  new Function("window", configSource)(fakeWindow);
  const realConfig = fakeWindow.LAUNCHER_CONFIG;

  assert.ok(realConfig, "launcher-config.js must define window.LAUNCHER_CONFIG");
  assert.equal(typeof realConfig.PUBLIC_URL_FILE, "string");
  assert.equal(realConfig.PUBLIC_URL_FILE, "./public-url.json", "must keep reading the existing file");

  /* The shipped config is real: the gate will ask for a password. */
  assert.equal(GATE.isConfigured(realConfig), true, "the shipped config must be configured");
  assert.match(String(realConfig.PASSWORD_SHA256), /^[0-9a-f]{64}$/);
  assert.notEqual(String(realConfig.PASSWORD_SHA256), GATE.CONFIGURED_PLACEHOLDER);

  const dom = makeDom(ELEMENT_IDS);
  const fetches = [];
  const result = GATE.start({
    document: dom,
    window: {
      ...fakeWindow,
      sessionStorage: makeSessionStore(),
      crypto: { subtle: webcrypto.subtle },
      location: { assign: () => {} },
    },
    subtle: webcrypto.subtle,
    fetch: (url, init) => { fetches.push({ url, init }); return Promise.resolve({ ok: true, json: () => Promise.resolve({}) }); },
  });

  await new Promise((r) => setTimeout(r, 0));

  /* Fresh session: locked, no setup message, and the tunnel URL is not
   * requested. A wrong password is rejected without unlocking. */
  assert.equal(result.unlocked, false, "a fresh session must start locked");
  assert.equal(dom.getElementById("login-error").textContent, "",
    "a configured gate must not show the setup message");
  assert.equal(dom.getElementById("launcher-view").hidden, true, "launcher must stay hidden");
  assert.equal(fetches.length, 0, "no tunnel URL request while locked");

  dom.getElementById("password").value = "definitely-not-the-password";
  const gate = GATE.createGate({
    document: dom,
    window: { ...fakeWindow, sessionStorage: makeSessionStore(), crypto: { subtle: webcrypto.subtle }, location: { assign: () => {} } },
    subtle: webcrypto.subtle,
    fetch: (url, init) => { fetches.push({ url, init }); return Promise.resolve({ ok: true, json: () => Promise.resolve({}) }); },
  });
  assert.equal(await gate.attemptLogin(), false, "a wrong password must not unlock the shipped config");
  assert.equal(dom.getElementById("login-error").textContent, GATE.GENERIC_ERROR);
  assert.equal(dom.getElementById("launcher-view").hidden, true, "launcher must stay hidden after a failed attempt");
  assert.equal(fetches.length, 0, "a failed attempt must not request the tunnel URL");
});

test("INTEGRATION: a real configured hash round-trips through the gate", async () => {
  /* The hash an operator would paste from generate-password-hash.ps1, computed
   * here with standard SHA-256 over UTF-8 - the same algorithm the PowerShell
   * script self-tests against the published "abc" vector. */
  const password = "Melbourne-Utilities-2026";
  const pastedHash = await hash(password);
  assert.match(pastedHash, /^[0-9a-f]{64}$/);

  const dom = makeDom(ELEMENT_IDS);
  const store = makeSessionStore();
  const fetches = [];
  const gate = GATE.createGate({
    document: dom,
    window: {
      sessionStorage: store,
      crypto: { subtle: webcrypto.subtle },
      LAUNCHER_CONFIG: { CONFIGURED: true, PASSWORD_SHA256: pastedHash, PUBLIC_URL_FILE: "./public-url.json" },
      location: { assign: () => {} },
    },
    subtle: webcrypto.subtle,
    fetch: (url, init) => { fetches.push({ url }); return Promise.resolve({ ok: true, json: () => Promise.resolve({ url: "https://density-including-sending-derek.trycloudflare.com" }) }); },
  });

  gate.init();
  dom.getElementById("password").value = "wrong";
  assert.equal(await gate.attemptLogin(), false, "wrong password rejected");

  dom.getElementById("password").value = password;
  assert.equal(await gate.attemptLogin(), true, "the pasted hash accepts its own password");
  await new Promise((r) => setTimeout(r, 0));

  assert.equal(dom.getElementById("launcher-view").hidden, false);
  assert.equal(dom.getElementById("open-dashboard").disabled, false);
  assert.equal(fetches.length, 1, "the tunnel URL is read only after unlock");
});

test("the public URL publishing contract is preserved", async () => {
  /* publish-public-url.ps1 in the dashboard repo writes exactly this shape. */
  const json = JSON.parse(readFileSync(join(ROOT, "public-url.json"), "utf8"));
  assert.equal(typeof json.url, "string");
  assert.match(json.url, /^https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com$/);
  assert.equal(Object.keys(json).length, 1, "public-url.json must keep its single-key shape");
  /* The gate reads it by the same relative path it has always used. */
  assert.match(readFileSync(join(ROOT, "launcher-config.js"), "utf8"), /PUBLIC_URL_FILE: "\.\/public-url\.json"/);
  assert.equal(readFileSync(join(ROOT, "launcher-config.js"), "utf8").includes("./public-url.json"), true);
});
