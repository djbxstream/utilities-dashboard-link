/* =============================================================================
 * launcher-gate.js - client-side password gate for the Utilities Dashboard
 * launcher.
 *
 * WHAT THIS IS
 * A casual-access deterrent. See the security notice in launcher-config.js and
 * the limitations section of README.md. Nothing here is server-side: the
 * comparison happens in the browser, the expected hash is a public file, and
 * anyone who reads the source can bypass the gate. It is not authentication.
 *
 * DESIGN
 *   - SHA-256 via the Web Crypto API, never a hand-rolled digest.
 *   - sessionStorage only. Never localStorage, never a cookie. A refresh in the
 *     same tab stays unlocked; closing the tab session locks it again.
 *   - The launcher content is not in the DOM and public-url.json is not
 *     requested until the password has been accepted.
 *   - Fails CLOSED: an unconfigured placeholder or a missing Web Crypto
 *     implementation blocks the launcher rather than silently allowing it.
 *   - Every failure reports the same message. No length, no hash, no partial
 *     match, no hint.
 * ========================================================================== */

(function (root, factory) {
  "use strict";
  const api = factory();
  // CommonJS for the Node test suite, plain global for the browser.
  if (typeof module === "object" && module && module.exports) module.exports = api;
  else root.LauncherGate = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  /* sessionStorage, not localStorage. Cleared when the tab session ends. */
  const SESSION_KEY = "utilities-dashboard-authorized";

  /* One message for every failure. Deliberately identical whether the password
   * was wrong, the hash was unconfigured, or Web Crypto was unavailable, so
   * nothing about the expected value can be inferred. */
  const GENERIC_ERROR = "Incorrect password";
  const NOT_CONFIGURED_ERROR =
    "This launcher has no password configured yet. See launcher-config.js.";
  const NO_CRYPTO_ERROR =
    "This browser cannot verify the password. Use a modern HTTPS browser.";

  const SHA256_HEX = /^[0-9a-f]{64}$/;
  const CONFIGURED_PLACEHOLDER = "SET_YOUR_64_CHARACTER_SHA256_HASH_HERE";

  /* ---------------------------------------------------------------- utils */

  function toHex(buffer) {
    const bytes = new Uint8Array(buffer);
    let out = "";
    for (let i = 0; i < bytes.length; i += 1) {
      out += bytes[i].toString(16).padStart(2, "0");
    }
    return out;
  }

  /* SHA-256 of the UTF-8 text, lowercase hex. */
  function sha256Hex(text, subtle) {
    if (!subtle || typeof subtle.digest !== "function") {
      return Promise.reject(new Error("Web Crypto unavailable"));
    }
    const encoded = new TextEncoder().encode(String(text));
    return subtle.digest("SHA-256", encoded).then(toHex);
  }

  /* Length-independent comparison. The lengths of the two values are compared
   * through the same accumulator, so an early return cannot leak a prefix
   * length through timing. It is not a meaningful defence here - the expected
   * hash is a public file - but it costs nothing and is correct practice. */
  function timingSafeEqualString(a, b) {
    const left = String(a);
    const right = String(b);
    const length = Math.max(left.length, right.length);
    let diff = left.length ^ right.length;
    for (let i = 0; i < length; i += 1) {
      diff |= (left.charCodeAt(i) || 0) ^ (right.charCodeAt(i) || 0);
    }
    return diff === 0;
  }

  /* sessionStorage access throws in some privacy modes and when cookies are
   * blocked. Never let that break the page; fail closed instead. */
  function safeSessionStore(win) {
    const empty = {
      get: function () { return null; },
      set: function () { return false; },
      remove: function () { return false; }
    };
    try {
      const store = win && win.sessionStorage;
      if (!store) return empty;
      // Probe: a store can exist and still throw on write.
      const probe = "__launcher_probe__";
      store.setItem(probe, "1");
      store.removeItem(probe);
      return {
        get: function (key) { return store.getItem(key); },
        set: function (key, value) { store.setItem(key, value); return true; },
        remove: function (key) { store.removeItem(key); return true; }
      };
    } catch (_) {
      return empty;
    }
  }

  /* A configuration that is a real 64-character hex hash, not the placeholder. */
  function isConfigured(config) {
    if (!config || config.CONFIGURED !== true) return false;
    if (typeof config.PASSWORD_SHA256 !== "string") return false;
    const hash = config.PASSWORD_SHA256.trim().toLowerCase();
    if (hash === CONFIGURED_PLACEHOLDER) return false;
    return SHA256_HEX.test(hash);
  }

  /* ----------------------------------------------------------------- gate */

  function createGate(options) {
    const opts = options || {};
    const doc = opts.document;
    const win = opts.window;
    const config = opts.config || (win && win.LAUNCHER_CONFIG) || null;
    const subtle = opts.subtle || (win && win.crypto && win.crypto.subtle) || null;
    const fetchImpl = opts.fetch || (typeof fetch === "function" ? fetch : null);
    const store = safeSessionStore(win);

    const loginView = doc.getElementById("login-view");
    const launcherView = doc.getElementById("launcher-view");
    const form = doc.getElementById("login-form");
    const passwordInput = doc.getElementById("password");
    const errorEl = doc.getElementById("login-error");
    const submitButton = doc.getElementById("login-submit");
    const openButton = doc.getElementById("open-dashboard");
    const statusText = doc.getElementById("status");
    const logoutButton = doc.getElementById("logout");

    let onAuthorizedChange = typeof opts.onAuthorizedChange === "function"
      ? opts.onAuthorizedChange
      : function () {};

    /* Unlocked only when the session record is present. A refresh in the same
     * tab therefore stays unlocked; a new tab session starts locked. */
    function isAuthorized() {
      return store.get(SESSION_KEY) === "1";
    }

    function showLogin() {
      if (launcherView) launcherView.hidden = true;
      if (loginView) loginView.hidden = false;
      if (errorEl) errorEl.textContent = "";
      if (passwordInput) {
        passwordInput.value = "";
        if (typeof passwordInput.focus === "function") passwordInput.focus();
      }
    }

    function showLauncher() {
      if (loginView) loginView.hidden = true;
      if (launcherView) launcherView.hidden = false;
      if (errorEl) errorEl.textContent = "";
      if (passwordInput) passwordInput.value = "";
    }

    function setError(message) {
      if (errorEl) errorEl.textContent = message || "";
    }

    function setStatus(message) {
      if (statusText) statusText.textContent = message;
    }

    function setOpenEnabled(enabled) {
      if (openButton) openButton.disabled = !enabled;
    }

    /* ------------------------------------------------------------- loader */

    /* The tunnel URL is read only after the gate is unlocked. While the gate
     * is locked this file is never requested, so the launcher page itself
     * gives nothing away. */
    function loadDashboardUrl() {
      if (!fetchImpl) {
        setStatus("Dashboard is currently unavailable.");
        setOpenEnabled(false);
        return Promise.resolve(null);
      }
      const source = (config && config.PUBLIC_URL_FILE) || "./public-url.json";
      setOpenEnabled(false);
      return fetchImpl(source, {
        cache: "no-store",
        headers: { Accept: "application/json" }
      })
        .then(function (response) {
          if (!response.ok) throw new Error("Unavailable");
          return response.json();
        })
        .then(function (data) {
          const value = typeof (data && data.url) === "string" ? data.url.trim() : "";

          let parsed;
          try {
            parsed = new URL(value);
          } catch (_) {
            throw new Error("Invalid URL");
          }

          /* Only a bare HTTPS Cloudflare Quick Tunnel root is accepted, so a
           * tampered public-url.json cannot turn the launcher into an open
           * redirect to an arbitrary site. */
          const validCloudflareTunnel =
            parsed.protocol === "https:" &&
            /^[a-z0-9-]+\.trycloudflare\.com$/i.test(parsed.hostname) &&
            parsed.pathname === "/" &&
            !parsed.search &&
            !parsed.hash;

          if (!validCloudflareTunnel) throw new Error("Invalid URL");

          if (openButton) {
            openButton.addEventListener("click", function () {
              win.location.assign(parsed.origin + "/slrat");
            }, { once: true });
          }
          setOpenEnabled(true);
          setStatus("Dashboard is available.");
          return parsed.origin;
        })
        .catch(function () {
          setStatus("Dashboard is currently unavailable.");
          setOpenEnabled(false);
          return null;
        });
    }

    /* --------------------------------------------------------- authorize */

    function unlock() {
      const ok = store.set(SESSION_KEY, "1");
      if (!ok) return false;
      showLauncher();
      onAuthorizedChange(true);
      loadDashboardUrl();
      return true;
    }

    /* Always clears the field first, so a failed attempt never leaves the
     * password sitting in the DOM. */
    function attemptLogin() {
      if (!isConfigured(config)) {
        setError(NOT_CONFIGURED_ERROR);
        if (passwordInput) passwordInput.value = "";
        return Promise.resolve(false);
      }
      if (!subtle) {
        setError(NO_CRYPTO_ERROR);
        if (passwordInput) passwordInput.value = "";
        return Promise.resolve(false);
      }

      const entered = passwordInput ? passwordInput.value : "";
      if (passwordInput) passwordInput.value = "";
      if (submitButton) submitButton.disabled = true;

      return sha256Hex(entered, subtle)
        .then(function (digest) {
          const expected = String(config.PASSWORD_SHA256).trim().toLowerCase();
          if (!timingSafeEqualString(digest, expected)) {
            setError(GENERIC_ERROR);
            return false;
          }
          setError("");
          return unlock();
        })
        .catch(function () {
          setError(GENERIC_ERROR);
          return false;
        })
        .then(function (result) {
          if (submitButton) submitButton.disabled = false;
          if (passwordInput && typeof passwordInput.focus === "function") {
            passwordInput.focus();
          }
          return result;
        });
    }

    function logout() {
      store.remove(SESSION_KEY);
      setOpenEnabled(false);
      showLogin();
      onAuthorizedChange(false);
      return true;
    }

    /* ------------------------------------------------------------- wiring */

    function init() {
      /* A form with a submit handler already submits on Enter in every modern
       * browser, which is why this is a real <form> and not a div + click. */
      if (form) form.addEventListener("submit", function (event) {
        if (event && typeof event.preventDefault === "function") event.preventDefault();
        attemptLogin();
      });

      if (logoutButton) logoutButton.addEventListener("click", function () { logout(); });

      if (isAuthorized()) {
        showLauncher();
        onAuthorizedChange(true);
        loadDashboardUrl();
        return true;
      }

      showLogin();
      onAuthorizedChange(false);
      /* Deliberately no loadDashboardUrl() here: the tunnel URL is not read
       * and is not present in the page while the gate is locked. */
      return false;
    }

    return {
      init: init,
      attemptLogin: attemptLogin,
      logout: logout,
      isAuthorized: isAuthorized,
      loadDashboardUrl: loadDashboardUrl,
      isConfigured: function () { return isConfigured(config); }
    };
  }

  /* Point the page at a config that may be missing or unconfigured. */
  function start(options) {
    const opts = options || {};
    const doc = opts.document;
    const config = opts.config || (opts.window && opts.window.LAUNCHER_CONFIG) || null;
    const gate = createGate(opts);
    const unlocked = gate.init();

    if (!gate.isConfigured()) {
      /* Fail closed with a setup message instead of an unusable login form. */
      const errorEl = doc.getElementById("login-error");
      if (errorEl) errorEl.textContent = NOT_CONFIGURED_ERROR;
    }
    return { gate: gate, unlocked: unlocked };
  }

  return {
    SESSION_KEY: SESSION_KEY,
    GENERIC_ERROR: GENERIC_ERROR,
    NOT_CONFIGURED_ERROR: NOT_CONFIGURED_ERROR,
    NO_CRYPTO_ERROR: NO_CRYPTO_ERROR,
    CONFIGURED_PLACEHOLDER: CONFIGURED_PLACEHOLDER,
    sha256Hex: sha256Hex,
    toHex: toHex,
    timingSafeEqualString: timingSafeEqualString,
    isConfigured: isConfigured,
    createGate: createGate,
    start: start
  };
});
