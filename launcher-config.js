/* =============================================================================
 * launcher-config.js - LAUNCHER PASSWORD CONFIGURATION
 * =============================================================================
 *
 * This is the ONLY file you need to edit to set a password.
 *
 * SECURITY NOTICE - READ THIS FIRST
 * ---------------------------------
 * GitHub Pages serves this repository as PUBLIC static files. The hash below
 * is therefore readable by anyone, as is every commit you have ever made to
 * this repository (including the public-url.json tunnel URL and any earlier
 * password hash). This gate is a CASUAL-ACCESS DETERRENT ONLY. It is NOT
 * authentication in any meaningful sense. A determined user can read this
 * file, or open the browser developer tools, and bypass the gate entirely.
 * It also does NOT protect the direct Cloudflare Quick Tunnel URL, which is
 * publicly published in public-url.json.
 *
 * For real access control see README.md -> "Production recommendation".
 *
 * HOW TO SET A PASSWORD
 * ---------------------
 *   1. Run:  .\generate-password-hash.ps1
 *      It prompts for the password securely, hashes it with SHA-256, and
 *      prints ONLY the 64-character hex hash. The plain text is never saved,
 *      logged, or written to disk.
 *
 *   2. Copy the printed hash and paste it over the placeholder below.
 *
 *   3. Set CONFIGURED to true.
 *
 *   4. Commit and push. Do NOT ever commit the plain-text password.
 *
 * The placeholder below is deliberately invalid. While CONFIGURED is false the
 * gate FAILS CLOSED: it refuses to show the launcher and explains how to
 * finish setup, rather than presenting a login form that could never succeed.
 * ========================================================================== */

window.LAUNCHER_CONFIG = Object.freeze({
  /* Set to true only after pasting a real SHA-256 hash below. */
  CONFIGURED: false,

  /* SHA-256 of the password, lowercase hex, 64 characters.
   * Placeholder - deliberately not a valid hash. */
  PASSWORD_SHA256: "SET_YOUR_64_CHARACTER_SHA256_HASH_HERE",

  /* Location of the published Cloudflare Quick Tunnel URL. The launcher does
   * not read this file until after the password is accepted, so the tunnel URL
   * is not requested at all while the gate is locked. */
  PUBLIC_URL_FILE: "./public-url.json"
});
