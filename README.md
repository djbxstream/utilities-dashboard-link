# Utilities Dashboard — Link Launcher

A one-page static site that publishes the current Cloudflare Quick Tunnel URL for the
City of Melbourne **Utilities Dashboard** and sends the user to the SL RAT module.

- **Public URL:** <https://djbxstream.github.io/utilities-dashboard-link/>
- **Serves:** `index.html` (page), `launcher-gate.js` (gate logic), `launcher-config.js` (password hash)
- **Reads:** `public-url.json` — the current published tunnel URL
- **Hosting:** GitHub Pages, from the `main` branch

---

## ⚠️ Security notice — read this before relying on the password gate

**The password gate on this launcher is a casual-access deterrent. It is not
authentication, and it is not a security control.**

Everything this site does happens in the visitor's browser, on files that GitHub
Pages serves publicly. Concretely:

| What | Reality |
|---|---|
| Page source | **Public.** Anyone can view-source, and the SHA-256 hash is in `launcher-config.js`. |
| JavaScript | **Public.** The whole gate is a client-side comparison. |
| The gate itself | **Trivially bypassable.** Clear site data, patch the function, or just type the URL. |
| Git history | **Public.** Every hash and every tunnel URL you have ever committed is in the repository history. |
| The tunnel URL | **Not protected by this gate at all.** It is published in `public-url.json`. |
| Cloudflare Quick Tunnel | **Reachable directly**, with no launcher involved. |

So the gate stops **casual, accidental, or shoulder-surfing** access — someone who
lands on the page and cannot get in without asking. That is genuinely useful for a
public link that is not meant to be advertised. It stops **nobody who is trying**.

It also gives **no protection to the underlying data**. The SL RAT dashboard is
served over a Quick Tunnel whose address is published. Anyone who learns that
address — from the repository, from the browser network tab, from Cloudflare — can
reach the dashboard directly and never see this page.

**Do not describe this as, or rely on this as, access control.**

---

## Setting a password

The password is **never** stored in this repository. Only its SHA-256 hash is.

```powershell
# 1. Generate the hash. Prompts with no echo; prints only the hash.
.\generate-password-hash.ps1

# Optional self-test, to confirm the script hashes correctly before you trust it:
.\generate-password-hash.ps1 -ShowSample
```

2. Paste the printed 64-character hex hash over `PASSWORD_SHA256` in
   [`launcher-config.js`](launcher-config.js).
3. Set `CONFIGURED: true`.
4. Commit and push.

> The script reads the password as a `SecureString` and never passes it as a
> command-line argument, because on Windows a process argument is visible to every
> other process on the machine. The plain text is converted in memory only for the
> hash, then zeroed and released. Nothing is written to disk or to a log.

While `CONFIGURED` is `false`, or the hash is still the placeholder, **the gate
fails closed**: it refuses to open the launcher and shows a setup message, rather
than presenting a login form that could never succeed.

### Rotating the password

Generate a new hash, replace `PASSWORD_SHA256`, commit, push. Users must log in
again the next time they open the launcher — but see the limitation below about
commit history retaining the old hash.

---

## How the gate behaves

| Behaviour | Detail |
|---|---|
| Algorithm | SHA-256 via the Web Crypto API (`crypto.subtle.digest`), UTF-8, lowercase hex |
| Comparison | Length-independent XOR comparison |
| Storage | `sessionStorage` only — **never** `localStorage`, **never** a cookie |
| Refresh | Stays unlocked within the same tab session |
| Closing the tab or browser | Locks again |
| Logout | Clears the session record and returns to the password screen |
| Failed attempt | Shows `Incorrect password` — the same message for every failure |
| Enter key | Submits, because the field lives in a real `<form>` |
| Tunnel URL | **Not requested at all** while locked; the launcher markup is `hidden` |
| Unconfigured / no Web Crypto | Fails closed with an explanatory message |

Because authorization lives in `sessionStorage`, a refresh stays unlocked but
opening the link in a new tab asks again. That is the intent of the setting, not an
oversight.

### Accessibility and mobile

- `<label for="password">`, `type="password"`, `autocomplete="current-password"`.
- Error text is a polite live region (`aria-live="polite"`), and the field points
  at it with `aria-describedby`.
- Visible `:focus-visible` outlines on the input and every button.
- 2.75 rem (44 px) minimum input and button height, full-width card, no horizontal
  scrolling at narrow widths.
- The page also carries `<meta name="robots" content="noindex, nofollow">`.

---

## Files

| File | Purpose |
|---|---|
| `index.html` | Markup and styles. Dark/cyan theme matching the SL RAT dashboard. |
| `launcher-gate.js` | All gate logic. Usable from Node (`module.exports`) as well as the browser. |
| `launcher-config.js` | **The only file to edit.** Holds the SHA-256 hash and the `CONFIGURED` flag. |
| `generate-password-hash.ps1` | Secure prompt that prints the hash. |
| `public-url.json` | The current tunnel URL. **Written by the publishing script, not by hand.** |
| `tests/launcher-gate.test.mjs` | Dependency-free behavioural tests. |

## Tests

```powershell
node --test tests/launcher-gate.test.mjs
```

The tests drive the real `launcher-gate.js` against a small DOM stub and the real
Web Crypto API. They cover: the launcher staying hidden and unrequested while
locked, wrong-password rejection, correct-hash acceptance, SHA-256 known-answer
vectors, refresh staying unlocked, logout relocking, Enter submitting, the
not-configured and no-Web-Crypto fail-closed paths, hostile `sessionStorage`,
URL validation against open-redirect payloads, the absence of any plain-text
password in source, mobile and accessibility markup, and the unchanged
`public-url.json` publishing contract.

They test behaviour, not security. Nothing here can make a client-side gate secure.

## Updating the tunnel URL

The tunnel URL is **not** edited in this repository. It is written by the publishing
script that lives in the dashboard project:

```powershell
E:\Development\Utilities Dashboard\publish-public-url.ps1
```

That script reads `E:\Development\Utilities Dashboard\config\public-url.txt`,
validates it is an HTTPS Cloudflare Quick Tunnel URL, rewrites `public-url.json`
here, and commits and pushes. The launcher gate does not interfere with that flow,
and the `public-url.json` single-key shape is unchanged.

---

## Production recommendation

For real access control, replace this gate. In rough order of fit:

1. **Cloudflare Access / Zero Trust** — put an identity provider in front of the
   dashboard hostname. Email OTP, Google, or a City AD/Entra ID. No application
   code to maintain, and it produces real audit logs. **This is the preferred
   option.**
2. **A stable named Cloudflare Tunnel on a custom hostname** instead of a Quick
   Tunnel. A Quick Tunnel address is random on every restart, is not something you
   can put in a DNS record, an access policy, or a firewall allow-list, and expires
   without warning. A named tunnel on something like `dashboards.melbourne.fl.us`
   is prerealisable for an Access policy and does not change every night.
3. **City-managed reverse-proxy or IIS authentication** if the dashboard runs
   behind an existing City web platform. Windows Authentication / integrated auth
   keeps access tied to existing City credentials and offboarding.

Do not extend the client-side gate. Adding client-side complexity to a public
static page cannot raise it above a deterrent.

## Licence / ownership

Internal City of Melbourne utility. Contains no credentials, no tokens, and no
utility data — only a link.
