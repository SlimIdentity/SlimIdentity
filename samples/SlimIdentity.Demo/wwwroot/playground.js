// SlimIdentity Playground – plain ES module, no dependencies.
// Everything from the server (mails, addresses, JSON) is inserted with textContent only – never as HTML.

import { installVirtualPasskey } from "./virtual-passkey.js";

const $ = (id) => document.getElementById(id);
const state = { accessToken: null, refreshToken: null, flowToken: null, step: null, rememberToken: null, totpSecret: null };

// ------------------------------------------------------------------ HTTP

function mode() { return $("mode").value; }

async function call(method, path, body) {
  const headers = { "Content-Type": "application/json", "X-CSRF": "1" };   // CSRF header: required in cookie mode
  if (mode() === "bearer" && state.accessToken) headers.Authorization = `Bearer ${state.accessToken}`;
  const url = path.startsWith("/auth/") && ["/auth/login", "/auth/register", "/auth/flow"].includes(path) ? `${path}?useCookies=${mode() === "cookie"}` : path;
  const response = await fetch(url, { method, headers, credentials: "same-origin", body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await response.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
  log(method, path, response.status, json ?? text);
  return { status: response.status, ok: response.ok, json };
}

function log(method, path, status, payload) {
  const li = document.createElement("li");
  const head = document.createElement("span");
  head.textContent = `${method} ${path} → ${status}`;
  head.className = status < 400 ? "status-ok" : "status-err";
  const pre = document.createElement("pre");
  pre.textContent = typeof payload === "string" ? payload : JSON.stringify(redact(payload), null, 2);
  li.append(head, pre);
  $("log").prepend(li);
  while ($("log").children.length > 40) $("log").lastChild.remove();
}

// tokens are shortened in the log – they are secrets, even in a playground
function redact(value) {
  if (!value || typeof value !== "object") return value;
  const copy = Array.isArray(value) ? [...value] : { ...value };
  for (const [key, v] of Object.entries(copy)) {
    if (typeof v === "string" && /token/i.test(key) && v.length > 24) copy[key] = `${v.slice(0, 12)}…(${v.length})`;
    else if (v && typeof v === "object") copy[key] = redact(v);
  }
  return copy;
}

function storeSession(auth) {
  if (!auth) return;
  if (auth.accessToken) state.accessToken = auth.accessToken;
  if (auth.refreshToken) state.refreshToken = auth.refreshToken;
  if (auth.twoFactorRememberToken) state.rememberToken = auth.twoFactorRememberToken;
}

async function updateWho() {
  const me = await fetch("/auth/me", { headers: mode() === "bearer" && state.accessToken ? { Authorization: `Bearer ${state.accessToken}` } : {} });
  if (!me.ok) { $("who").textContent = "not signed in"; return; }
  const json = await me.json();
  $("who").textContent = `signed in as ${json.email}${json.isImpersonating ? ` (impersonated by ${json.impersonatorId})` : ""} · ${mode()}`;
}

const email = () => $("email").value.trim();
const password = () => $("password").value;

// ------------------------------------------------------------------ actions

const actions = {
  // registration: the address first, the password once the mailbox is proven (code or link)
  async register() {
    state.registration = true;
    const r = await call("POST", "/auth/register", { email: email(), rememberMe: $("rememberMe").checked });
    showSteps(r.json);
    $("mailboxAddress").value = email();
  },

  async login() {
    state.registration = false;
    const r = await call("POST", "/auth/login", {
      email: email(), password: password(), rememberMe: $("rememberMe").checked,
      twoFactorRememberToken: mode() === "bearer" ? state.rememberToken : null,
    });
    if (showSteps(r.json)) { $("mailboxAddress").value = email(); return; }
    $("challenge").hidden = true;
    if (r.ok) storeSession(r.json);
    await updateWho();
  },

  async virtualCode() {
    if (!state.totpSecret) { alert("No authenticator set up in this browser – set one up first (Two-factor panel)."); return; }
    $("code").value = await totp(state.totpSecret);
  },

  async secondFactor() {
    const r = state.step === "set_credential"
      ? await call("POST", "/auth/register/password", { flowToken: state.flowToken, password: password() })
      : state.step === "verify_email"
      ? await call("POST", state.registration ? "/auth/register/verify" : "/auth/login/verify-email", { flowToken: state.flowToken, code: $("code").value || null })
      : await call("POST", "/auth/login/2fa", {
        flowToken: state.flowToken, code: $("code").value || null, recoveryCode: $("recoveryCode").value || null,
        rememberDevice: $("rememberDevice").checked,
      });
    if (r.ok) { $("code").value = ""; $("recoveryCode").value = ""; }
    if (r.ok && !showSteps(r.json)) { storeSession(r.json); $("challenge").hidden = true; }
    await updateWho();
  },

  async me() { await call("GET", "/auth/me"); },

  async refresh() {
    const r = await call("POST", "/auth/refresh", { refreshToken: state.refreshToken });
    if (r.ok) storeSession(r.json);
  },

  async logout() {
    await call("POST", "/auth/logout", { refreshToken: state.refreshToken });
    state.accessToken = state.refreshToken = null;
    await updateWho();
    startAutofill();
  },

  async logoutAll() {
    await call("POST", "/auth/logout-all", {});
    state.accessToken = state.refreshToken = null;
    await updateWho();
  },


  async setup2fa() {
    const r = await call("POST", "/auth/2fa/setup", {});
    if (!r.ok) return;
    state.setupToken = r.json.setupToken;
    state.totpSecret = r.json.sharedKey.replace(/\s/g, "");
    $("sharedKey").textContent = r.json.sharedKey;
    $("otpauth").textContent = r.json.authenticatorUri;
    $("authenticator").hidden = false;
  },

  async enable2fa() {
    if (!state.setupToken) { alert("Set up the authenticator first."); return; }
    const r = await call("POST", "/auth/2fa/enable", { setupToken: state.setupToken, code: await totp(state.totpSecret), password: password() });
    if (r.ok) { storeSession(r.json.session); showRecoveryCodes(r.json.recoveryCodes); }
  },

  async enableEmail2fa() {
    const r = await call("POST", "/auth/2fa/enable-email", { password: password() });
    if (r.ok) { storeSession(r.json.session); showRecoveryCodes(r.json.recoveryCodes); }
  },

  async recoveryCodes() {
    const r = await call("POST", "/auth/2fa/recovery-codes", { password: password() });
    if (r.ok) showRecoveryCodes(r.json.recoveryCodes);
  },

  async disable2fa() {
    const r = await call("POST", "/auth/2fa/disable", { password: password() });
    if (r.ok) storeSession(r.json);
  },

  async forgetDevice() { await call("POST", "/auth/2fa/forget-device", {}); state.rememberToken = null; },

  async sessions() {
    const r = await call("GET", "/auth/sessions");
    const list = $("sessionList");
    list.replaceChildren();
    for (const s of r.json ?? []) {
      const li = document.createElement("li");
      li.textContent = `${s.isCurrent ? "▶ this device · " : ""}${s.mode} · ${s.authenticationMethod} · last seen ${new Date(s.lastSeenUtc).toLocaleString()} · ${s.userAgent ?? ""}`;
      if (!s.isCurrent) li.append(button("Sign out this device", async () => { await call("DELETE", `/auth/sessions/${encodeURIComponent(s.id)}`); await actions.sessions(); }));
      list.append(li);
    }
  },

  async forgot() { await call("POST", "/auth/forgot-password", { email: email() }); $("mailboxAddress").value = email(); },
  async changePassword() { const r = await call("POST", "/auth/change-password", { currentPassword: password(), newPassword: $("newValue").value }); if (r.ok) storeSession(r.json); },
  async changeEmail() { await call("POST", "/auth/change-email", { newEmail: $("newValue").value, password: password() }); $("mailboxAddress").value = $("newValue").value; },

  async mailbox() {
    const address = $("mailboxAddress").value.trim() || email();
    const r = await call("GET", `/api/playground/mailbox?address=${encodeURIComponent(address)}`);
    const list = $("mails");
    list.replaceChildren();
    for (const mail of r.json ?? []) {
      const li = document.createElement("li");
      const title = document.createElement("strong");
      title.textContent = `${mail.subject} · ${new Date(mail.sentAt).toLocaleTimeString()}`;
      const body = document.createElement("div");
      body.className = "small";
      body.textContent = mail.body;
      li.append(title, body);
      const link = safeLink(mail.body);
      if (link) li.append(button("Open link", () => { location.href = link; }));
      list.append(li);
    }
  },

  async users() {
    const r = await call("GET", "/api/admin/users");
    const list = $("userList");
    list.replaceChildren();
    for (const u of r.json ?? []) {
      const li = document.createElement("li");
      li.textContent = `${u.email} · ${u.isActive ? "active" : "banned"}${u.twoFactorEnabled ? " · 2FA" : ""}`;
      li.append(button("Impersonate", async () => {
        const i = await call("POST", `/api/admin/impersonate/${encodeURIComponent(u.id)}?useCookies=${mode() === "cookie"}`, {});
        if (i.ok) storeSession(i.json);
        await updateWho();
      }));
      list.append(li);
    }
  },

  // ---------------------------------------------------------------- passkeys (WebAuthn)

  async addPasskey() {
    stopAutofill();   // the browser runs one WebAuthn request at a time
    // in the registration step set_credential the passkey becomes the first sign-in method of the new account
    const registering = state.step === "set_credential" && !$("challenge").hidden;
    const start = registering
      ? await call("POST", "/auth/register/passkey/options", { flowToken: state.flowToken })
      : await call("POST", "/auth/passkeys/register/options", { password: password() || null });
    if (start.ok) {
      const { options, state: ceremony } = start.json;
      const credential = await navigator.credentials.create({
        publicKey: {
          ...options,
          challenge: fromB64url(options.challenge),
          user: { ...options.user, id: fromB64url(options.user.id) },
          excludeCredentials: options.excludeCredentials.map((c) => ({ type: c.type, id: fromB64url(c.id) })),
        },
      }).catch((e) => { log("WebAuthn", "create", 0, e.message); return null; });
      if (credential) {
        const r = await call("POST", registering ? "/auth/register/passkey" : "/auth/passkeys/register", {
          flowToken: registering ? state.flowToken : undefined,
          state: ceremony,
          name: $("passkeyName").value || null,
          credential: {
            id: credential.id, rawId: b64url(credential.rawId), type: credential.type,
            response: {
              clientDataJSON: b64url(credential.response.clientDataJSON),
              attestationObject: b64url(credential.response.attestationObject),
              transports: credential.response.getTransports?.() ?? [],
            },
          },
        });
        if (registering) {
          if (r.ok && !showSteps(r.json)) { storeSession(r.json); $("challenge").hidden = true; }
          await updateWho();
        }
        else await actions.signInMethods();
      }
    }
    startAutofill();
  },

  async loginPasskey() {
    stopAutofill();
    await passkeySignIn();
    startAutofill();
  },

  pickAutofill() { virtual?.pickForAutofill(); },

  async signInMethods() {
    const r = await call("GET", "/auth/sign-in-methods");
    const list = $("methodList");
    list.replaceChildren();
    if (!r.ok) return;
    const item = (text) => { const li = document.createElement("li"); li.textContent = text; list.append(li); return li; };
    item(r.json.hasPassword ? "Password" : "No password (a fresh sign-in confirms changes)");
    for (const e of r.json.externalLogins) item(`External login: ${e.provider}`);
    for (const p of r.json.passkeys) {
      const synced = p.backedUp ? "synced" : p.backupEligible ? "may be synced" : "this device only";
      const used = p.lastUsedUtc ? ` · last used ${new Date(p.lastUsedUtc).toLocaleString()}` : "";
      const li = item(`Passkey "${p.name}" · ${synced} · added ${new Date(p.createdUtc).toLocaleString()}${used}`);
      li.append(button("Rename", async () => {
        const name = prompt("New name", p.name);
        if (name) { await call("POST", "/auth/sign-in-methods/passkeys/rename", { id: p.id, name }); await actions.signInMethods(); }
      }));
      li.append(button("Remove", async () => {
        await call("POST", "/auth/sign-in-methods/passkeys/remove", { id: p.id, password: password() || null });
        await actions.signInMethods();
      }));
    }
  },

  async stopImpersonation() { const r = await call("POST", "/api/admin/impersonate/stop", {}); if (r.ok) storeSession(r.json); await updateWho(); },
  async adminOnly() { await call("GET", "/api/admin"); },
  clearLog() { $("log").replaceChildren(); },
};

function button(text, onClick) {
  const b = document.createElement("button");
  b.textContent = text;
  b.addEventListener("click", onClick);
  const row = document.createElement("div");
  row.className = "row";
  row.append(b);
  return row;
}

function showRecoveryCodes(codes) {
  alert(`Recovery codes – shown once:\n\n${(codes ?? []).join("\n")}`);
}

// only links back into this playground are offered as buttons
function safeLink(text) {
  const match = /https?:\/\/[^\s]+/.exec(text);
  if (!match) return null;
  try {
    const url = new URL(match[0]);
    return url.origin === location.origin ? url.pathname + url.search : null;
  } catch { return null; }
}

// ------------------------------------------------------------------ passkeys: sign-in and autofill

const b64url = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64url = (text) => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=")), (c) => c.charCodeAt(0));

let virtual = null;
let autofill = null;

/** One sign-in: options, the authenticator (dialog or – with a signal – autofill), the server. */
async function passkeySignIn(signal) {
  const start = await call("POST", "/auth/passkeys/login/options", {});
  if (!start.ok) return;
  const { options, state: ceremony } = start.json;
  const credential = await navigator.credentials.get({
    publicKey: { ...options, challenge: fromB64url(options.challenge), allowCredentials: [] },
    ...(signal ? { mediation: "conditional", signal } : {}),
  }).catch((e) => { if (!signal?.aborted) log("WebAuthn", "get", 0, e.message); return null; });
  if (!credential) return;
  const r = await call("POST", `/auth/passkeys/login?useCookies=${mode() === "cookie"}`, {
    state: ceremony,
    rememberMe: $("rememberMe").checked,
    credential: {
      id: credential.id, rawId: b64url(credential.rawId), type: credential.type,
      response: {
        clientDataJSON: b64url(credential.response.clientDataJSON),
        authenticatorData: b64url(credential.response.authenticatorData),
        signature: b64url(credential.response.signature),
        userHandle: credential.response.userHandle ? b64url(credential.response.userHandle) : null,
      },
    },
  });
  if (r.ok) storeSession(r.json);
  await updateWho();
}

// autofill: a conditional request waits in the background while the page is open; the state of a ceremony lives
// 5 minutes, so a fresh one is fetched every 4
async function startAutofill() {
  stopAutofill();
  if (!(await window.PublicKeyCredential?.isConditionalMediationAvailable?.())) return;
  const controller = new AbortController();
  autofill = controller;
  while (!controller.signal.aborted) {
    const round = new AbortController();
    const stop = () => round.abort();
    controller.signal.addEventListener("abort", stop, { once: true });
    const timer = setTimeout(stop, 4 * 60_000);
    await passkeySignIn(round.signal);
    clearTimeout(timer);
    if (!round.signal.aborted) break;   // signed in (or failed): no new offer until the next sign-out
  }
}

function stopAutofill() { autofill?.abort(); autofill = null; }

function applyVirtualPasskey() {
  stopAutofill();
  if ($("virtualPasskey").checked) virtual ??= installVirtualPasskey((name) => { $("autofillOffer").hidden = !name; $("autofillName").textContent = name ?? ""; });
  else { virtual?.uninstall(); virtual = null; $("autofillOffer").hidden = true; }
  startAutofill();
}

// ------------------------------------------------------------------ external login (only with a configured provider)

// a full-page navigation to the provider; bearer clients bind the one-time code to themselves with PKCE
async function externalLogin(provider) {
  const returnUrl = encodeURIComponent("/");   // a local path – always allowed, whatever port the demo runs on
  sessionStorage.setItem("slim.mode", mode());   // the page reloads on the way back
  if (mode() === "cookie") { location.href = `/auth/login/${provider}?useCookies=true&returnUrl=${returnUrl}`; return; }
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  sessionStorage.setItem("slim.pkce", verifier);
  const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  location.href = `/auth/login/${provider}?useCookies=false&returnUrl=${returnUrl}&code_challenge=${challenge}&code_challenge_method=S256`;
}

// a sign-in with open steps ("action_required"): the playground shows the mailbox and second-factor steps; others only in the log
function showSteps(json) {
  if (json?.status !== "action_required") return false;
  state.flowToken = json.flowToken;
  state.step = json.actions[0];
  if (state.step === "verify_email" || state.step === "second_factor") {
    const method = state.step === "verify_email" ? "email" : json.details?.secondFactor?.methods?.[0];
    $("challengeTitle").textContent = state.step === "verify_email" ? "Confirm your e-mail address" : "Second factor required";
    $("challengeMethod").textContent = method === "totp" ? "authenticator app" : method === "email" ? "code sent by e-mail" : "recovery code";
    $("challenge").hidden = false;
  }
  else if (state.step === "set_credential") {
    $("challengeTitle").textContent = "Address confirmed – enter a password above, then Continue (or Add passkey)";
    $("challengeMethod").textContent = "registration";
    $("challenge").hidden = false;
  }
  return true;
}

// back from the provider: an error in the query, secrets in the fragment (never sent to a server)
async function handleExternalReturn() {
  const error = new URLSearchParams(location.search).get("slim_error");
  const fragment = new URLSearchParams(location.hash.slice(1));
  if (!error && !fragment.size) return;
  history.replaceState(null, "", "/");
  const started = sessionStorage.getItem("slim.mode");
  sessionStorage.removeItem("slim.mode");
  if (started) { $("mode").value = started; document.body.classList.toggle("bearer", started === "bearer"); }
  if (error) { log("GET", "external login", 0, `slim_error=${error}`); return; }
  if (fragment.get("slim_status") === "action_required") {
    const r = await call("POST", "/auth/flow", { flowToken: fragment.get("flowToken") });   // names the open steps
    showSteps(r.json);
    return;
  }
  if (fragment.get("code")) {
    const r = await call("POST", "/auth/login/external/exchange", { code: fragment.get("code"), codeVerifier: sessionStorage.getItem("slim.pkce") });
    sessionStorage.removeItem("slim.pkce");
    if (!showSteps(r.json) && r.ok) storeSession(r.json);
  }
}

// ------------------------------------------------------------------ links from mails

async function handleLinkPage() {
  const kind = location.pathname.slice(1);
  const token = new URLSearchParams(location.search).get("token");
  if (!token) return;
  if (kind === "verify-email" || kind === "reset-password" || kind === "accept-invitation") {
    // every link continues as a flow ending in set_credential, like a registration
    state.registration = kind === "verify-email";
    showSteps((await call("POST", "/auth/flow", { token })).json);
    history.replaceState(null, "", "/");
  }
  else if (kind === "confirm-email-change") { await call("POST", "/auth/confirm-email-change", { token }); history.replaceState(null, "", "/"); }
}

// ------------------------------------------------------------------ virtual authenticator (RFC 6238, WebCrypto)

function base32(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of text.toUpperCase().replace(/=+$/, "")) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  return bytes;
}

async function totp(secret, now = Date.now()) {
  const counter = new DataView(new ArrayBuffer(8));
  counter.setBigUint64(0, BigInt(Math.floor(now / 1000 / 30)));
  const key = await crypto.subtle.importKey("raw", base32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const hash = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter.buffer));
  const offset = hash[19] & 0x0f;
  const binary = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
  return String(binary % 1_000_000).padStart(6, "0");
}

setInterval(async () => {
  if (!state.totpSecret) return;
  $("liveCode").textContent = await totp(state.totpSecret);
  $("liveTtl").textContent = `(${30 - Math.floor(Date.now() / 1000) % 30} s)`;
}, 1000);

// ------------------------------------------------------------------ start

document.addEventListener("click", async (e) => {
  const action = e.target.closest("[data-action]")?.dataset.action;
  if (action && actions[action]) { e.preventDefault(); await actions[action](); }
});
$("mode").addEventListener("change", async () => { document.body.classList.toggle("bearer", mode() === "bearer"); await updateWho(); });
$("virtualPasskey").addEventListener("change", applyVirtualPasskey);

const info = await (await fetch("/api/playground/info")).json();
$("breakme").hidden = !info.breakme;
if (!info.jwtEnabled) { $("mode").querySelector("[value=bearer]").disabled = true; }
for (const provider of info.providers ?? []) {
  const b = document.createElement("button");
  b.textContent = `Sign in with ${provider}`;
  b.addEventListener("click", () => externalLogin(provider));
  $("providers").append(b);
  $("providers").hidden = false;
}
await handleExternalReturn();
await handleLinkPage();
await updateWho();
applyVirtualPasskey();
