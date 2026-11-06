// SlimIdentity Playground – plain ES module, no dependencies.
// Everything from the server (mails, addresses, JSON) is inserted with textContent only – never as HTML.

const $ = (id) => document.getElementById(id);
const state = { accessToken: null, refreshToken: null, preAuthToken: null, rememberToken: null, totpSecret: null, link: null };

// ------------------------------------------------------------------ HTTP

function mode() { return $("mode").value; }

async function call(method, path, body) {
  const headers = { "Content-Type": "application/json", "X-CSRF": "1" };   // CSRF header: required in cookie mode
  if (mode() === "bearer" && state.accessToken) headers.Authorization = `Bearer ${state.accessToken}`;
  const url = path.startsWith("/auth/") && ["/auth/login", "/auth/invitation/accept"].includes(path) ? `${path}?useCookies=${mode() === "cookie"}` : path;
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
  async register() {
    await call("POST", "/auth/register", { email: email(), password: password() });
    $("mailboxAddress").value = email();
  },

  async login() {
    const r = await call("POST", "/auth/login", {
      email: email(), password: password(), rememberMe: $("rememberMe").checked,
      twoFactorRememberToken: mode() === "bearer" ? state.rememberToken : null,
    });
    if (r.status === 401 && r.json?.status === "requires_two_factor") {
      state.preAuthToken = r.json.preAuthToken;
      $("challengeMethod").textContent = r.json.twoFactorMethod === "totp" ? "authenticator app" : "code sent by e-mail";
      $("challenge").hidden = false;
      $("mailboxAddress").value = email();
      return;
    }
    $("challenge").hidden = true;
    if (r.ok) storeSession(r.json);
    await updateWho();
  },

  async virtualCode() {
    if (!state.totpSecret) { alert("No authenticator set up in this browser – set one up first (Two-factor panel)."); return; }
    $("code").value = await totp(state.totpSecret);
  },

  async secondFactor() {
    const r = await call("POST", "/auth/login/2fa", {
      preAuthToken: state.preAuthToken, code: $("code").value || null, recoveryCode: $("recoveryCode").value || null,
      rememberDevice: $("rememberDevice").checked,
    });
    if (r.ok) { storeSession(r.json); $("challenge").hidden = true; $("code").value = ""; $("recoveryCode").value = ""; }
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
  },

  async logoutAll() {
    await call("POST", "/auth/logout-all", {});
    state.accessToken = state.refreshToken = null;
    await updateWho();
  },

  async resendVerification() { await call("POST", "/auth/resend-verification", { email: email() }); },

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
    const r = await call("POST", "/auth/2fa/enable", { setupToken: state.setupToken, code: await totp(state.totpSecret) });
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

  async completeLink() {
    const { kind, token } = state.link ?? {};
    if (kind === "reset-password") await call("POST", "/auth/reset-password", { token, newPassword: $("linkPassword").value });
    if (kind === "accept-invitation") { const r = await call("POST", "/auth/invitation/accept", { token, password: $("linkPassword").value }); if (r.ok) storeSession(r.json); }
    $("linkForm").hidden = true;
    history.replaceState(null, "", "/");
    await updateWho();
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

// ------------------------------------------------------------------ links from mails

async function handleLinkPage() {
  const kind = location.pathname.slice(1);
  const token = new URLSearchParams(location.search).get("token");
  if (!token) return;
  if (kind === "verify-email") { await call("POST", "/auth/verify-email", { token }); history.replaceState(null, "", "/"); }
  else if (kind === "confirm-email-change") { await call("POST", "/auth/confirm-email-change", { token }); history.replaceState(null, "", "/"); }
  else if (kind === "reset-password" || kind === "accept-invitation") {
    state.link = { kind, token };
    $("linkTitle").textContent = kind === "reset-password" ? "Set a new password" : "Accept the invitation – choose a password";
    if (kind === "accept-invitation") {
      const info = await call("POST", "/auth/invitation/info", { token });
      if (info.ok) $("linkTitle").textContent += ` for ${info.json.email}`;
    }
    $("linkForm").hidden = false;
  }
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

const info = await (await fetch("/api/playground/info")).json();
$("breakme").hidden = !info.breakme;
if (!info.jwtEnabled) { $("mode").querySelector("[value=bearer]").disabled = true; }
await handleLinkPage();
await updateWho();
