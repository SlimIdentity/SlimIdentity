// SlimIdentity sample – minimal SPA client (framework-agnostic, works in Vue / React / Svelte).
// Shows both flows:
//   1. Cookie flow  – HttpOnly cookie, X-CSRF header on every state-changing request
//   2. Bearer flow  – access token in memory, refresh token rotation on 401
//
// Tip: generate typed clients from /openapi/v1.json instead of hand-writing DTOs.

const API = "https://api.example.com";
const AUTH = `${API}/auth`;

export interface AuthResponse {
  status: "success";
  mode: "cookie" | "bearer";
  accessToken?: string;
  refreshToken?: string;
  expiresIn?: number;
  /** bearer mode, after /login/2fa with rememberDevice */
  twoFactorRememberToken?: string;
}

export interface LoginChallenge {
  status: "invalid_credentials" | "requires_two_factor" | "password_change_required";
  preAuthToken?: string;
  twoFactorMethod?: "totp" | "email" | "recovery";
  passwordChangeToken?: string;
}

export interface SignInMethods {
  hasPassword: boolean;
  externalLogins: { provider: string; providerKey: string }[];
  /** backupEligible: may be synced (iCloud Keychain, password manager); backedUp: currently synced – e.g. "synced" vs "this device only". */
  passkeys: { id: string; name: string; createdUtc: string; lastUsedUtc?: string; backupEligible: boolean; backedUp: boolean }[];
}

export interface SessionInfo {
  id: string;
  mode: "cookie" | "bearer";
  authenticationMethod: string;
  isCurrent: boolean;
  isImpersonation: boolean;
  createdUtc: string;
  lastSeenUtc: string;
  expiresUtc: string;
  userAgent?: string;
  ipAddress?: string;
}

export interface PasswordPolicy {
  minimumLength: number;
  maximumLength: number;
  /** Server-side rules (e.g. breached-password check) – only reported on submit. */
  hasAdditionalRules: boolean;
}

/** Loads the server's password rules (anonymous endpoint) – cache it per page load. */
export async function loadPasswordPolicy(): Promise<PasswordPolicy> {
  return (await fetch(`${AUTH}/password-policy`)).json();
}

/** Live validation as the user types; returns the unmet rules (empty = OK). The server validates again on submit. */
export function checkPassword(password: string, p: PasswordPolicy): string[] {
  const errors: string[] = [];
  if (password.length < p.minimumLength) errors.push(`At least ${p.minimumLength} characters`);
  if (password.length > p.maximumLength) errors.push(`At most ${p.maximumLength} characters`);
  // no character-class rules (NIST SP 800-63B) – encourage long passphrases instead
  return errors;
}

export type LoginResult =
  | { kind: "ok"; auth: AuthResponse }
  | { kind: "two_factor"; preAuthToken: string; method: "totp" | "email" | "recovery" }
  /** The password was set by an administrator: ask for an own one, then call completePasswordChange. */
  | { kind: "password_change"; passwordChangeToken: string }
  | { kind: "locked"; until: string }
  | { kind: "error"; status: string };

/** Answer of the form endpoints: `status` (e.g. "registration_accepted") or the field errors of a 400. */
export type FormResult =
  | { ok: true; status: string }
  | { ok: false; status: string; errors?: Record<string, string[]> };

/**
 * The machine-readable code of an answer: `status` ("invalid_token", "locked_out", …) – for validation errors
 * (RFC 9457, where `status` is the HTTP status number) the `code` "validation_failed".
 */
function codeOf(body: { status?: unknown; code?: unknown }, r: Response): string {
  if (typeof body.status === "string") return body.status;
  return typeof body.code === "string" ? body.code : `http_${r.status}`;
}

async function toFormResult(r: Response): Promise<FormResult> {
  const body = await r.json().catch(() => ({}));
  if (r.ok) return { ok: true, status: body.status ?? "ok" };
  return { ok: false, status: codeOf(body, r), errors: body.errors };
}

function anonymousPost(path: string, body: object): Promise<FormResult> {
  return fetch(`${AUTH}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then(toFormResult);
}

// =====================================================================================
// 0. Account flows without a session (same for cookie and bearer)
//    The answers never reveal whether an address has an account – show the same message in every case.
// =====================================================================================

export const account = {
  /**
   * Registration. `profile` is your business data (company, name, …) – the server validates it with its
   * ISlimRegistrationProfile; field errors come back as `errors["profile.<field>"]`.
   */
  register(email: string, password: string, profile?: object): Promise<FormResult> {
    return anonymousPost("/register", profile === undefined ? { email, password } : { email, password, profile });
  },

  /** Page behind the verification link: /verify-email?token=… */
  verifyEmail(token: string): Promise<FormResult> {
    return anonymousPost("/verify-email", { token });
  },

  resendVerification(email: string): Promise<FormResult> {
    return anonymousPost("/resend-verification", { email });
  },

  forgotPassword(email: string): Promise<FormResult> {
    return anonymousPost("/forgot-password", { email });
  },

  /** Page behind the reset link: /reset-password?token=… – all sessions of the account end. */
  resetPassword(token: string, newPassword: string): Promise<FormResult> {
    return anonymousPost("/reset-password", { token, newPassword });
  },
};

// =====================================================================================
// 1. Cookie flow  (same-site SPA, or app.domain.de -> api.domain.de with SameSite=Lax)
// =====================================================================================

const cookieHeaders = { "Content-Type": "application/json", "X-CSRF": "1" };

async function cookieFetch(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`${API}${path}`, {
    ...init,
    credentials: "include",
    headers: { ...cookieHeaders, ...(init.headers ?? {}) },
  });
}

export const cookieAuth = {
  async login(email: string, password: string, rememberMe = false): Promise<LoginResult> {
    const r = await cookieFetch("/auth/login?useCookies=true", {
      method: "POST",
      body: JSON.stringify({ email, password, rememberMe }),
    });
    return toLoginResult(r);
  },

  /**
   * Authenticator setup: returns a QR code (data URL for an <img>) plus the key for manual entry.
   * QR rendering happens in the browser – e.g. with the "qrcode" npm package:
   *   import QRCode from "qrcode";
   */
  async setupAuthenticator(toQrDataUrl: (text: string) => Promise<string>) {
    const r = await cookieFetch("/auth/2fa/setup", { method: "POST", body: "{}" });
    const setup: { sharedKey: string; authenticatorUri: string; setupToken: string } = await r.json();
    return { ...setup, qrCode: await toQrDataUrl(setup.authenticatorUri) };   // e.g. (uri) => QRCode.toDataURL(uri)
  },

  /** Confirms the first code with the current password; returns the recovery codes – show them exactly once. */
  async enableAuthenticator(setupToken: string, code: string, password: string): Promise<string[]> {
    const r = await cookieFetch("/auth/2fa/enable", { method: "POST", body: JSON.stringify({ setupToken, code, password }) });
    return r.ok ? (await r.json()).recoveryCodes : [];
  },

  /** Turns 2FA off; the session is renewed (cookie). */
  async disableTwoFactor(password: string): Promise<FormResult> {
    return toFormResult(await cookieFetch("/auth/2fa/disable", { method: "POST", body: JSON.stringify({ password }) }));
  },

  /** Replaces all recovery codes – show the new ones exactly once. */
  async regenerateRecoveryCodes(password: string): Promise<string[]> {
    const r = await cookieFetch("/auth/2fa/recovery-codes", { method: "POST", body: JSON.stringify({ password }) });
    return r.ok ? (await r.json()).recoveryCodes : [];
  },

  /** Other devices are signed out, this one gets a new cookie. */
  async changePassword(currentPassword: string, newPassword: string): Promise<FormResult> {
    return toFormResult(await cookieFetch("/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ currentPassword, newPassword }),
    }));
  },

  /** This browser asks for the second factor again. */
  async forgetThisDevice() {
    await cookieFetch("/auth/2fa/forget-device", { method: "POST", body: "{}" });
  },

  /** All remembered devices ask again; other sessions end, this one is renewed. */
  async forgetAllDevices() {
    await cookieFetch("/auth/2fa/forget-all-devices", { method: "POST", body: "{}" });
  },

  /** E-mail change: confirmation link goes to the new address; the page behind it calls confirmEmailChange. */
  async changeEmail(newEmail: string, password: string) {
    await cookieFetch("/auth/change-email", { method: "POST", body: JSON.stringify({ newEmail, password }) });
  },

  async confirmEmailChange(token: string) {
    return (await cookieFetch("/auth/confirm-email-change", { method: "POST", body: JSON.stringify({ token }) })).ok;
  },

  /** "Remember this device" sets a cookie (if TwoFactor.RememberDeviceLifetime is configured on the server). */
  async loginTwoFactor(preAuthToken: string, code: string, rememberDevice = false): Promise<LoginResult> {
    const r = await cookieFetch("/auth/login/2fa", { method: "POST", body: JSON.stringify({ preAuthToken, code, rememberDevice }) });
    return toLoginResult(r);
  },

  /** After { kind: "password_change" }: sets the own password – the result is the session or the 2FA challenge. */
  async completePasswordChange(passwordChangeToken: string, newPassword: string): Promise<LoginResult> {
    const r = await cookieFetch("/auth/login/password-change", {
      method: "POST",
      body: JSON.stringify({ token: passwordChangeToken, newPassword }),
    });
    return toLoginResult(r);
  },

  /** Call after F5 to restore the session state. */
  async me() {
    const r = await cookieFetch("/auth/me");
    return r.ok ? r.json() : null;
  },

  async logout() {
    await cookieFetch("/auth/logout?useCookies=true", { method: "POST", body: "{}" });
  },

  /** "Sign out on all devices" */
  async logoutAll() {
    await cookieFetch("/auth/logout-all", { method: "POST", body: "{}" });
  },

  /** Active devices (requires ISlimSessionStore on the server). */
  async sessions(): Promise<SessionInfo[]> {
    const r = await cookieFetch("/auth/sessions");
    return r.ok ? r.json() : [];
  },

  async revokeSession(id: string) {
    await cookieFetch(`/auth/sessions/${encodeURIComponent(id)}`, { method: "DELETE" });
  },

  /** Invitation page: /accept-invitation?token=... → show e-mail, ask for a password, then accept. */
  async invitationInfo(token: string): Promise<{ email: string; expiresAt: string } | null> {
    const r = await cookieFetch("/auth/invitation/info", { method: "POST", body: JSON.stringify({ token }) });
    return r.ok ? r.json() : null;
  },

  async acceptInvitation(token: string, password: string): Promise<LoginResult> {
    const r = await cookieFetch("/auth/invitation/accept?useCookies=true", {
      method: "POST",
      body: JSON.stringify({ token, password }),
    });
    return toLoginResult(r);
  },

  /** Social login is a full-page navigation, not fetch. */
  loginWith(provider: string) {
    const returnUrl = encodeURIComponent(window.location.origin + "/after-login");
    window.location.href = `${AUTH}/login/${provider}?useCookies=true&returnUrl=${returnUrl}`;
  },

  /**
   * On the /after-login page: the session cookie is set – unless 2FA is required; then the challenge arrives in the
   * URL fragment (#slim_status=requires_two_factor&preAuthToken=…), which is never sent to a server. Errors come as
   * ?slim_error=….
   */
  readExternalLoginResult(): LoginResult {
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const error = new URLSearchParams(window.location.search).get("slim_error");
    history.replaceState(null, "", window.location.pathname);   // remove secrets from the address bar / history
    if (error) return { kind: "error", status: error };
    if (fragment.get("slim_status") === "requires_two_factor")
      return { kind: "two_factor", preAuthToken: fragment.get("preAuthToken") ?? "", method: toTwoFactorMethod(fragment.get("method")) };
    return { kind: "ok", auth: { status: "success", mode: "cookie" } as AuthResponse };
  },

  /**
   * Links a provider (e.g. Google) to the signed-in account – accounts with a password are never joined
   * automatically. Full-page navigation; afterwards call completeLink() on the return page.
   */
  linkWith(provider: string, returnPath = "/settings") {
    return startLink(provider, returnPath);
  },

  /** On the return page of linkWith(): "external_login_linked", or an error code (e.g. invalid_password). */
  completeLink(password?: string): Promise<string> {
    return finishLink((path, init) => cookieFetch(path, init), password);
  },

  /** Password, linked providers and passkeys – for a "sign-in methods" settings page. */
  async signInMethods(): Promise<SignInMethods> {
    return (await cookieFetch("/auth/sign-in-methods")).json();
  },

  /** Sign in with a passkey – no e-mail needed; the browser shows the passkeys of this site. */
  async loginWithPasskey(rememberMe = false): Promise<LoginResult> {
    const assertion = await passkeyAssertion((path, init) => cookieFetch(path, init), true);
    if (typeof assertion === "string") return { kind: "error", status: assertion };
    const r = await cookieFetch("/auth/passkeys/login?useCookies=true", {
      method: "POST",
      body: JSON.stringify({ ...assertion, rememberMe }),
    });
    return toLoginResult(r);
  },

  /**
   * Passkey autofill: the browser offers the passkeys of this site in the e-mail field of the sign-in form – the input
   * needs autocomplete="username webauthn". Start it when the sign-in page opens; it waits until the user picks a
   * passkey. Abort the signal before any other sign-in (password, passkey button) – one WebAuthn request at a time.
   * Resolves with the session, or { kind: "error", status: "unsupported" | "cancelled" | … }.
   */
  async loginWithPasskeyAutofill(signal: AbortSignal, rememberMe = false): Promise<LoginResult> {
    const assertion = await passkeyAutofill((path, init) => cookieFetch(path, init), true, signal);
    if (typeof assertion === "string") return { kind: "error", status: assertion };
    return toLoginResult(await cookieFetch("/auth/passkeys/login?useCookies=true", {
      method: "POST",
      body: JSON.stringify({ ...assertion, rememberMe }),
    }));
  },

  /** Adds a passkey to the signed-in account ("passkey_added" or an error code). */
  addPasskey(name?: string, password?: string): Promise<string> {
    return addPasskeyWith((path, init) => cookieFetch(path, init), name, password);
  },

  renamePasskey(id: string, name: string): Promise<string> {
    return statusOf(cookieFetch("/auth/sign-in-methods/passkeys/rename", { method: "POST", body: JSON.stringify({ id, name }) }));
  },

  /** "passkey_removed", or last_sign_in_method / invalid_password. */
  removePasskey(id: string, password?: string): Promise<string> {
    return statusOf(cookieFetch("/auth/sign-in-methods/passkeys/remove", { method: "POST", body: JSON.stringify({ id, password }) }));
  },

  /** "external_login_removed", or an error code – last_sign_in_method: add another way in first. */
  removeExternalLogin(provider: string, providerKey: string, password?: string): Promise<string> {
    return removeExternal((path, init) => cookieFetch(path, init), provider, providerKey, password);
  },

  api: cookieFetch,
};

// =====================================================================================
// 2. Bearer flow  (mobile apps, cross-domain SPAs)
// =====================================================================================

let accessToken: string | null = null;                 // memory only, per tab – never in storage
let refreshPromise: Promise<boolean> | null = null;
// Shared by all tabs, so they use one refresh-token chain. (Same XSS exposure as sessionStorage – the real protection
// is a strict CSP. Prefer the cookie flow for browser SPAs; mobile apps use the platform's secure storage instead.)
const REFRESH_KEY = "slim.refresh";
const REMEMBER_KEY = "slim.2fa-remember";              // "remember this device" – mobile: secure storage
const PKCE_KEY = "slim.pkce-verifier";                 // per tab, only between redirect and exchange

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Linking a provider to the signed-in account (both flows): PKCE binds the link code to this tab, so a code from
// someone else's flow planted in the URL is worthless; the session and the password complete it.
const LINK_PKCE_KEY = "slim.link-verifier";

async function startLink(provider: string, returnPath: string) {
  const verifier = base64Url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  sessionStorage.setItem(LINK_PKCE_KEY, verifier);
  const returnUrl = encodeURIComponent(window.location.origin + returnPath);
  window.location.href = `${AUTH}/login/${provider}?link=true&returnUrl=${returnUrl}&code_challenge=${challenge}&code_challenge_method=S256`;
}

async function finishLink(send: (path: string, init: RequestInit) => Promise<Response>, password?: string): Promise<string> {
  const code = new URLSearchParams(window.location.hash.slice(1)).get("slim_link_code");
  const error = new URLSearchParams(window.location.search).get("slim_error");
  const codeVerifier = sessionStorage.getItem(LINK_PKCE_KEY);
  history.replaceState(null, "", window.location.pathname);   // remove the code from the address bar / history
  if (error || !code || !codeVerifier) return error ?? "missing_code";

  const r = await send("/auth/link/external", { method: "POST", body: JSON.stringify({ code, codeVerifier, password }) });
  if (r.ok) sessionStorage.removeItem(LINK_PKCE_KEY);   // kept on a wrong password: the user may try again
  return codeOf(await r.json().catch(() => ({})), r);
}

// Passkeys (WebAuthn): the server sends options with base64url fields; the browser API wants ArrayBuffers.
function fromBase64Url(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0)).buffer;
}

const toBase64Url = (buffer: ArrayBuffer) => base64Url(new Uint8Array(buffer));

async function statusOf(response: Promise<Response>): Promise<string> {
  const r = await response;
  return codeOf(await r.json().catch(() => ({})), r);
}

async function addPasskeyWith(send: (path: string, init: RequestInit) => Promise<Response>, name?: string, password?: string): Promise<string> {
  const start = await send("/auth/passkeys/register/options", { method: "POST", body: JSON.stringify({ password }) });
  if (!start.ok) return statusOf(Promise.resolve(start));
  const { options, state } = await start.json();

  const credential = await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: fromBase64Url(options.challenge),
      user: { ...options.user, id: fromBase64Url(options.user.id) },
      excludeCredentials: options.excludeCredentials.map((c: { type: "public-key"; id: string }) => ({ type: c.type, id: fromBase64Url(c.id) })),
    },
  }).catch(() => null) as PublicKeyCredential | null;
  if (!credential) return "cancelled";

  const response = credential.response as AuthenticatorAttestationResponse;
  return statusOf(send("/auth/passkeys/register", {
    method: "POST",
    body: JSON.stringify({
      state,
      name,
      credential: {
        id: credential.id,
        rawId: toBase64Url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: toBase64Url(response.clientDataJSON),
          attestationObject: toBase64Url(response.attestationObject),
          transports: response.getTransports?.() ?? [],
        },
      },
    }),
  })).then(status => (status === "http_200" ? "passkey_added" : status));
}

async function passkeyAssertion(send: (path: string, init: RequestInit) => Promise<Response>, useCookies: boolean,
    conditional?: AbortSignal): Promise<{ state: string; credential: object } | string> {
  // the mode tells the server whether the anti-forgery check applies to this anonymous call
  const start = await send(`/auth/passkeys/login/options?useCookies=${useCookies}`, { method: "POST", body: "{}" });
  if (!start.ok) return statusOf(Promise.resolve(start));
  const { options, state } = await start.json();

  const credential = await navigator.credentials.get({
    publicKey: { ...options, challenge: fromBase64Url(options.challenge), allowCredentials: [] },
    // autofill: no dialog – the browser offers the passkeys in the input marked autocomplete="username webauthn"
    ...(conditional ? { mediation: "conditional" as CredentialMediationRequirement, signal: conditional } : {}),
  }).catch(() => null) as PublicKeyCredential | null;
  if (!credential) return "cancelled";

  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    state,
    credential: {
      id: credential.id,
      rawId: toBase64Url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: toBase64Url(response.clientDataJSON),
        authenticatorData: toBase64Url(response.authenticatorData),
        signature: toBase64Url(response.signature),
        userHandle: response.userHandle ? toBase64Url(response.userHandle) : null,
      },
    },
  };
}

// The server's sign-in state lives 5 minutes, an autofill request waits as long as the page is open: fetch a fresh
// challenge every 4 minutes until the user picks a passkey or the caller aborts.
async function passkeyAutofill(send: (path: string, init: RequestInit) => Promise<Response>, useCookies: boolean,
    signal: AbortSignal): Promise<{ state: string; credential: object } | string> {
  if (!(await PublicKeyCredential.isConditionalMediationAvailable?.())) return "unsupported";
  while (!signal.aborted) {
    const round = new AbortController();
    const stop = () => round.abort();
    signal.addEventListener("abort", stop, { once: true });
    const timer = setTimeout(stop, 4 * 60_000);
    try {
      const result = await passkeyAssertion(send, useCookies, round.signal);
      if (result !== "cancelled" || !round.signal.aborted) return result;   // picked, failed – or the browser refused
    } finally {
      clearTimeout(timer);
      signal.removeEventListener("abort", stop);
    }
  }
  return "cancelled";
}

async function removeExternal(send: (path: string, init: RequestInit) => Promise<Response>,
  provider: string, providerKey: string, password?: string): Promise<string> {
  const r = await send("/auth/sign-in-methods/external/remove", { method: "POST", body: JSON.stringify({ provider, providerKey, password }) });
  return codeOf(await r.json().catch(() => ({})), r);
}

function storeTokens(auth: AuthResponse) {
  accessToken = auth.accessToken ?? null;
  if (auth.refreshToken) localStorage.setItem(REFRESH_KEY, auth.refreshToken);
  if (auth.twoFactorRememberToken) localStorage.setItem(REMEMBER_KEY, auth.twoFactorRememberToken);
}

// Refresh tokens are single use: presenting one twice counts as theft and ends the session (RFC 9700 reuse
// detection). Two tabs refreshing at the same moment would trigger exactly that. The Web Locks API serializes the
// refresh across all tabs of the origin, and the token is read from the shared storage *inside* the lock – so no tab
// ever sends a token another tab has already used. (Within one tab, parallel calls share one promise.)
async function refresh(): Promise<boolean> {
  refreshPromise ??= navigator.locks.request("slim-refresh", async () => {
    const refreshToken = localStorage.getItem(REFRESH_KEY);
    if (!refreshToken) return false;
    const r = await fetch(`${AUTH}/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken }),
    });
    if (!r.ok) { bearerAuth.clear(); return false; }
    storeTokens(await r.json());
    return true;
  }).finally(() => (refreshPromise = null));
  return refreshPromise;
}

async function bearerFetch(path: string, init: RequestInit = {}, retry = true): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
  const r = await fetch(`${API}${path}`, { ...init, headers });
  if (r.status === 401 && retry && (await refresh())) return bearerFetch(path, init, false);
  return r;
}

export const bearerAuth = {
  async login(email: string, password: string): Promise<LoginResult> {
    const twoFactorRememberToken = localStorage.getItem(REMEMBER_KEY) ?? undefined;   // skips 2FA on a remembered device
    const r = await fetch(`${AUTH}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, twoFactorRememberToken }),
    });
    const result = await toLoginResult(r);
    if (result.kind === "ok") storeTokens(result.auth);
    return result;
  },

  async loginTwoFactor(preAuthToken: string, code: string, rememberDevice = false): Promise<LoginResult> {
    const r = await fetch(`${AUTH}/login/2fa`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ preAuthToken, code, rememberDevice }),
    });
    const result = await toLoginResult(r);
    if (result.kind === "ok") storeTokens(result.auth);
    return result;
  },

  /** After { kind: "password_change" }: sets the own password – the result is the session or the 2FA challenge. */
  async completePasswordChange(passwordChangeToken: string, newPassword: string): Promise<LoginResult> {
    const r = await fetch(`${AUTH}/login/password-change`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: passwordChangeToken, newPassword }),
    });
    const result = await toLoginResult(r);
    if (result.kind === "ok") storeTokens(result.auth);
    return result;
  },

  /**
   * Social login for bearer clients: full-page navigation with a PKCE challenge (RFC 7636, S256). The verifier stays
   * in this tab; whoever intercepts the redirect gets a code that is worthless without it.
   */
  async loginWith(provider: string) {
    const verifier = base64Url(crypto.getRandomValues(new Uint8Array(32)));
    const challenge = base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
    sessionStorage.setItem(PKCE_KEY, verifier);
    const returnUrl = encodeURIComponent(window.location.origin + "/after-login");
    window.location.href = `${AUTH}/login/${provider}?useCookies=false&returnUrl=${returnUrl}`
      + `&code_challenge=${challenge}&code_challenge_method=S256`;
  },

  /** On the /after-login page: the one-time code is in the fragment (#code=…); redeem it with the PKCE verifier. */
  async completeExternalLogin(): Promise<LoginResult> {
    const code = new URLSearchParams(window.location.hash.slice(1)).get("code");
    const error = new URLSearchParams(window.location.search).get("slim_error");
    const codeVerifier = sessionStorage.getItem(PKCE_KEY);
    sessionStorage.removeItem(PKCE_KEY);
    history.replaceState(null, "", window.location.pathname);   // remove the code from the address bar / history
    if (error || !code || !codeVerifier) return { kind: "error", status: error ?? "missing_code" };

    const twoFactorRememberToken = localStorage.getItem(REMEMBER_KEY) ?? undefined;
    const r = await fetch(`${AUTH}/login/external/exchange`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, codeVerifier, twoFactorRememberToken }),
    });
    const result = await toLoginResult(r);   // tokens – or a 2FA challenge (continue with loginTwoFactor)
    if (result.kind === "ok") storeTokens(result.auth);
    return result;
  },

  async logout() {
    const refreshToken = localStorage.getItem(REFRESH_KEY);
    await fetch(`${AUTH}/logout`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken }),
    });
    bearerAuth.clear();
  },

  clear() {
    accessToken = null;
    localStorage.removeItem(REFRESH_KEY);
  },

  /** Links a provider to the signed-in account (see cookieAuth.linkWith). */
  linkWith(provider: string, returnPath = "/settings") {
    return startLink(provider, returnPath);
  },

  /** On the return page of linkWith(): "external_login_linked", or an error code. */
  completeLink(password?: string): Promise<string> {
    return finishLink((path, init) => bearerFetch(path, init), password);
  },

  async signInMethods(): Promise<SignInMethods> {
    return (await bearerFetch("/auth/sign-in-methods")).json();
  },

  async loginWithPasskey(): Promise<LoginResult> {
    const anonymous = (path: string, init: RequestInit) =>
      fetch(`${API}${path}`, { ...init, headers: { "Content-Type": "application/json" } });
    const assertion = await passkeyAssertion(anonymous, false);
    if (typeof assertion === "string") return { kind: "error", status: assertion };
    const result = await toLoginResult(await anonymous("/auth/passkeys/login?useCookies=false", {
      method: "POST",
      body: JSON.stringify(assertion),
    }));
    if (result.kind === "ok") storeTokens(result.auth);
    return result;
  },

  /** Passkey autofill – see cookieAuth.loginWithPasskeyAutofill. */
  async loginWithPasskeyAutofill(signal: AbortSignal): Promise<LoginResult> {
    const anonymous = (path: string, init: RequestInit) =>
      fetch(`${API}${path}`, { ...init, headers: { "Content-Type": "application/json" } });
    const assertion = await passkeyAutofill(anonymous, false, signal);
    if (typeof assertion === "string") return { kind: "error", status: assertion };
    const result = await toLoginResult(await anonymous("/auth/passkeys/login?useCookies=false", {
      method: "POST",
      body: JSON.stringify(assertion),
    }));
    if (result.kind === "ok") storeTokens(result.auth);
    return result;
  },

  addPasskey(name?: string, password?: string): Promise<string> {
    return addPasskeyWith((path, init) => bearerFetch(path, init), name, password);
  },

  renamePasskey(id: string, name: string): Promise<string> {
    return statusOf(bearerFetch("/auth/sign-in-methods/passkeys/rename", { method: "POST", body: JSON.stringify({ id, name }) }));
  },

  removePasskey(id: string, password?: string): Promise<string> {
    return statusOf(bearerFetch("/auth/sign-in-methods/passkeys/remove", { method: "POST", body: JSON.stringify({ id, password }) }));
  },

  removeExternalLogin(provider: string, providerKey: string, password?: string): Promise<string> {
    return removeExternal((path, init) => bearerFetch(path, init), provider, providerKey, password);
  },

  /** Other devices are signed out; this client gets new tokens. */
  async changePassword(currentPassword: string, newPassword: string): Promise<FormResult> {
    const r = await bearerFetch("/auth/change-password", { method: "POST", body: JSON.stringify({ currentPassword, newPassword }) });
    if (r.ok) storeTokens(await r.clone().json());
    return toFormResult(r);
  },

  /** Turns 2FA off; this client gets new tokens. */
  async disableTwoFactor(password: string): Promise<FormResult> {
    const r = await bearerFetch("/auth/2fa/disable", { method: "POST", body: JSON.stringify({ password }) });
    if (r.ok) storeTokens(await r.clone().json());
    return toFormResult(r);
  },

  async regenerateRecoveryCodes(password: string): Promise<string[]> {
    const r = await bearerFetch("/auth/2fa/recovery-codes", { method: "POST", body: JSON.stringify({ password }) });
    return r.ok ? (await r.json()).recoveryCodes : [];
  },

  api: bearerFetch,
};

// =====================================================================================

function toTwoFactorMethod(method: string | null): "totp" | "email" | "recovery" {
  return method === "totp" || method === "recovery" ? method : "email";
}

async function toLoginResult(r: Response): Promise<LoginResult> {
  const body = await r.json().catch(() => ({}));
  if (r.ok) return { kind: "ok", auth: body as AuthResponse };
  if (r.status === 401 && body.status === "requires_two_factor")
    return { kind: "two_factor", preAuthToken: body.preAuthToken, method: body.twoFactorMethod };
  if (r.status === 401 && body.status === "password_change_required")
    return { kind: "password_change", passwordChangeToken: body.passwordChangeToken };
  // only with SignIn.RevealAccountState = true – by default locked accounts answer like a wrong password
  if (r.status === 423) return { kind: "locked", until: body.lockoutEndUtc };
  return { kind: "error", status: codeOf(body, r) };
}
