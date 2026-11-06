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
  status: "invalid_credentials" | "requires_two_factor";
  preAuthToken?: string;
  twoFactorMethod?: "totp" | "email";
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
  | { kind: "two_factor"; preAuthToken: string; method: "totp" | "email" }
  | { kind: "locked"; until: string }
  | { kind: "error"; status: string };

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

  /** Confirms the first code; returns the recovery codes – show them exactly once. */
  async enableAuthenticator(setupToken: string, code: string): Promise<string[]> {
    const r = await cookieFetch("/auth/2fa/enable", { method: "POST", body: JSON.stringify({ setupToken, code }) });
    return r.ok ? (await r.json()).recoveryCodes : [];
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

  /** After the social-login redirect: /after-login?code=... */
  async completeExternalLogin(code: string) {
    const r = await fetch(`${AUTH}/login/external/exchange`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    });
    if (r.ok) storeTokens(await r.json());
    return r.ok;
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

  api: bearerFetch,
};

// =====================================================================================

async function toLoginResult(r: Response): Promise<LoginResult> {
  const body = await r.json().catch(() => ({}));
  if (r.ok) return { kind: "ok", auth: body as AuthResponse };
  if (r.status === 401 && body.status === "requires_two_factor")
    return { kind: "two_factor", preAuthToken: body.preAuthToken, method: body.twoFactorMethod };
  // only with SignIn.RevealAccountState = true – by default locked accounts answer like a wrong password
  if (r.status === 423) return { kind: "locked", until: body.lockoutEndUtc };
  return { kind: "error", status: body.status ?? `http_${r.status}` };
}
