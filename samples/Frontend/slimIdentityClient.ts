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
}

export interface LoginChallenge {
  status: "invalid_credentials" | "requires_two_factor";
  preAuthToken?: string;
  twoFactorMethod?: "totp" | "email";
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

  async loginTwoFactor(preAuthToken: string, code: string): Promise<LoginResult> {
    const r = await cookieFetch("/auth/login/2fa", { method: "POST", body: JSON.stringify({ preAuthToken, code }) });
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

let accessToken: string | null = null;                 // memory only – never localStorage
let refreshPromise: Promise<boolean> | null = null;
const REFRESH_KEY = "slim.refresh";                    // for mobile use secure storage instead

function storeTokens(auth: AuthResponse) {
  accessToken = auth.accessToken ?? null;
  if (auth.refreshToken) sessionStorage.setItem(REFRESH_KEY, auth.refreshToken);
}

async function refresh(): Promise<boolean> {
  // de-duplicate parallel refreshes: refresh tokens are single-use
  refreshPromise ??= (async () => {
    const refreshToken = sessionStorage.getItem(REFRESH_KEY);
    if (!refreshToken) return false;
    const r = await fetch(`${AUTH}/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken }),
    });
    if (!r.ok) { bearerAuth.clear(); return false; }
    storeTokens(await r.json());
    return true;
  })().finally(() => (refreshPromise = null));
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
    const r = await fetch(`${AUTH}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const result = await toLoginResult(r);
    if (result.kind === "ok") storeTokens(result.auth);
    return result;
  },

  async loginTwoFactor(preAuthToken: string, code: string): Promise<LoginResult> {
    const r = await fetch(`${AUTH}/login/2fa`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ preAuthToken, code }),
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
    const refreshToken = sessionStorage.getItem(REFRESH_KEY);
    await fetch(`${AUTH}/logout`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken }),
    });
    bearerAuth.clear();
  },

  clear() {
    accessToken = null;
    sessionStorage.removeItem(REFRESH_KEY);
  },

  api: bearerFetch,
};

// =====================================================================================

async function toLoginResult(r: Response): Promise<LoginResult> {
  const body = await r.json().catch(() => ({}));
  if (r.ok) return { kind: "ok", auth: body as AuthResponse };
  if (r.status === 401 && body.status === "requires_two_factor")
    return { kind: "two_factor", preAuthToken: body.preAuthToken, method: body.twoFactorMethod };
  if (r.status === 423) return { kind: "locked", until: body.lockoutEndUtc };
  return { kind: "error", status: body.status ?? `http_${r.status}` };
}
