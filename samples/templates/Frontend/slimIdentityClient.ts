// SlimIdentity sample – minimal SPA client (framework-agnostic, works in Vue / React / Svelte).
// Shows both flows:
//   1. Cookie flow  – HttpOnly cookie, X-CSRF header on every state-changing request (anonymous ones too)
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

/**
 * The password (passkey, external login) was right, but steps follow before the session: "verify_email" (code from
 * the mail) at verifyEmail, "second_factor" at loginTwoFactor / loginRecoveryCode, "change_password" (set by an administrator) at completePasswordChange. Each step
 * answers with the remaining ones and a new flowToken – or with the session.
 * A registration answers the same way: "verify_email" at verifyRegistration (or the mailed link at openLink),
 * then "set_credential" at completeRegistration or completeRegistrationWithPasskey. A reset link (openLink) ends in
 * "set_credential" as well – possibly after "verify_email" or "second_factor" – and so does an invitation link.
 * If the server requires a second factor the account lacks: "setup_second_factor" at setupLoginAuthenticator +
 * enableLoginAuthenticator (answers with `details.recoveryCodes` – show them once), then "confirm_recovery_codes" at
 * confirmRecoveryCodes.
 */
export interface ActionRequired {
  status: "action_required";
  actions: string[];
  flowToken: string;
  expiresIn: number;
  details?: {
    secondFactor?: { methods: ("totp" | "email" | "recovery")[] };
    setCredential?: { kinds: "password"[] };
    setupSecondFactor?: { methods: ("totp" | "passkey")[] };
    /** only in the answer of enableLoginAuthenticator */
    recoveryCodes?: string[];
  };
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
  | { kind: "action_required"; steps: ActionRequired }
  | { kind: "locked"; until: string }
  | { kind: "error"; status: string };

export interface TwoFactorStatus {
  enabled: boolean;
  /** "recovery": no codes can be sent – set up an authenticator. */
  method: "totp" | "email" | "recovery" | null;
  hasAuthenticator: boolean;
}

/**
 * Answer of the form endpoints: `status` (e.g. "registration_accepted") or the field errors of a 400.
 * "reauthentication_required": the account has no password – sign in again (provider, passkey), then repeat.
 */
export type FormResult =
  | { ok: true; status: string }
  | { ok: false; status: string; errors?: Record<string, string[]> };

/** Recovery codes (enabling 2FA, regenerating) – show them exactly once – or the error, like FormResult. */
export type RecoveryCodesResult =
  | { ok: true; recoveryCodes: string[] }
  | { ok: false; status: string; errors?: Record<string, string[]> };

/** Authenticator setup: QR code (data URL for an <img>), the key for manual entry and the token for enabling. */
export type AuthenticatorSetupResult =
  | { ok: true; sharedKey: string; authenticatorUri: string; setupToken: string; qrCode: string }
  | { ok: false; status: string; errors?: Record<string, string[]> };

/**
 * The machine-readable code of an answer: errors are problem details (RFC 9457) carrying `code`
 * ("invalid_token", "locked_out", "validation_failed", …); success answers carry it as text in `status`.
 */
function codeOf(body: { status?: unknown; code?: unknown }, r: Response): string {
  if (typeof body.code === "string") return body.code;
  return typeof body.status === "string" ? body.status : `http_${r.status}`;
}

async function toFormResult(r: Response): Promise<FormResult> {
  const body = await r.json().catch(() => ({}));
  if (r.ok) return { ok: true, status: body.status ?? "ok" };
  return { ok: false, status: codeOf(body, r), errors: body.errors };
}

async function failureOf(r: Response): Promise<{ ok: false; status: string; errors?: Record<string, string[]> }> {
  const body = await r.json().catch(() => ({}));
  return { ok: false, status: codeOf(body, r), errors: body.errors };
}

async function toRecoveryCodesResult(r: Response): Promise<RecoveryCodesResult> {
  if (!r.ok) return failureOf(r);
  return { ok: true, recoveryCodes: (await r.json()).recoveryCodes };
}

async function toAuthenticatorSetup(r: Response, toQrDataUrl: (text: string) => Promise<string>): Promise<AuthenticatorSetupResult> {
  if (!r.ok) return failureOf(r);
  const setup: { sharedKey: string; authenticatorUri: string; setupToken: string } = await r.json();
  return { ok: true, ...setup, qrCode: await toQrDataUrl(setup.authenticatorUri) };   // e.g. (uri) => QRCode.toDataURL(uri)
}

// X-CSRF on every state-changing request, anonymous ones included: without a JwtSecret the server treats each request
// as cookie context, and a cookie-context POST without the header is refused (403 csrf_validation_failed).
const jsonHeaders = { "Content-Type": "application/json", "X-CSRF": "1" };

function anonymousPost(path: string, body: object): Promise<FormResult> {
  return fetch(`${AUTH}${path}`, {
    method: "POST",
    headers: jsonHeaders,
    body: JSON.stringify(body),
  }).then(toFormResult);
}

// =====================================================================================
// 0. Account flows without a session (same for cookie and bearer)
//    The answers never reveal whether an address has an account – show the same message in every case.
// =====================================================================================

export const account = {
  forgotPassword(email: string): Promise<FormResult> {
    return anonymousPost("/forgot-password", { email });
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
  async setupAuthenticator(toQrDataUrl: (text: string) => Promise<string>): Promise<AuthenticatorSetupResult> {
    return toAuthenticatorSetup(await cookieFetch("/auth/2fa/setup", { method: "POST", body: "{}" }), toQrDataUrl);
  },

  /** Confirms the first code with the current password; returns the recovery codes – show them exactly once. */
  async enableAuthenticator(setupToken: string, code: string, password: string): Promise<RecoveryCodesResult> {
    return toRecoveryCodesResult(await cookieFetch("/auth/2fa/enable", { method: "POST", body: JSON.stringify({ setupToken, code, password }) }));
  },

  /** 2FA with codes by e-mail instead of an app; returns the recovery codes – show them exactly once. */
  async enableEmailTwoFactor(password: string): Promise<RecoveryCodesResult> {
    return toRecoveryCodesResult(await cookieFetch("/auth/2fa/enable-email", { method: "POST", body: JSON.stringify({ password }) }));
  },

  /** For the 2FA settings page. */
  async twoFactorStatus(): Promise<TwoFactorStatus | null> {
    const r = await cookieFetch("/auth/2fa");
    return r.ok ? r.json() : null;
  },

  /** Turns 2FA off; the session is renewed (cookie). */
  async disableTwoFactor(password: string): Promise<FormResult> {
    return toFormResult(await cookieFetch("/auth/2fa/disable", { method: "POST", body: JSON.stringify({ password }) }));
  },

  /** Replaces all recovery codes – show the new ones exactly once. */
  async regenerateRecoveryCodes(password: string): Promise<RecoveryCodesResult> {
    return toRecoveryCodesResult(await cookieFetch("/auth/2fa/recovery-codes", { method: "POST", body: JSON.stringify({ password }) }));
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
  async changeEmail(newEmail: string, password: string): Promise<FormResult> {
    return toFormResult(await cookieFetch("/auth/change-email", { method: "POST", body: JSON.stringify({ newEmail, password }) }));
  },

  /** On success every session of the account ends – sign in again with the new address. */
  async confirmEmailChange(token: string): Promise<FormResult> {
    return toFormResult(await cookieFetch("/auth/confirm-email-change", { method: "POST", body: JSON.stringify({ token }) }));
  },

  /** Step "verify_email": the 6-digit code from the mail confirms the address. */
  async verifyEmail(flowToken: string, code: string): Promise<LoginResult> {
    return toLoginResult(await cookieFetch("/auth/login/verify-email", { method: "POST", body: JSON.stringify({ flowToken, code }) }));
  },

  /**
   * Registration: only the address. The answer is the same whether it has an account or not – the mail decides
   * (a code and a link, or "you already have an account"). Continue with verifyRegistration.
   */
  async register(email: string, rememberMe = false): Promise<LoginResult> {
    return toLoginResult(await cookieFetch("/auth/register?useCookies=true", { method: "POST", body: JSON.stringify({ email, rememberMe }) }));
  },

  /** Registration step "verify_email": the 6-digit code from the mail. Next is "set_credential". */
  async verifyRegistration(flowToken: string, code: string): Promise<LoginResult> {
    return toLoginResult(await cookieFetch("/auth/register/verify", { method: "POST", body: JSON.stringify({ flowToken, code }) }));
  },

  /**
   * Page behind a link (/verify-email, /reset-password, /accept-invitation – each ?token=…) – also on another device.
   * Next is "set_credential" (`details.setCredential.email` names the account); after a reset or an invitation all
   * other sessions of the account end.
   */
  async openLink(token: string): Promise<LoginResult> {
    return toLoginResult(await cookieFetch("/auth/flow?useCookies=true", { method: "POST", body: JSON.stringify({ token }) }));
  },

  /**
   * Step "set_credential": creates the account (or sets the new password after a reset) and signs in. `profile` is your business data (company,
   * name, …) – the server validates it with its ISlimRegistrationProfile; field errors come back as
   * `errors["profile.<field>"]`.
   */
  async completeRegistration(flowToken: string, password: string, profile?: object): Promise<LoginResult> {
    return toLoginResult(await cookieFetch("/auth/register/password", { method: "POST", body: JSON.stringify({ flowToken, password, profile }) }));
  },

  /**
   * Registration step "set_credential" with a passkey instead of a password (offered when `details.setCredential.kinds`
   * contains "passkey"): creates the account with the passkey and signs in. Errors: "cancelled", "unsupported", …
   */
  async completeRegistrationWithPasskey(flowToken: string, name?: string, profile?: object): Promise<LoginResult> {
    const send = (path: string, init: RequestInit) => cookieFetch(path, init);
    const created = await passkeyCreation(send, "/auth/register/passkey/options", { flowToken });
    if (typeof created === "string") return { kind: "error", status: created };
    return toLoginResult(await send("/auth/register/passkey", { method: "POST", body: JSON.stringify({ flowToken, ...created, name, profile }) }));
  },

  /** "Remember this device" sets a cookie (if TwoFactor.RememberDeviceLifetime is configured on the server). */
  async loginTwoFactor(flowToken: string, code: string, rememberDevice = false): Promise<LoginResult> {
    const r = await cookieFetch("/auth/login/2fa", { method: "POST", body: JSON.stringify({ flowToken, code, rememberDevice }) });
    return toLoginResult(r);
  },

  /** Second step with one of the recovery codes (single use) instead of an authenticator / e-mail code. */
  async loginRecoveryCode(flowToken: string, recoveryCode: string): Promise<LoginResult> {
    return toLoginResult(await cookieFetch("/auth/login/2fa", { method: "POST", body: JSON.stringify({ flowToken, recoveryCode }) }));
  },

  /** Step "setup_second_factor": key and QR code of a new authenticator (see setupAuthenticator). */
  async setupLoginAuthenticator(flowToken: string, toQrDataUrl: (text: string) => Promise<string>): Promise<AuthenticatorSetupResult> {
    return toAuthenticatorSetup(await cookieFetch("/auth/login/2fa/setup", { method: "POST", body: JSON.stringify({ flowToken }) }), toQrDataUrl);
  },

  /** Enables the authenticator with its first code; the answer carries `details.recoveryCodes` – show them exactly once. */
  async enableLoginAuthenticator(flowToken: string, setupToken: string, code: string): Promise<LoginResult> {
    return toLoginResult(await cookieFetch("/auth/login/2fa/enable", { method: "POST", body: JSON.stringify({ flowToken, setupToken, code }) }));
  },

  /** Step "confirm_recovery_codes": the user has saved the codes – the result is the session or the remaining steps. */
  async confirmRecoveryCodes(flowToken: string): Promise<LoginResult> {
    return toLoginResult(await cookieFetch("/auth/login/2fa/recovery-codes-saved", { method: "POST", body: JSON.stringify({ flowToken }) }));
  },

  /** Step "change_password": sets the own password – the result is the session or the remaining steps. */
  async completePasswordChange(flowToken: string, newPassword: string): Promise<LoginResult> {
    const r = await cookieFetch("/auth/login/password-change", { method: "POST", body: JSON.stringify({ flowToken, newPassword }) });
    return toLoginResult(r);
  },

  /** The open steps of a flowToken again (e.g. after a reload); changes nothing. */
  async readFlow(flowToken: string): Promise<LoginResult> {
    return toLoginResult(await cookieFetch("/auth/flow", { method: "POST", body: JSON.stringify({ flowToken }) }));
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

  /** Social login is a full-page navigation, not fetch. */
  loginWith(provider: string) {
    const returnUrl = encodeURIComponent(window.location.origin + "/after-login");
    window.location.href = `${AUTH}/login/${provider}?useCookies=true&returnUrl=${returnUrl}`;
  },

  /**
   * On the /after-login page: the session cookie is set – unless steps follow (2FA, own password); then the flowToken
   * arrives in the URL fragment (#slim_status=action_required&flowToken=…), which is never sent to a server, and
   * /auth/flow names the steps. Errors come as ?slim_error=….
   */
  async readExternalLoginResult(): Promise<LoginResult> {
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const error = new URLSearchParams(window.location.search).get("slim_error");
    history.replaceState(null, "", window.location.pathname);   // remove secrets from the address bar / history
    if (error) return { kind: "error", status: error };
    if (fragment.get("slim_status") === "action_required") return cookieAuth.readFlow(fragment.get("flowToken") ?? "");
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

  /** "success" (other devices are signed out), or last_sign_in_method / invalid_password / concurrent_change. */
  removePasskey(id: string, password?: string): Promise<string> {
    return statusOf(cookieFetch("/auth/sign-in-methods/passkeys/remove", { method: "POST", body: JSON.stringify({ id, password }) }));
  },

  /** "success" (other devices are signed out), or an error code – last_sign_in_method: add another way in first. */
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
  const created = await passkeyCreation(send, "/auth/passkeys/register/options", { password });
  if (typeof created === "string") return created;
  return statusOf(send("/auth/passkeys/register", { method: "POST", body: JSON.stringify({ ...created, name }) }))
    .then(status => (status === "http_200" ? "passkey_added" : status));
}

/** navigator.credentials.create with the options of the server: the state and the credential to post, or an error code. */
async function passkeyCreation(send: (path: string, init: RequestInit) => Promise<Response>, optionsPath: string,
    body: object): Promise<{ state: string; credential: object } | string> {
  if (typeof PublicKeyCredential === "undefined") return "unsupported";
  const start = await send(optionsPath, { method: "POST", body: JSON.stringify(body) });
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
  return {
    state,
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
  };
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

// bearer: enabling 2FA renews the session – the answer carries the new tokens next to the recovery codes
async function enableTwoFactorWith(path: string, body: object): Promise<RecoveryCodesResult> {
  const r = await bearerFetch(path, { method: "POST", body: JSON.stringify(body) });
  if (!r.ok) return failureOf(r);
  const answer: { recoveryCodes: string[]; session?: AuthResponse } = await r.json();
  if (answer.session) storeTokens(answer.session);
  return { ok: true, recoveryCodes: answer.recoveryCodes };
}

async function removeExternal(send: (path: string, init: RequestInit) => Promise<Response>,
  provider: string, providerKey: string, password?: string): Promise<string> {
  const r = await send("/auth/sign-in-methods/external/remove", { method: "POST", body: JSON.stringify({ provider, providerKey, password }) });
  const body = await r.json().catch(() => ({}));
  if (r.ok && body.accessToken) storeTokens(body);
  return codeOf(body, r);
}

async function flowStep(path: string, body: { flowToken: string } & Record<string, unknown>): Promise<LoginResult> {
  const r = await fetch(`${AUTH}${path}`, { method: "POST", headers: jsonHeaders, body: JSON.stringify(body) });
  const result = await toLoginResult(r);
  if (result.kind === "ok") storeTokens(result.auth);
  return result;
}

const anonymousFetch = (path: string, init: RequestInit) => fetch(`${API}${path}`, { ...init, headers: jsonHeaders });

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
      headers: jsonHeaders,
      body: JSON.stringify({ refreshToken }),
    });
    // only a rejected token ends the session – 429 (rate limit) or 5xx (deployment) keep it for the next attempt
    if (r.status === 400 || r.status === 401) { bearerAuth.clear(); return false; }
    if (!r.ok) return false;
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
      headers: jsonHeaders,
      body: JSON.stringify({ email, password, twoFactorRememberToken }),
    });
    const result = await toLoginResult(r);
    if (result.kind === "ok") storeTokens(result.auth);
    return result;
  },

  /** Step "verify_email": the 6-digit code from the mail confirms the address. */
  async verifyEmail(flowToken: string, code: string): Promise<LoginResult> {
    return flowStep("/login/verify-email", { flowToken, code });
  },

  /** Registration: only the address; the same answer for every address – the mail decides. */
  async register(email: string): Promise<LoginResult> {
    return toLoginResult(await fetch(`${AUTH}/register?useCookies=false`, { method: "POST", headers: jsonHeaders, body: JSON.stringify({ email }) }));
  },

  /** Registration step "verify_email": the 6-digit code from the mail. */
  async verifyRegistration(flowToken: string, code: string): Promise<LoginResult> {
    return flowStep("/register/verify", { flowToken, code });
  },

  /** Page behind a link (/verify-email, /reset-password, /accept-invitation – each ?token=…) – also on another device. */
  async openLink(token: string): Promise<LoginResult> {
    return toLoginResult(await fetch(`${AUTH}/flow?useCookies=false`, { method: "POST", headers: jsonHeaders, body: JSON.stringify({ token }) }));
  },

  /** Step "set_credential": creates the account or sets the new password, then signs in (profile: see cookieAuth.completeRegistration). */
  async completeRegistration(flowToken: string, password: string, profile?: object): Promise<LoginResult> {
    return flowStep("/register/password", { flowToken, password, profile });
  },

  /** Registration step "set_credential" with a passkey – see cookieAuth.completeRegistrationWithPasskey. */
  async completeRegistrationWithPasskey(flowToken: string, name?: string, profile?: object): Promise<LoginResult> {
    const created = await passkeyCreation(anonymousFetch, "/auth/register/passkey/options", { flowToken });
    if (typeof created === "string") return { kind: "error", status: created };
    return flowStep("/register/passkey", { flowToken, ...created, name, profile });
  },

  async loginTwoFactor(flowToken: string, code: string, rememberDevice = false): Promise<LoginResult> {
    return flowStep("/login/2fa", { flowToken, code, rememberDevice });
  },

  /** Second step with one of the recovery codes (single use) instead of an authenticator / e-mail code. */
  async loginRecoveryCode(flowToken: string, recoveryCode: string): Promise<LoginResult> {
    return flowStep("/login/2fa", { flowToken, recoveryCode });
  },

  /** Step "setup_second_factor": key and QR code of a new authenticator (see setupAuthenticator). */
  async setupLoginAuthenticator(flowToken: string, toQrDataUrl: (text: string) => Promise<string>): Promise<AuthenticatorSetupResult> {
    return toAuthenticatorSetup(await fetch(`${AUTH}/login/2fa/setup`, { method: "POST", headers: jsonHeaders, body: JSON.stringify({ flowToken }) }), toQrDataUrl);
  },

  /** Enables the authenticator with its first code; the answer carries `details.recoveryCodes` – show them exactly once. */
  async enableLoginAuthenticator(flowToken: string, setupToken: string, code: string): Promise<LoginResult> {
    return flowStep("/login/2fa/enable", { flowToken, setupToken, code });
  },

  /** Step "confirm_recovery_codes": the user has saved the codes – the result is the session or the remaining steps. */
  async confirmRecoveryCodes(flowToken: string): Promise<LoginResult> {
    return flowStep("/login/2fa/recovery-codes-saved", { flowToken });
  },

  /** Step "change_password": sets the own password – the result is the session or the remaining steps. */
  async completePasswordChange(flowToken: string, newPassword: string): Promise<LoginResult> {
    return flowStep("/login/password-change", { flowToken, newPassword });
  },

  /** The open steps of a flowToken again (e.g. after a reload); changes nothing. */
  async readFlow(flowToken: string): Promise<LoginResult> {
    return flowStep("/flow", { flowToken });
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
      headers: jsonHeaders,
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
      headers: jsonHeaders,
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
    const assertion = await passkeyAssertion(anonymousFetch, false);
    if (typeof assertion === "string") return { kind: "error", status: assertion };
    const result = await toLoginResult(await anonymousFetch("/auth/passkeys/login?useCookies=false", {
      method: "POST",
      body: JSON.stringify(assertion),
    }));
    if (result.kind === "ok") storeTokens(result.auth);
    return result;
  },

  /** Passkey autofill – see cookieAuth.loginWithPasskeyAutofill. */
  async loginWithPasskeyAutofill(signal: AbortSignal): Promise<LoginResult> {
    const assertion = await passkeyAutofill(anonymousFetch, false, signal);
    if (typeof assertion === "string") return { kind: "error", status: assertion };
    const result = await toLoginResult(await anonymousFetch("/auth/passkeys/login?useCookies=false", {
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

  /** Other devices are signed out; this client gets new tokens. */
  async removePasskey(id: string, password?: string): Promise<string> {
    const r = await bearerFetch("/auth/sign-in-methods/passkeys/remove", { method: "POST", body: JSON.stringify({ id, password }) });
    const body = await r.json().catch(() => ({}));
    if (r.ok) storeTokens(body);
    return codeOf(body, r);
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

  async regenerateRecoveryCodes(password: string): Promise<RecoveryCodesResult> {
    return toRecoveryCodesResult(await bearerFetch("/auth/2fa/recovery-codes", { method: "POST", body: JSON.stringify({ password }) }));
  },

  async me() {
    const r = await bearerFetch("/auth/me");
    return r.ok ? r.json() : null;
  },

  async twoFactorStatus(): Promise<TwoFactorStatus | null> {
    const r = await bearerFetch("/auth/2fa");
    return r.ok ? r.json() : null;
  },

  /** Authenticator setup – see cookieAuth.setupAuthenticator. */
  async setupAuthenticator(toQrDataUrl: (text: string) => Promise<string>): Promise<AuthenticatorSetupResult> {
    return toAuthenticatorSetup(await bearerFetch("/auth/2fa/setup", { method: "POST", body: "{}" }), toQrDataUrl);
  },

  /** Returns the recovery codes – show them exactly once; this client gets new tokens (the security state changed). */
  async enableAuthenticator(setupToken: string, code: string, password: string): Promise<RecoveryCodesResult> {
    return enableTwoFactorWith("/auth/2fa/enable", { setupToken, code, password });
  },

  async enableEmailTwoFactor(password: string): Promise<RecoveryCodesResult> {
    return enableTwoFactorWith("/auth/2fa/enable-email", { password });
  },

  /** All remembered devices ask for the second factor again; other sessions end, this client gets new tokens. */
  async forgetAllDevices() {
    localStorage.removeItem(REMEMBER_KEY);
    const r = await bearerFetch("/auth/2fa/forget-all-devices", { method: "POST", body: "{}" });
    if (r.ok) storeTokens(await r.json());
  },

  /** E-mail change: the confirmation link goes to the new address; the page behind it calls confirmEmailChange. */
  async changeEmail(newEmail: string, password: string): Promise<FormResult> {
    return toFormResult(await bearerFetch("/auth/change-email", { method: "POST", body: JSON.stringify({ newEmail, password }) }));
  },

  /** Anonymous; on success every session of the account ends – this client signs in again. */
  async confirmEmailChange(token: string): Promise<FormResult> {
    const result = await anonymousPost("/confirm-email-change", { token });
    if (result.ok) bearerAuth.clear();
    return result;
  },

  /** "Sign out on all devices" – this one included. */
  async logoutAll() {
    await bearerFetch("/auth/logout-all", { method: "POST", body: "{}" });
    bearerAuth.clear();
  },

  /** Active devices (requires ISlimSessionStore on the server). */
  async sessions(): Promise<SessionInfo[]> {
    const r = await bearerFetch("/auth/sessions");
    return r.ok ? r.json() : [];
  },

  async revokeSession(id: string) {
    await bearerFetch(`/auth/sessions/${encodeURIComponent(id)}`, { method: "DELETE" });
  },

  api: bearerFetch,
};

// =====================================================================================

async function toLoginResult(r: Response): Promise<LoginResult> {
  const body = await r.json().catch(() => ({}));
  if (r.ok && body.status === "success") return { kind: "ok", auth: body as AuthResponse };
  if (r.ok && body.status === "action_required") return { kind: "action_required", steps: body as ActionRequired };
  // only with SignIn.RevealAccountState = true – by default locked accounts answer like a wrong password
  if (r.status === 423) return { kind: "locked", until: body.lockoutEndUtc };
  return { kind: "error", status: codeOf(body, r) };
}
