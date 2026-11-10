// Virtual passkey – a software authenticator for the playground (ES256 with WebCrypto), so passkeys can be tried
// without a phone or a security key. It answers navigator.credentials.create / get with exactly what a real
// authenticator sends (CBOR attestation object, COSE key, DER signature) – the server checks it like any other.
// Demo only: the private keys live in this browser's localStorage, readable by any script of the page.

const STORAGE = "slim.virtual-passkeys";
const encoder = new TextEncoder();

const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64url = (text) => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=")), (c) => c.charCodeAt(0));
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let i = 0; for (const p of parts) { out.set(p, i); i += p.length; } return out; };

// ------------------------------------------------------------------ minimal CBOR (canonical enough for WebAuthn)

function cborHead(major, value) {
  if (value < 24) return Uint8Array.of((major << 5) | value);
  if (value < 0x100) return Uint8Array.of((major << 5) | 24, value);
  if (value < 0x10000) return Uint8Array.of((major << 5) | 25, value >> 8, value & 0xff);
  return Uint8Array.of((major << 5) | 26, value >>> 24, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff);
}

function cbor(value) {
  if (typeof value === "number") return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  if (typeof value === "string") { const bytes = encoder.encode(value); return concat(cborHead(3, bytes.length), bytes); }
  if (value instanceof Uint8Array) return concat(cborHead(2, value.length), value);
  if (value instanceof Map) return concat(cborHead(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)]));
  throw new Error("unsupported CBOR value");
}

// ECDSA signatures from WebCrypto are r||s (IEEE P1363); WebAuthn wants an ASN.1 DER SEQUENCE of two INTEGERs
function toDer(raw) {
  const integer = (bytes) => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    let v = bytes.slice(i);
    if (v[0] & 0x80) v = concat(Uint8Array.of(0), v);
    return concat(Uint8Array.of(0x02, v.length), v);
  };
  const body = concat(integer(raw.slice(0, 32)), integer(raw.slice(32)));
  return concat(Uint8Array.of(0x30, body.length), body);
}

// ------------------------------------------------------------------ the authenticator

function load() { try { return JSON.parse(localStorage.getItem(STORAGE) ?? "[]"); } catch { return []; } }
function save(list) { localStorage.setItem(STORAGE, JSON.stringify(list)); }

const FLAGS = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40 };

async function authData(rpId, extra, flags) {
  return concat(await sha256(encoder.encode(rpId)), Uint8Array.of(flags), new Uint8Array(4) /* counter 0, like synced passkeys */, extra);
}

function clientData(type, challenge) {
  return encoder.encode(JSON.stringify({ type, challenge: b64url(challenge), origin: location.origin, crossOrigin: false }));
}

async function create(publicKey) {
  const rpId = publicKey.rp.id;
  const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
  const id = crypto.getRandomValues(new Uint8Array(16));
  const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, fromB64url(jwk.x)], [-3, fromB64url(jwk.y)]]));
  const attested = concat(new Uint8Array(16) /* aaguid */, Uint8Array.of(0, id.length), id, cose);
  const data = await authData(rpId, attested, FLAGS.UP | FLAGS.UV | FLAGS.BE | FLAGS.BS | FLAGS.AT);
  const attestationObject = cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", data]]));

  const list = load();
  list.push({
    id: b64url(id), rpId, userHandle: b64url(new Uint8Array(publicKey.user.id)), name: publicKey.user.name,
    privateKey: await crypto.subtle.exportKey("jwk", keys.privateKey),
  });
  save(list);

  return {
    id: b64url(id), rawId: id.buffer, type: "public-key",
    response: { clientDataJSON: clientData("webauthn.create", new Uint8Array(publicKey.challenge)).buffer, attestationObject: attestationObject.buffer, getTransports: () => ["internal"] },
  };
}

async function get(publicKey, stored) {
  const key = await crypto.subtle.importKey("jwk", stored.privateKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const data = await authData(publicKey.rpId, new Uint8Array(0), FLAGS.UP | FLAGS.UV | FLAGS.BE | FLAGS.BS);
  const client = clientData("webauthn.get", new Uint8Array(publicKey.challenge));
  const signature = toDer(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, concat(data, await sha256(client)))));
  const id = fromB64url(stored.id);
  return {
    id: stored.id, rawId: id.buffer, type: "public-key",
    response: { clientDataJSON: client.buffer, authenticatorData: data.buffer, signature: signature.buffer, userHandle: fromB64url(stored.userHandle).buffer },
  };
}

/**
 * Replaces navigator.credentials.create / get with the virtual passkey while installed. A conditional request
 * (autofill) waits until pickForAutofill() is called – the stand-in for picking the passkey in the browser's list.
 */
export function installVirtualPasskey(onAutofillOffer) {
  const original = {
    create: navigator.credentials.create.bind(navigator.credentials),
    get: navigator.credentials.get.bind(navigator.credentials),
    conditional: window.PublicKeyCredential?.isConditionalMediationAvailable,
  };
  let pending = null;

  navigator.credentials.create = (options) => create(options.publicKey);
  navigator.credentials.get = (options) => {
    const candidates = load().filter((k) => k.rpId === options.publicKey.rpId);
    if (options.mediation !== "conditional") {
      return candidates.length === 0
        ? Promise.reject(new DOMException("No virtual passkey for this site.", "NotAllowedError"))
        : get(options.publicKey, candidates.at(-1));
    }
    // autofill: like a browser, offer nothing (and wait quietly) when there is no passkey for the site
    return new Promise((resolve, reject) => {
      if (candidates.length > 0) {
        pending = { resolve: () => resolve(get(options.publicKey, candidates.at(-1))), name: candidates.at(-1).name };
        onAutofillOffer?.(pending.name);
      }
      options.signal?.addEventListener("abort", () => { pending = null; onAutofillOffer?.(null); reject(new DOMException("Aborted", "AbortError")); });
    });
  };
  if (window.PublicKeyCredential) PublicKeyCredential.isConditionalMediationAvailable = async () => true;

  return {
    pickForAutofill() { const p = pending; pending = null; onAutofillOffer?.(null); p?.resolve(); },
    count: () => load().length,
    forget() { save([]); },
    uninstall() {
      navigator.credentials.create = original.create;
      navigator.credentials.get = original.get;
      if (window.PublicKeyCredential) PublicKeyCredential.isConditionalMediationAvailable = original.conditional;
    },
  };
}
