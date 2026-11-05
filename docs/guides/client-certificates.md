# Client certificates (mTLS)

Client certificates are not built into the package (extra dependency, highly deployment specific), but a complete,
ready-to-copy implementation is in
[`samples/templates/Enterprise/CertificateAuthentication.cs`](../../samples/templates/Enterprise/CertificateAuthentication.cs).

## How it fits together

1. **Package:** `Microsoft.AspNetCore.Authentication.Certificate` in your host.
2. **Transport:**
   - Kestrel terminates TLS and requests the certificate: `ClientCertificateMode.RequireCertificate`
     (or `AllowCertificate` if only some endpoints need it), **or**
   - a proxy (nginx, Envoy, ingress) validates the certificate and forwards it in a header
     (nginx: `proxy_set_header X-Client-Cert $ssl_client_escaped_cert;`). The app reads it with
     `AddCertificateForwarding` + `app.UseCertificateForwarding()`. Only trust that header from the proxy.
3. **Validation:** `AddCertificate` with your own CA (`ChainTrustValidationMode = CustomRootTrust`, revocation check).
4. **Mapping to users:** through `ISlimExternalLoginStore` with provider `"certificate"` and the SHA-256 thumbprint as
   key – link a certificate to a user once (`LinkExternalLoginAsync(userId, "certificate", thumbprint)`).

## Two ways to use it

- **Machine-to-machine:** the certificate authenticates every request
  (`[Authorize(AuthenticationSchemes = "Certificate")]`). Inactive users are rejected.
- **User login** (e.g. smart cards in a browser): `POST /api/login/certificate` exchanges a valid certificate for a
  regular SlimIdentity session (cookie or JWT) via `ISlimAuthManager.SignInAsync`. Deactivated and locked users are
  rejected; users with 2FA have to use the normal login.

Certificate-bound access tokens (RFC 8705) are not supported.
