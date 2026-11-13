# Client certificates (mTLS)

Not built in; a ready-to-copy implementation is
[`CertificateAuthentication.cs`](../../samples/templates/Enterprise/CertificateAuthentication.cs).

1. **Package:** `Microsoft.AspNetCore.Authentication.Certificate`.
2. **Transport:** Kestrel requests the certificate (`ClientCertificateMode.RequireCertificate`, or `AllowCertificate`
   if only some endpoints need it), **or** a proxy validates it and forwards it in a header (nginx:
   `proxy_set_header X-Client-Cert $ssl_client_escaped_cert;`), read with `AddCertificateForwarding` and
   `app.UseCertificateForwarding()` – trust that header only from the proxy.
3. **Validation:** `AddCertificate` with your CA (`ChainTrustValidationMode = CustomRootTrust`, revocation check).
4. **Mapping:** `ISlimExternalLoginStore` with provider `"certificate"` and the SHA-256 thumbprint as key
   (`LinkExternalLoginAsync(userId, "certificate", thumbprint)`).

Use it either **machine-to-machine** (`[Authorize(AuthenticationSchemes = "Certificate")]`; inactive users rejected) or
as a **user login** (smart cards): an endpoint exchanges the certificate for a SlimIdentity session via
`ISlimAuthManager.SignInAsync(user, useCookies, authenticationMethod: "cert")`. The rules of `/login` apply; open steps
come back as `action_required` and continue at `/auth/login/verify-email`, `/auth/login/2fa` or
`/auth/login/password-change`. For a smart card with PIN pass `secondFactorVerified: true`.

Certificate-bound access tokens (RFC 8705) are not supported.
