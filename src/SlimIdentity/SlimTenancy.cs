namespace SlimIdentity;

/// <summary>
/// Which browser origins SlimIdentity trusts – per request, so tenants with their own domains can trust their own
/// front end only. Decides three things: the <c>Origin</c> check of cookie requests (CSRF; the API's own origin is
/// always allowed), the <c>returnUrl</c> after external login (open redirect) and, with <c>AddCorsPolicy()</c>,
/// credentialed cross-origin calls. The default trusts <see cref="SlimIdentityOptions.TrustedOrigins"/> and the
/// origin of <see cref="SlimLinkOptions.BaseUrl"/>. Register your own with <c>AddOriginPolicy&lt;T&gt;()</c> – it then
/// replaces that list.
/// </summary>
/// <remarks>Called on every cookie request: keep it synchronous and cheap (an in-memory map of tenants).</remarks>
public interface ISlimOriginPolicy
{
    /// <summary>
    /// <c>true</c> if <paramref name="origin"/> – normalized: <c>scheme://host[:port]</c>, lower case, no trailing
    /// slash – is trusted for this request.
    /// </summary>
    bool IsTrusted(HttpContext httpContext, string origin);
}

/// <summary>The links SlimIdentity creates.</summary>
public enum SlimLinkKind
{
    /// <summary>Proves the mailbox of a registration (<c>POST /auth/flow</c> with its token).</summary>
    EmailVerification,
    /// <summary>Sets a new password or passkey (<c>POST /auth/flow</c> with its token, then step <c>set_credential</c>) – mailed or created by an administrator.</summary>
    PasswordReset,
    /// <summary>Accepts an invitation (<c>POST /auth/flow</c> with its token, then step <c>set_credential</c>).</summary>
    Invitation,
}

/// <summary>
/// Builds the links of mails, reset links and invitations – per request, e.g. pointing to the tenant's own front end.
/// Return <c>null</c> to fall back to <see cref="SlimLinkOptions"/>. Register with <c>AddLinkBuilder&lt;T&gt;()</c>.
/// </summary>
/// <remarks>
/// Put the token into the fragment (<c>#token=…</c>) or the query, URL-encoded. Point links only to origins your
/// <see cref="ISlimOriginPolicy"/> trusts, and never derive them from request headers an attacker controls
/// (<c>Host</c> without a host filter, <c>X-Forwarded-Host</c> without a trusted proxy) – a reset link to a foreign
/// domain hands the token to its owner.
/// </remarks>
public interface ISlimLinkBuilder
{
    /// <summary>The link for <paramref name="token"/>, or <c>null</c> for the configured default.</summary>
    string? BuildLink(SlimLinkKind kind, string token, HttpContext? httpContext);
}
