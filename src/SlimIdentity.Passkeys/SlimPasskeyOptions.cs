namespace SlimIdentity;

/// <summary>Passkeys (WebAuthn) – configured with <c>AddPasskeys(o =&gt; …)</c>.</summary>
public sealed class SlimPasskeyOptions
{
    /// <summary>
    /// Relying party id: the domain passkeys are bound to, e.g. <c>example.com</c> – the front end's host or a parent
    /// domain of it (<c>app.example.com</c> may use <c>example.com</c>). Default: the host of <c>Links.BaseUrl</c>.
    /// Changing it later makes every registered passkey unusable.
    /// </summary>
    public string? RelyingPartyId { get; set; }

    /// <summary>Name shown by the authenticator ("Sign in to …"). Default: <c>TwoFactor.AuthenticatorIssuer</c>.</summary>
    public string? RelyingPartyName { get; set; }

    internal string? EffectiveRelyingPartyId(SlimLinkOptions links) =>
        !string.IsNullOrWhiteSpace(RelyingPartyId) ? RelyingPartyId.Trim().ToLowerInvariant()
        : Uri.TryCreate(links.BaseUrl, UriKind.Absolute, out var baseUrl) ? baseUrl.Host.ToLowerInvariant()
        : null;
}
