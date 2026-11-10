using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace SlimIdentity;

/// <summary>
/// OpenID Connect Back-Channel Logout for one identity provider (<c>AddBackChannelLogout(provider, …)</c>): where the
/// signing keys come from and which audience the logout token must carry.
/// </summary>
public sealed class SlimBackChannelLogoutOptions
{
    /// <summary>
    /// The provider's discovery document, e.g. <c>https://keycloak.example.com/realms/corp/.well-known/openid-configuration</c>.
    /// Issuer and signing keys are read from it (cached, refreshed like the JWT bearer handler does).
    /// </summary>
    public string? MetadataAddress { get; set; }

    /// <summary>Instead of <see cref="MetadataAddress"/>: a fixed issuer and signing keys.</summary>
    public OpenIdConnectConfiguration? Configuration { get; set; }

    /// <summary>Your client id at the provider – the logout token's required <c>aud</c>.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Only HTTPS for <see cref="MetadataAddress"/>. Default <c>true</c>.</summary>
    public bool RequireHttpsMetadata { get; set; } = true;
}
