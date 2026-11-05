namespace SlimIdentity;

/// <summary>
/// Optional capability: activates OAuth social logins and enterprise OIDC (Entra ID, Keycloak, …).
/// The provider handlers themselves are registered by the host (e.g. <c>AddGoogle</c>, <c>AddOpenIdConnect</c>).
/// </summary>
public interface ISlimExternalLoginStore
{
    /// <summary>Finds the user linked to the external identity (<paramref name="provider"/> = scheme name, <paramref name="providerKey"/> = subject).</summary>
    Task<SlimUser?> FindByExternalLoginAsync(string provider, string providerKey, CancellationToken ct);

    /// <summary>Links an external identity to a user (unique per provider + key).</summary>
    Task LinkExternalLoginAsync(string userId, string provider, string providerKey, CancellationToken ct);
}
