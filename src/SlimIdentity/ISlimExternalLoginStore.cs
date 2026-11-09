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

    /// <summary>
    /// Removes <b>all</b> external identities linked to the user. Called when the owner of an unconfirmed address proves
    /// the mailbox for the first time: whatever was linked before (possibly by someone else) must not keep access.
    /// </summary>
    Task RemoveExternalLoginsAsync(string userId, CancellationToken ct);

    /// <summary>The external identities linked to the user (sign-in methods list).</summary>
    Task<IReadOnlyList<SlimExternalLogin>> GetExternalLoginsAsync(string userId, CancellationToken ct);

    /// <summary>
    /// Removes one external identity of <b>this</b> user: <c>DELETE … WHERE user_id = @userId AND provider = @provider AND
    /// provider_key = @providerKey</c>. Returns <c>true</c> if it was linked to the user; never touches other users.
    /// </summary>
    Task<bool> RemoveExternalLoginAsync(string userId, string provider, string providerKey, CancellationToken ct);
}

/// <summary>An external identity linked to an account.</summary>
/// <param name="Provider">Authentication scheme name, e.g. <c>Google</c>.</param>
/// <param name="ProviderKey">Subject at the provider.</param>
public sealed record SlimExternalLogin(string Provider, string ProviderKey);
