using SlimIdentity.Contracts;

namespace SlimIdentity;

// Extension points for the other SlimIdentity packages (released with the same version, see InternalsVisibleTo).
// Internal on purpose: they reach into the flows, so they are no public contract a host could misuse.

/// <summary>Endpoints of another SlimIdentity package, mapped by <c>MapSlimIdentityApi</c> into its groups.</summary>
internal interface ISlimEndpointModule
{
    /// <param name="auth">The <c>/auth</c> group (CSRF filter, no-store, tags).</param>
    /// <param name="signInMethods">The authorized <c>/auth/sign-in-methods</c> group.</param>
    /// <param name="services">The application's root services – for start-up checks.</param>
    void Map(RouteGroupBuilder auth, RouteGroupBuilder signInMethods, IServiceProvider services);
}

/// <summary>Passkeys as sign-in methods (<c>SlimIdentity.Passkeys</c>): listed, counted for the last way in, cleared.</summary>
internal interface ISlimPasskeySignInMethods
{
    Task<IReadOnlyList<SlimPasskeyInfo>> GetPasskeysAsync(string userId, CancellationToken ct);

    /// <summary>
    /// First proof of the mailbox (pre-account hijacking): whoever registered the address before must keep no way in.
    /// </summary>
    Task RemoveAllAsync(string userId, CancellationToken ct);
}
