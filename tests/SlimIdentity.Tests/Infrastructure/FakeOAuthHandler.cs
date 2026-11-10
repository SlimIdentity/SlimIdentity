using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SlimIdentity.Tests.Infrastructure;

public sealed class FakeOAuthOptions : AuthenticationSchemeOptions
{
    /// <summary>Claims the "identity provider" returns.</summary>
    public List<Claim> Claims { get; set; } = [];
}

/// <summary>
/// Stand-in for a remote OAuth/OIDC handler: the challenge immediately "returns" from the provider by signing the
/// configured identity into SlimIdentity's external scheme and redirecting to the callback – like a real handler after
/// the provider round trip.
/// </summary>
public sealed class FakeOAuthHandler(IOptionsMonitor<FakeOAuthOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<FakeOAuthOptions>(options, logger, encoder), IAuthenticationRequestHandler
{
    public Task<bool> HandleRequestAsync() => Task.FromResult(false);

    protected override Task<AuthenticateResult> HandleAuthenticateAsync() => Task.FromResult(AuthenticateResult.NoResult());

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(Options.Claims, Scheme.Name));
        await Context.SignInAsync(SlimIdentityDefaults.ExternalScheme, principal, properties);
        Response.Redirect(properties.RedirectUri!);
    }
}
