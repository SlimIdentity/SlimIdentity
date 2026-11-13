using SlimIdentity.Endpoints;

namespace SlimIdentity;

/// <summary>Options of the host's remote handlers (Google, Microsoft, OpenID Connect, …) for SlimIdentity.</summary>
public static class SlimRemoteAuthenticationExtensions
{
    /// <summary>
    /// Sends failed provider round trips back to the front end instead of an error page: a user who cancels at the
    /// provider lands on the <c>returnUrl</c> of the sign-in with <c>?slim_error=access_denied</c>, an answer that
    /// cannot be matched (state lost or forged, correlation cookie gone, provider error) with
    /// <c>?slim_error=external_login_failed</c> – at <c>ExternalLogin.DefaultReturnUrl</c> when no sign-in can be
    /// recognized. Call it after setting <c>Events</c>; handlers already set there run first.
    /// </summary>
    /// <example><code>
    /// slim.Authentication.AddGoogle("Google", o =&gt;
    /// {
    ///     o.ClientId = …; o.ClientSecret = …;
    ///     o.UseSlimErrorRedirects();
    /// });
    /// </code></example>
    public static TOptions UseSlimErrorRedirects<TOptions>(this TOptions options) where TOptions : RemoteAuthenticationOptions
    {
        ArgumentNullException.ThrowIfNull(options);
        var events = options.Events;

        var accessDenied = events.OnAccessDenied;
        events.OnAccessDenied = async context =>
        {
            await accessDenied(context);
            if (context.Result is not null) return;   // handled by the host
            await SlimExternalLoginHandlers.RedirectRemoteFailureAsync(context.HttpContext, context.Properties, context.Scheme.Name, SlimErrorCodes.AccessDenied);
            context.HandleResponse();
        };

        var remoteFailure = events.OnRemoteFailure;
        events.OnRemoteFailure = async context =>
        {
            await remoteFailure(context);
            if (context.Result is not null) return;
            await SlimExternalLoginHandlers.RedirectRemoteFailureAsync(context.HttpContext, context.Properties, context.Scheme.Name, SlimErrorCodes.ExternalLoginFailed);
            context.HandleResponse();
        };
        return options;
    }
}
