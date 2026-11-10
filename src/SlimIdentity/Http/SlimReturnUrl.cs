namespace SlimIdentity.Http;

/// <summary>
/// Open-redirect protection for <c>returnUrl</c> after external login: only local paths and absolute URLs on a
/// trusted origin (<see cref="SlimIdentityOptions.TrustedOrigins"/>, <see cref="SlimLinkOptions.BaseUrl"/>) pass.
/// </summary>
internal static class SlimReturnUrl
{
    /// <summary>Returns the URL to redirect to, the default for an empty input, or <c>null</c> if it is not allowed.</summary>
    public static string? Validate(string? returnUrl, SlimIdentityOptions options) =>
        Validate(returnUrl, options, options.IsTrustedOrigin);

    /// <summary>As above, with the origin decision of an <see cref="ISlimOriginPolicy"/>.</summary>
    public static string? Validate(string? returnUrl, SlimIdentityOptions options, Func<string, bool> isTrustedOrigin)
    {
        if (string.IsNullOrWhiteSpace(returnUrl)) return options.ExternalLogin.DefaultReturnUrl;

        // Browsers strip tabs and line breaks from URLs and trim surrounding whitespace – "/\t/evil.com" would become
        // "//evil.com". Anything the browser might rewrite is rejected instead of interpreted.
        foreach (var c in returnUrl)
            if (char.IsControl(c)) return null;
        if (char.IsWhiteSpace(returnUrl[0]) || char.IsWhiteSpace(returnUrl[^1])) return null;

        if (IsLocalPath(returnUrl)) return returnUrl;

        if (!Uri.TryCreate(returnUrl, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)
            || !string.IsNullOrEmpty(uri.UserInfo))   // https://trusted@evil.example
            return null;

        // redirect to the URL exactly as .NET parsed it, never to the raw input another parser might read differently
        return isTrustedOrigin(uri.AbsoluteUri) ? uri.AbsoluteUri : null;
    }

    /// <summary>"/path" – but not "//host" or "/\host" (protocol-relative in browsers).</summary>
    private static bool IsLocalPath(string url) =>
        url[0] == '/' && (url.Length == 1 || (url[1] != '/' && url[1] != '\\'));
}
