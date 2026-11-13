// SlimIdentity sample – client certificates (mTLS) mapped to SlimIdentity users.
// Package: Microsoft.AspNetCore.Authentication.Certificate
//
//   builder.WebHost.ConfigureKestrel(k => k.ConfigureHttpsDefaults(h =>
//       h.ClientCertificateMode = ClientCertificateMode.AllowCertificate));      // Kestrel terminates TLS itself, or:
//   builder.Services.AddCertificateForwarding(o => o.CertificateHeader = "X-Client-Cert");   // proxy forwards the cert
//
//   var slim = builder.Services.AddSlimIdentity(...)
//       .AddExternalLoginStore<MyExternalLoginStore>();                          // certificate → user mapping
//   slim.AddClientCertificates(trustedRootCertificates);
//
//   app.UseCertificateForwarding();   // only behind a proxy – and only trust the header from the proxy!
//   app.UseAuthentication();
//   app.MapCertificateLogin();        // optional: exchange the certificate for a cookie / JWT session
//
// Users are linked once (e.g. by an admin): externalStore.LinkExternalLoginAsync(userId, "certificate", sha256Thumbprint).

using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity;

namespace MyApp.Enterprise;

public static class CertificateAuthentication
{
    public const string Scheme = CertificateAuthenticationDefaults.AuthenticationScheme; // "Certificate"
    public const string Provider = "certificate";

    /// <summary>
    /// Validates client certificates against your own CA and maps them to users via <see cref="ISlimExternalLoginStore"/>.
    /// Machine-to-machine endpoints can then use <c>[Authorize(AuthenticationSchemes = "Certificate")]</c>.
    /// </summary>
    public static SlimIdentityBuilder AddClientCertificates(this SlimIdentityBuilder slim, X509Certificate2Collection trustedRoots)
    {
        slim.Authentication.AddCertificate(Scheme, o =>
        {
            o.AllowedCertificateTypes = CertificateTypes.Chained;
            o.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
            o.CustomTrustStore = trustedRoots;
            o.RevocationMode = X509RevocationMode.Online;
            o.Events = new CertificateAuthenticationEvents
            {
                OnCertificateValidated = async ctx =>
                {
                    var store = ctx.HttpContext.RequestServices.GetRequiredService<ISlimExternalLoginStore>();
                    var thumbprint = ctx.ClientCertificate.GetCertHashString(HashAlgorithmName.SHA256);
                    var user = await store.FindByExternalLoginAsync(Provider, thumbprint, ctx.HttpContext.RequestAborted);
                    if (user is not { IsActive: true })
                    {
                        ctx.Fail("Unknown or disabled certificate.");
                        return;
                    }

                    ctx.Principal = new ClaimsPrincipal(new ClaimsIdentity(
                    [
                        new Claim(SlimClaimTypes.UserId, user.Id),
                        new Claim(SlimClaimTypes.Email, user.Email),
                        new Claim(SlimClaimTypes.AuthenticationMethod, "cert"),
                    ], ctx.Scheme.Name, SlimClaimTypes.Email, SlimClaimTypes.Role));
                    ctx.Success();
                },
            };
        });
        return slim;
    }

    /// <summary>
    /// Exchanges a valid client certificate for a regular SlimIdentity session (cookie or JWT), e.g. for smart-card
    /// logins in a browser. SignInAsync applies the rules of /login: inactive and unconfirmed accounts are refused,
    /// the steps that follow (second factor, own password) are answered as action_required, continued at /auth/login/2fa
    /// and /auth/login/password-change.
    /// </summary>
    public static IEndpointRouteBuilder MapCertificateLogin(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/login/certificate", async (HttpContext http, [FromQuery] bool? useCookies,
                ISlimUserStore store, ISlimAuthManager auth, TimeProvider time, CancellationToken ct) =>
            {
                var result = await http.AuthenticateAsync(Scheme);
                if (!result.Succeeded || result.Principal.GetSlimUserId() is not { } userId) return Results.Unauthorized();

                if (await store.FindByIdAsync(userId, ct) is not { } user) return Results.Unauthorized();

                // a smart card with PIN is multi-factor on its own: pass secondFactorVerified: true for such cards
                var session = await auth.SignInAsync(user, useCookies ?? false, authenticationMethod: "cert", ct: ct);
                if (session.ActionRequired is { } steps) return Results.Ok(steps);
                return session.Succeeded
                    ? Results.Ok(session.ToResponse())
                    : Results.Json(new { status = session.Error }, statusCode: StatusCodes.Status403Forbidden);
            })
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
            .RequireSlimCsrf();
        return app;
    }
}
