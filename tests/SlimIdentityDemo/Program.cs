using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SlimIdentity;
using SlimIdentity.Abstractions;
using SlimIdentity.Security;
using SlimIdentityDemo;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

// Reverse proxy with TLS termination: take client IP, scheme and host from X-Forwarded-* – but only from
// trusted proxies (default: loopback only). Without this the CSRF origin check sees http://, OAuth builds
// http:// redirect URIs, UseHttpsRedirection loops and the rate limiter puts every user into the proxy's bucket.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    var proxy = builder.Configuration.GetSection("ReverseProxy");
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    foreach (var ip in proxy.GetSection("KnownProxies").Get<string[]>() ?? [])
        o.KnownProxies.Add(IPAddress.Parse(ip));
    foreach (var network in proxy.GetSection("KnownNetworks").Get<string[]>() ?? [])
        o.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(network));
    // public host names the proxy may forward in X-Forwarded-Host (empty = any)
    foreach (var host in proxy.GetSection("AllowedHosts").Get<string[]>() ?? [])
        o.AllowedHosts.Add(host);
});

// 1. Services & stores (appsettings.json section + code overrides)
var slim = builder.Services.AddSlimIdentity(
        builder.Configuration.GetSection(SlimIdentityOptions.DefaultSectionName),
        options =>
        {
            options.Lockout.MaxFailedAttempts = 5;
            options.Lockout.Duration = TimeSpan.FromMinutes(1);    // first lockout, doubles each time …
            options.Lockout.MaxDuration = TimeSpan.FromHours(1);   // … up to this cap
            options.Cookies.SameSite = SameSiteMode.Strict;
            // options.Tokens.JwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET")!; // production
        })
    .AddUserStore<InMemoryUserStore>(ServiceLifetime.Singleton)              // mandatory
    .AddEmailSender<ConsoleEmailSender>(ServiceLifetime.Singleton)           // mandatory
    .AddRefreshTokenStore<InMemoryRefreshTokenStore>(ServiceLifetime.Singleton)
    .AddSessionStore<InMemorySessionStore>(ServiceLifetime.Singleton)            // per-device logout, /auth/sessions
    .AddTwoFactorStore<InMemoryTwoFactorStore>(ServiceLifetime.Singleton)
    .AddExternalLoginStore<InMemoryExternalLoginStore>(ServiceLifetime.Singleton)
    .AddApiKeyStore<InMemoryApiKeyStore>(ServiceLifetime.Singleton);

// Social login: add any remote handler and point it at the SlimIdentity external scheme, e.g.
// (package Microsoft.AspNetCore.Authentication.Google)
// slim.Authentication.AddGoogle("Google", o =>
// {
//     o.ClientId = builder.Configuration["Google:ClientId"]!;
//     o.ClientSecret = builder.Configuration["Google:ClientSecret"]!;
//     o.SignInScheme = SlimIdentityDefaults.ExternalScheme;
// });
// → browser navigation to /auth/login/Google?returnUrl=/&useCookies=true

var app = builder.Build();

// 2. Standard pipeline – order stays explicit in the host
app.UseForwardedHeaders(); // first: everything below needs the real scheme, host and client IP
app.UseHttpsRedirection();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapOpenApi(); // /openapi/v1.json

// 3. Hardened endpoints
app.MapSlimIdentityApi();

// ---------------------------------------------------------------------------------------------
// Demo endpoints of the "host application"
// ---------------------------------------------------------------------------------------------

app.MapGet("/", () => Results.Text(
    "SlimIdentity demo – see SlimIdentityDemo.http. Users: admin@demo.local / Admin123!, user@demo.local / User1234!"));

app.MapGet("/api/hello", (ClaimsPrincipal user) =>
        new { message = $"Hello {user.GetSlimEmail()}", userId = user.GetSlimUserId(), impersonatedBy = user.GetImpersonatorId() })
    .RequireAuthorization();

app.MapGet("/api/admin", (ClaimsPrincipal user) => new { message = "Admins only", user = user.GetSlimEmail() })
    .RequireAuthorization(p => p.RequireRole("Admin"));

// M2M via X-API-Key: demo-key-123
app.MapGet("/api/m2m/report", (ClaimsPrincipal client) => new { client = client.GetSlimUserId(), generatedAt = DateTimeOffset.UtcNow })
    .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = SlimIdentityDefaults.ApiKeyScheme });

// Admin impersonation via ISlimAuthManager ('act' claim keeps the admin id)
app.MapPost("/api/admin/impersonate/{userId}", async (
        string userId, [FromQuery] bool? useCookies, ClaimsPrincipal admin,
        ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
    {
        if (admin.IsImpersonating()) return Results.BadRequest(new { status = "already_impersonating" });
        var target = await store.FindByIdAsync(userId, ct);
        if (target is null) return Results.NotFound();

        var result = await auth.ImpersonateAsync(target, admin.GetSlimUserId()!, useCookies ?? admin.IsSlimCookieSession(), ct);
        return result.Succeeded
            ? Results.Ok(result.ToResponse(DateTimeOffset.UtcNow))
            : Results.BadRequest(new { status = result.Error });
    })
    .RequireAuthorization(p => p.RequireRole("Admin"))
    .RequireSlimCsrf();

// End impersonation: back to the original admin – only if the admin is still active with an unchanged security stamp
app.MapPost("/api/admin/impersonate/stop", async (ISlimAuthManager auth, CancellationToken ct) =>
    {
        var result = await auth.EndImpersonationAsync(ct);
        return result.Succeeded
            ? Results.Ok(result.ToResponse(DateTimeOffset.UtcNow))
            : Results.Json(new { status = result.Error }, statusCode: result.Error == "not_impersonating" ? 400 : 401);
    })
    .RequireAuthorization()
    .RequireSlimCsrf();

// Step-up auth (sudo mode): confirm password → 5 minutes elevated session
app.MapPost("/api/sudo", async (
        SudoRequest request, ClaimsPrincipal principal, ISlimUserStore store,
        IPasswordHasher<SlimUser> hasher, ISlimAuthManager auth, CancellationToken ct) =>
    {
        var user = await store.FindByIdAsync(principal.GetSlimUserId()!, ct);
        if (user is null || string.IsNullOrEmpty(user.PasswordHash)
            || hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
            return Results.BadRequest(new { status = "invalid_password" });

        var result = await auth.ElevateSessionAsync(user, [SlimClaims.SudoFor(TimeSpan.FromMinutes(5))], principal.IsSlimCookieSession(), ct);
        return Results.Ok(result.ToResponse(DateTimeOffset.UtcNow));
    })
    .RequireAuthorization()
    .RequireSlimCsrf()
    .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);

app.MapDelete("/api/danger-zone", (ClaimsPrincipal user) => new { message = "Sudo action executed", until = user.GetSudoUntil() })
    .RequireAuthorization(SlimIdentityDefaults.SudoPolicy)
    .RequireSlimCsrf();

// Admin ban: end all sessions (stamp rotation + session store) and block further logins
app.MapPost("/api/admin/users/{userId}/ban", async (string userId, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
    {
        var user = await store.FindByIdAsync(userId, ct);
        if (user is null) return Results.NotFound();
        await auth.SignOutEverywhereAsync(user, ct);
        ((InMemoryUserStore)store).SetActive(userId, false);
        return Results.Ok(new { status = "banned" });
    })
    .RequireAuthorization(p => p.RequireRole("Admin"))
    .RequireSlimCsrf();

// Invitation: create the user without password (+ your own business data), then hand out the link.
// In a real app the link is mailed – the demo returns it.
app.MapPost("/api/admin/invite", async (InviteRequest request, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
    {
        if (await store.FindByEmailAsync(request.Email, ct) is not null) return Results.Conflict(new { status = "already_exists" });
        var user = await store.CreateAsync(request.Email, passwordHash: string.Empty, ct);
        var invitation = await auth.CreateInvitationAsync(user, ct: ct);
        return Results.Ok(invitation);
    })
    .RequireAuthorization(p => p.RequireRole("Admin"))
    .RequireSlimCsrf();

app.MapGet("/api/admin/users", (ISlimUserStore store) =>
        ((InMemoryUserStore)store).All.Select(u => new { u.Id, u.Email, u.IsActive, u.EmailConfirmed, u.TwoFactorEnabled, u.LockoutEndUtc }))
    .RequireAuthorization(p => p.RequireRole("Admin"));

app.Run();

internal sealed record SudoRequest(string Password);
internal sealed record InviteRequest(string Email);
