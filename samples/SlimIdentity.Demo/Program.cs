using System.Net;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SlimIdentity;
using SlimIdentity.Contracts;
using SlimIdentity.Security;
using SlimIdentity.Demo;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.TypeInfoResolverChain.Add(DemoJsonContext.Default));
builder.Services.AddSingleton<DemoSettings>();
builder.Services.AddSingleton<DemoMailbox>();
builder.Services.AddSingleton(TimeProvider.System);

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
    .AddApiKeyStore<InMemoryApiKeyStore>(ServiceLifetime.Singleton)
    .AddPasskeyStore<InMemoryPasskeyStore>(ServiceLifetime.Singleton);   // package SlimIdentity.Passkeys; relying party: host of Links.BaseUrl

// Social login (docs/guides/google-and-entra-id.md) – only when credentials are configured, e.g.
//   dotnet user-secrets set "Google:ClientId" "…" --project samples/SlimIdentity.Demo
//   dotnet user-secrets set "Google:ClientSecret" "…" --project samples/SlimIdentity.Demo
// with the redirect URI http://localhost:5209/signin-google registered at Google.
if (builder.Configuration["Google:ClientId"] is { Length: > 0 } googleClientId)
{
    slim.Authentication.AddGoogle("Google", o =>
    {
        o.ClientId = googleClientId;
        o.ClientSecret = builder.Configuration["Google:ClientSecret"]!;
        o.ClaimActions.MapJsonKey("email_verified", "email_verified");   // Google's own verification – not blind trust
        o.UseSlimErrorRedirects();                                       // "Cancel" at Google → ?slim_error=access_denied
    });
}

var app = builder.Build();

var demo = app.Services.GetRequiredService<DemoSettings>();
if (demo.Breakme)
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"""

        ===== BREAKME MODE =====================================================
        Seeded accounts have random passwords (only shown here, for the operator):
          admin@demo.local  {demo.AdminPassword}
          user@demo.local   {demo.UserPassword}
        Rules and goals: BREAKME.md
        ========================================================================
        """);
    Console.ResetColor();
}

// 2. Standard pipeline – order stays explicit in the host
app.UseForwardedHeaders(); // first: everything below needs the real scheme, host and client IP
app.UseHttpsRedirection();
app.UseDefaultFiles();     // playground: wwwroot/index.html
app.UseStaticFiles();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapOpenApi(); // /openapi/v1.json

// 3. Hardened endpoints
app.MapSlimIdentityApi();

// ---------------------------------------------------------------------------------------------
// Demo endpoints of the "host application"
// ---------------------------------------------------------------------------------------------

// Playground (wwwroot/index.html): fake mailbox and the links from the mails (they point back into the page)
app.MapGet("/api/playground/info", async (DemoSettings settings, IOptions<SlimIdentityOptions> options, IAuthenticationSchemeProvider schemes) =>
    new DemoInfo(settings.Breakme, !string.IsNullOrEmpty(options.Value.Tokens.JwtSecret), ["admin@demo.local", "user@demo.local"],
        [.. (await schemes.GetRequestHandlerSchemesAsync()).Select(s => s.Name)]));   // the configured external providers
app.MapGet("/api/playground/mailbox", (string address, DemoMailbox mailbox) => mailbox.For(address))
    .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);
foreach (var page in new[] { "/verify-email", "/reset-password", "/accept-invitation", "/confirm-email-change" })
    app.MapGet(page, (IWebHostEnvironment env) => Results.File(Path.Combine(env.WebRootPath, "index.html"), "text/html"));

app.MapGet("/api/hello", (ClaimsPrincipal user) =>
        new HelloResponse($"Hello {user.GetSlimEmail()}", user.GetSlimUserId(), user.GetImpersonatorId()))
    .RequireAuthorization();

app.MapGet("/api/admin", (ClaimsPrincipal user) => new MessageResponse("Admins only", user.GetSlimEmail()))
    .RequireAuthorization(p => p.RequireRole("Admin"));

// M2M via X-API-Key: demo-key-123
app.MapGet("/api/m2m/report", (ClaimsPrincipal client) => new ReportResponse(client.GetSlimUserId(), DateTimeOffset.UtcNow))
    .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = SlimIdentityDefaults.ApiKeyScheme });

// Admin impersonation via ISlimAuthManager ('act' claim keeps the admin id)
app.MapPost("/api/admin/impersonate/{userId}", async (
        string userId, [FromQuery] bool? useCookies, ClaimsPrincipal admin,
        ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
    {
        var target = await store.FindByIdAsync(userId, ct);
        if (target is null) return Results.NotFound();

        var result = await auth.ImpersonateAsync(target, admin.GetSlimUserId()!, useCookies ?? admin.IsSlimCookieSession(), ct);
        return result.Succeeded
            ? Results.Ok(result.ToResponse())
            : Results.BadRequest(new SlimStatusResponse(result.Error!));
    })
    .RequireAuthorization(p => p.RequireRole("Admin"))
    .RequireSlimCsrf();

// End impersonation: back to the original admin – only if the admin is still active with an unchanged security stamp
app.MapPost("/api/admin/impersonate/stop", async (ISlimAuthManager auth, CancellationToken ct) =>
    {
        var result = await auth.EndImpersonationAsync(ct);
        return result.Succeeded
            ? Results.Ok(result.ToResponse())
            : Results.Json(new SlimStatusResponse(result.Error!), DemoJsonContext.Default.SlimStatusResponse,
                statusCode: result.Error == "not_impersonating" ? 400 : 401);
    })
    .RequireAuthorization()
    .RequireSlimCsrf();

// Step-up auth (sudo mode): confirm password → 5 minutes elevated session
app.MapPost("/api/sudo", async (
        SudoRequest request, ClaimsPrincipal principal, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
    {
        var user = await store.FindByIdAsync(principal.GetSlimUserId()!, ct);
        if (user is null) return Results.Unauthorized();
        // lockout + notification like the built-in endpoints (400 invalid_password / 423)
        if (await auth.ConfirmPasswordAsync(user, request.Password, ct) is { } failure) return failure;

        var result = await auth.ElevateToSudoAsync(user, TimeSpan.FromMinutes(5), principal.IsSlimCookieSession(), ct);
        return Results.Ok(result.ToResponse());
    })
    .RequireAuthorization()
    .RequireSlimCsrf()
    .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);

app.MapDelete("/api/danger-zone", (ClaimsPrincipal user) => new SudoActionResponse("Sudo action executed", user.GetSudoUntil()))
    .RequireAuthorization(SlimIdentityDefaults.SudoPolicy)
    .RequireSlimCsrf();

// Admin ban: end all sessions (stamp rotation + session store) and block further logins
app.MapPost("/api/admin/users/{userId}/ban", async (string userId, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
    {
        var user = await store.FindByIdAsync(userId, ct);
        if (user is null) return Results.NotFound();
        await auth.SignOutEverywhereAsync(user, ct);
        ((InMemoryUserStore)store).SetActive(userId, false);
        return Results.Ok(new SlimStatusResponse("banned"));
    })
    .RequireAuthorization(p => p.RequireRole("Admin"))
    .RequireSlimCsrf();

// Invitation: create the user without password (+ your own business data), then hand out the link.
// In a real app the link is mailed – the demo returns it.
app.MapPost("/api/admin/invite", async (InviteRequest request, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
    {
        // CreateAsync returns null if the address is taken (unique index) – no separate check-then-act lookup
        if (await store.CreateAsync(new SlimNewUser { Email = request.Email }, ct) is not { } user)
            return Results.Conflict(new SlimStatusResponse("already_exists"));
        var invitation = await auth.CreateInvitationAsync(user, ct: ct);
        return Results.Ok(invitation);
    })
    .RequireAuthorization(p => p.RequireRole("Admin"))
    .RequireSlimCsrf();

app.MapGet("/api/admin/users", (ISlimUserStore store) =>
        ((InMemoryUserStore)store).All
            .Select(u => new UserSummary(u.Id, u.Email, u.IsActive, u.EmailConfirmed, u.TwoFactorEnabled, u.LockoutEndUtc))
            .ToList())
    .RequireAuthorization(p => p.RequireRole("Admin"));

app.Run();

// Native AOT: the host's own DTOs are serialized via source generation as well (SlimIdentity registers its own).
internal sealed record SudoRequest(string Password);
internal sealed record InviteRequest(string Email);
internal sealed record HelloResponse(string Message, string? UserId, string? ImpersonatedBy);
internal sealed record MessageResponse(string Message, string? User);
internal sealed record ReportResponse(string? Client, DateTimeOffset GeneratedAt);
internal sealed record SudoActionResponse(string Message, DateTimeOffset? Until);
internal sealed record UserSummary(string Id, string Email, bool IsActive, bool EmailConfirmed, bool TwoFactorEnabled, DateTimeOffset? LockoutEndUtc);

[JsonSerializable(typeof(SudoRequest))]
[JsonSerializable(typeof(InviteRequest))]
[JsonSerializable(typeof(HelloResponse))]
[JsonSerializable(typeof(MessageResponse))]
[JsonSerializable(typeof(ReportResponse))]
[JsonSerializable(typeof(SudoActionResponse))]
[JsonSerializable(typeof(List<UserSummary>))]
[JsonSerializable(typeof(SlimStatusResponse))]
[JsonSerializable(typeof(DemoInfo))]
[JsonSerializable(typeof(IReadOnlyList<DemoMail>))]
[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
internal sealed partial class DemoJsonContext : JsonSerializerContext;
