using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using SlimIdentity.Security;

namespace SlimIdentity.Tests.Infrastructure;

public sealed class TestAppOptions
{
    public bool Sessions { get; init; } = true;
    public bool RefreshTokens { get; init; } = true;
    public bool TwoFactor { get; init; } = true;
    public Action<SlimIdentityOptions>? Configure { get; init; }
}

/// <summary>An in-memory host with SlimIdentity, test stores, a fake clock and a few host endpoints.</summary>
public sealed class TestApp : IAsyncDisposable
{
    public const string AdminEmail = "admin@test.local";
    public const string AdminPassword = "Admin123!";
    public const string UserEmail = "user@test.local";
    public const string UserPassword = "User1234!";

    private TestApp(WebApplication app, FakeTimeProvider time)
    {
        App = app;
        Time = time;
        Users = (TestUserStore)app.Services.GetRequiredService<ISlimUserStore>();
        Mail = (CapturingEmailSender)app.Services.GetRequiredService<ISlimEmailSender>();
        Sessions = app.Services.GetService<ISlimSessionStore>() as TestSessionStore;
    }

    public WebApplication App { get; }
    public FakeTimeProvider Time { get; }
    public TestUserStore Users { get; }
    public CapturingEmailSender Mail { get; }
    public TestSessionStore? Sessions { get; }

    public static async Task<TestApp> StartAsync(TestAppOptions? options = null)
    {
        options ??= new TestAppOptions();
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        // starts at the real time: JWT / DataProtector validation use the system clock
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        builder.Services.AddSingleton<TimeProvider>(time);

        var slim = builder.Services.AddSlimIdentity(o =>
            {
                o.Tokens.JwtSecret = "test-secret-0123456789-abcdefghijklmnopqrstuvwxyz";
                o.RateLimit.PermitLimit = 10_000;
                o.Cookies.SecurityStampValidationInterval = TimeSpan.Zero;
                o.Csrf.AllowedOrigins.Add("https://app.test.local");
                options.Configure?.Invoke(o);
            })
            .AddUserStore<TestUserStore>(ServiceLifetime.Singleton)
            .AddEmailSender<CapturingEmailSender>(ServiceLifetime.Singleton);
        if (options.RefreshTokens) slim.AddRefreshTokenStore<TestRefreshTokenStore>(ServiceLifetime.Singleton);
        if (options.Sessions) slim.AddSessionStore<TestSessionStore>(ServiceLifetime.Singleton);
        if (options.TwoFactor) slim.AddTwoFactorStore<TestTwoFactorStore>(ServiceLifetime.Singleton);

        var app = builder.Build();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapSlimIdentityApi();
        MapHostEndpoints(app);

        var users = (TestUserStore)app.Services.GetRequiredService<ISlimUserStore>();
        users.Seed(AdminEmail, AdminPassword, "Admin");
        users.Seed(UserEmail, UserPassword);

        await app.StartAsync();
        return new TestApp(app, time);
    }

    private static void MapHostEndpoints(WebApplication app)
    {
        app.MapGet("/api/hello", (ClaimsPrincipal user) => new { email = user.GetSlimEmail(), impersonatedBy = user.GetImpersonatorId() })
            .RequireAuthorization();

        app.MapPost("/api/impersonate/{userId}", async (string userId, ClaimsPrincipal admin, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
            {
                var target = await store.FindByIdAsync(userId, ct);
                if (target is null) return Results.NotFound();
                var result = await auth.ImpersonateAsync(target, admin.GetSlimUserId()!, admin.IsSlimCookieSession(), ct);
                return result.Succeeded ? Results.Ok(result.ToResponse(DateTimeOffset.UtcNow)) : Results.BadRequest(new { status = result.Error });
            })
            .RequireAuthorization(p => p.RequireRole("Admin"))
            .RequireSlimCsrf();

        app.MapPost("/api/impersonate/stop", async (ISlimAuthManager auth, CancellationToken ct) =>
            {
                var result = await auth.EndImpersonationAsync(ct);
                return result.Succeeded ? Results.Ok(result.ToResponse(DateTimeOffset.UtcNow)) : Results.Json(new { status = result.Error }, statusCode: 401);
            })
            .RequireAuthorization()
            .RequireSlimCsrf();

        app.MapPost("/api/invite", async (InviteRequest request, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
            {
                var user = await store.CreateAsync(request.Email, string.Empty, ct);
                return Results.Ok(await auth.CreateInvitationAsync(user, ct: ct));
            })
            .RequireAuthorization(p => p.RequireRole("Admin"));

        app.MapPost("/api/ban/{userId}", async (string userId, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
            {
                var user = await store.FindByIdAsync(userId, ct);
                if (user is null) return Results.NotFound();
                await auth.SignOutEverywhereAsync(user, ct);
                ((TestUserStore)store).SetActive(userId, false);
                return Results.Ok();
            })
            .RequireAuthorization(p => p.RequireRole("Admin"));
    }

    /// <summary>A client with its own cookie jar (one "browser" / "device").</summary>
    public ApiClient CreateClient() => new(App.GetTestClient());

    /// <summary>Bearer login; returns the token response.</summary>
    public async Task<AuthTokens> LoginBearerAsync(string email, string password)
    {
        var client = CreateClient();
        var response = await client.PostAsync("/auth/login", new { email, password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<AuthTokens>(ApiClient.Json))!;
    }

    public async ValueTask DisposeAsync()
    {
        await App.StopAsync();
        await App.DisposeAsync();
    }

    private sealed record InviteRequest(string Email);
}

public sealed record AuthTokens(string Status, string Mode, string? AccessToken, string? RefreshToken, int? ExpiresIn);

/// <summary>HttpClient wrapper with a minimal cookie jar and convenience methods.</summary>
public sealed class ApiClient(HttpClient http)
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);

    public string? BearerToken { get; set; }
    public bool SendCsrfHeader { get; set; }
    public string? Origin { get; set; }

    public IReadOnlyDictionary<string, string> Cookies => _cookies;

    public void SetCookies(IReadOnlyDictionary<string, string> cookies)
    {
        _cookies.Clear();
        foreach (var (k, v) in cookies) _cookies[k] = v;
    }

    public Task<HttpResponseMessage> GetAsync(string path) => SendAsync(HttpMethod.Get, path, null);
    public Task<HttpResponseMessage> DeleteAsync(string path) => SendAsync(HttpMethod.Delete, path, null);
    public Task<HttpResponseMessage> PostAsync(string path, object? body = null) => SendAsync(HttpMethod.Post, path, body ?? new { });

    public async Task<JsonElement> PostJsonAsync(string path, object? body = null, HttpStatusCode expected = HttpStatusCode.OK)
    {
        var response = await PostAsync(path, body);
        var content = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == expected, $"{path}: expected {(int)expected}, got {(int)response.StatusCode}: {content}");
        return content.Length == 0 ? default : JsonDocument.Parse(content).RootElement.Clone();
    }

    public async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, object? body)
    {
        using var request = new HttpRequestMessage(method, new Uri(new Uri("https://localhost"), path));
        if (body is not null) request.Content = JsonContent.Create(body, options: Json);
        if (BearerToken is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", BearerToken);
        if (SendCsrfHeader) request.Headers.Add("X-CSRF", "1");
        if (Origin is not null) request.Headers.Add("Origin", Origin);
        if (_cookies.Count > 0) request.Headers.Add("Cookie", string.Join("; ", _cookies.Select(c => $"{c.Key}={c.Value}")));

        var response = await http.SendAsync(request);
        if (response.Headers.TryGetValues("Set-Cookie", out var setCookies))
        {
            foreach (var header in setCookies)
            {
                var pair = header.Split(';', 2)[0];
                var eq = pair.IndexOf('=');
                var (name, value) = (pair[..eq], pair[(eq + 1)..]);
                var expired = header.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase);
                if (expired || value.Length == 0) _cookies.Remove(name);
                else _cookies[name] = value;
            }
        }
        return response;
    }
}

public static class JsonElementExtensions
{
    public static string Str(this JsonElement e, string name) => e.GetProperty(name).GetString()!;
}
