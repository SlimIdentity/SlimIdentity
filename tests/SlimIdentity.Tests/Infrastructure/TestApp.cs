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
    /// <summary>Registers the capturing mail sender (off for hosts without mail).</summary>
    public bool EmailSender { get; init; } = true;
    public Action<SlimIdentityOptions>? Configure { get; init; }
    /// <summary>Additional capabilities (API keys, password rules, external providers, …).</summary>
    public Action<SlimIdentityBuilder>? Builder { get; init; }
    /// <summary>Additional host endpoints.</summary>
    public Action<WebApplication>? Map { get; init; }
    /// <summary>Receives all log output (minimum level Trace) – e.g. to assert that no secret is ever logged.</summary>
    public ILoggerProvider? LoggerProvider { get; init; }
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
        // a test may bring its own user store (e.g. one per tenant); Users is then an unused empty store
        Users = app.Services.GetRequiredService<ISlimUserStore>() as TestUserStore ?? new TestUserStore();
        Mail = app.Services.GetService<ISlimEmailSender>() as CapturingEmailSender ?? new CapturingEmailSender();
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
        if (options.LoggerProvider is { } loggerProvider)
            builder.Logging.AddProvider(loggerProvider).SetMinimumLevel(LogLevel.Trace);

        // starts at the real time (cookies and JWTs follow this clock, the TestServer's own headers do not)
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        builder.Services.AddSingleton<TimeProvider>(time);

        var slim = builder.Services.AddSlimIdentity(o =>
            {
                o.Tokens.JwtSecret = "test-secret-0123456789-abcdefghijklmnopqrstuvwxyz";
                o.RateLimit.PermitLimit = 10_000;
                o.Cookies.SecurityStampValidationInterval = TimeSpan.Zero;
                o.TrustedOrigins.Add("https://app.test.local");
                options.Configure?.Invoke(o);
            })
            .AddUserStore<TestUserStore>(ServiceLifetime.Singleton);
        if (options.EmailSender) slim.AddEmailSender<CapturingEmailSender>(ServiceLifetime.Singleton);
        if (options.RefreshTokens) slim.AddRefreshTokenStore<TestRefreshTokenStore>(ServiceLifetime.Singleton);
        if (options.Sessions) slim.AddSessionStore<TestSessionStore>(ServiceLifetime.Singleton);
        if (options.TwoFactor) slim.AddTwoFactorStore<TestTwoFactorStore>(ServiceLifetime.Singleton);
        options.Builder?.Invoke(slim);

        var app = builder.Build();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapSlimIdentityApi();
        MapHostEndpoints(app);
        options.Map?.Invoke(app);

        if (app.Services.GetRequiredService<ISlimUserStore>() is TestUserStore users)
        {
            users.Seed(AdminEmail, AdminPassword, "Admin");
            users.Seed(UserEmail, UserPassword);
        }

        await app.StartAsync();
        return new TestApp(app, time);
    }

    private static void MapHostEndpoints(WebApplication app)
    {
        app.MapGet("/api/hello", (ClaimsPrincipal user) => new { email = user.GetSlimEmail(), impersonatedBy = user.GetImpersonatorId() })
            .RequireAuthorization();

        app.MapPost("/api/impersonate/{userId}", async (string userId, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
            {
                var target = await store.FindByIdAsync(userId, ct);
                if (target is null) return Results.NotFound();
                var result = await auth.ImpersonateAsync(target, ct);
                return result.Succeeded ? Results.Ok(result.ToResponse()) : Results.BadRequest(new { status = result.Error });
            })
            .RequireAuthorization(p => p.RequireRole("Admin"))
            .RequireSlimCsrf();

        app.MapPost("/api/impersonate/stop", async (ISlimAuthManager auth, CancellationToken ct) =>
            {
                var result = await auth.EndImpersonationAsync(ct);
                return result.Succeeded ? Results.Ok(result.ToResponse()) : Results.Json(new { status = result.Error }, statusCode: 401);
            })
            .RequireAuthorization()
            .RequireSlimCsrf();

        app.MapPost("/api/invite", async (InviteRequest request, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
            {
                if (await store.CreateAsync(new SlimNewUser { Email = request.Email }, ct) is not { } user) return Results.Conflict();
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

    /// <summary>Bearer login that must end in a session; returns the token response.</summary>
    public async Task<AuthTokens> LoginBearerAsync(string email, string password)
    {
        var client = CreateClient();
        var response = await client.PostAsync("/auth/login", new { email, password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var tokens = (await response.Content.ReadFromJsonAsync<AuthTokens>(ApiClient.Json))!;
        Assert.False(string.IsNullOrEmpty(tokens.AccessToken), "no session: " + await response.Content.ReadAsStringAsync());
        return tokens;
    }

    /// <summary>
    /// Sets the confirmation flag directly in the store and keeps the stamp, so running sessions stay valid
    /// (an address changed by the host, imported data).
    /// </summary>
    public async Task SetEmailConfirmedAsync(string email, bool confirmed)
    {
        var user = Users.Get(email);
        user.EmailConfirmed = confirmed;
        await Users.UpdateSecurityStateAsync(user, default);
    }

    /// <summary>
    /// Bearer login of an account whose address is not confirmed yet: takes step <c>verify_email</c> with the mailed code.
    /// </summary>
    public async Task<AuthTokens> LoginConfirmingAsync(string email, string password)
    {
        var steps = await CreateClient().PostJsonAsync("/auth/login", new { email, password });
        Assert.True(steps.TryGetProperty("actions", out var actions), steps.ToString());
        Assert.Equal("verify_email", actions[0].GetString());
        var code = (await Mail.WaitForAsync("verification-code", email)).Payload;
        var response = await CreateClient().PostAsync("/auth/login/verify-email", new { flowToken = steps.GetProperty("flowToken").GetString(), code });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var tokens = (await response.Content.ReadFromJsonAsync<AuthTokens>(ApiClient.Json))!;
        Assert.False(string.IsNullOrEmpty(tokens.AccessToken), "no session: " + await response.Content.ReadAsStringAsync());
        return tokens;
    }

    /// <summary>
    /// <c>POST /register</c> → the mailed code at <c>/register/verify</c> → <c>/register/password</c>. Returns the last answer
    /// (the session, or open steps).
    /// </summary>
    public async Task<HttpResponseMessage> RegisterAsync(string email, string password, object? profile = null, ApiClient? client = null)
    {
        client ??= CreateClient();
        var flowToken = await VerifyRegistrationAsync(email, client);
        return await client.PostAsync("/auth/register/password", new { flowToken, password, profile });
    }

    /// <summary><c>POST /register</c> and <c>/register/verify</c> with the mailed code; returns the flow token of step <c>set_credential</c>.</summary>
    public async Task<string> VerifyRegistrationAsync(string email, ApiClient? client = null)
    {
        client ??= CreateClient();
        var before = Mail.Mails.Count(m => m.Kind == "verification" && string.Equals(m.To, email, StringComparison.OrdinalIgnoreCase));
        var started = await client.PostJsonAsync("/auth/register", new { email });
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (Mail.Mails.Count(m => m.Kind == "verification" && string.Equals(m.To, email, StringComparison.OrdinalIgnoreCase)) == before)
        {
            if (DateTime.UtcNow > deadline) throw new TimeoutException($"No new verification mail to {email} was sent.");
            await Task.Delay(20);
        }
        var code = (await Mail.WaitForAsync("verification", email)).Payload;
        var verified = await client.PostJsonAsync("/auth/register/verify", new { flowToken = started.Str("flowToken"), code });
        return verified.Str("flowToken");
    }

    /// <summary>The token of a mailed link (the link itself without a link template).</summary>
    public static string LinkToken(string link) =>
        link.IndexOf("token=", StringComparison.Ordinal) is var i and >= 0 ? Uri.UnescapeDataString(link[(i + 6)..]) : link;

    /// <summary>
    /// An account whose address nobody proved – created through <see cref="ISlimAuthManager.RegisterAsync"/>, which
    /// leaves the address unconfirmed.
    /// </summary>
    public async Task PreRegisterUnconfirmedAsync(string email, string password)
    {
        await using var scope = App.Services.CreateAsyncScope();
        var result = await scope.ServiceProvider.GetRequiredService<ISlimAuthManager>().RegisterAsync(email, password);
        Assert.NotNull(result.User);
        Assert.False(result.User.EmailConfirmed);
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
    /// <summary>Host the request is sent to (tenants by host name); default <c>localhost</c>.</summary>
    public string Host { get; set; } = "localhost";

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

    /// <summary>POST with a raw body (malformed JSON, other content types).</summary>
    public async Task<HttpResponseMessage> SendRawAsync(string path, string body, string contentType)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(new Uri("https://localhost"), path))
        {
            Content = new StringContent(body, System.Text.Encoding.UTF8, contentType),
        };
        if (BearerToken is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", BearerToken);
        if (SendCsrfHeader) request.Headers.Add("X-CSRF", "1");
        return await http.SendAsync(request);
    }

    public async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, object? body, IReadOnlyDictionary<string, string>? headers = null)
    {
        using var request = new HttpRequestMessage(method, new Uri(new Uri($"https://{Host}"), path));
        foreach (var (name, value) in headers ?? new Dictionary<string, string>()) request.Headers.Add(name, value);
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
