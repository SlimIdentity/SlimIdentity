using System.Globalization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Every mail carries who it is about, the request's culture and host data captured at request time.</summary>
public sealed class EmailContextTests
{
    /// <summary>Host data for templates, e.g. the tenant – captured while the request still exists.</summary>
    private sealed class TenantEnricher : ISlimEmailContextEnricher
    {
        public void Enrich(HttpContext httpContext, string kind, string? userId, IDictionary<string, string> items)
        {
            if (httpContext.Request.Headers.TryGetValue("X-Tenant", out var tenant)) items["tenant"] = tenant.ToString();
        }
    }

    private static TestAppOptions Localized() => new()
    {
        Builder = b => b.AddEmailContextEnricher<TenantEnricher>(),
        Map = app => app.UseRequestLocalization(o =>
        {
            o.SetDefaultCulture("en-US");
            o.AddSupportedUICultures("en-US", "de-DE");
            o.AddSupportedCultures("en-US", "de-DE");
        }),
    };

    private static readonly Dictionary<string, string> GermanTenantA = new() { ["Accept-Language"] = "de-DE", ["X-Tenant"] = "a" };

    [Fact]
    public async Task A_queued_mail_carries_user_culture_and_host_data_of_the_request()
    {
        await using var app = await TestApp.StartAsync(Localized());
        var userId = app.Users.Get(TestApp.UserEmail).Id;

        await app.CreateClient().SendAsync(HttpMethod.Post, "/auth/forgot-password", new { email = TestApp.UserEmail }, GermanTenantA);
        var mail = await app.Mail.WaitForAsync("password-reset", TestApp.UserEmail);   // sent by the background queue

        Assert.Equal(SlimEmailKinds.PasswordReset, mail.Context!.Kind);
        Assert.Equal(userId, mail.Context.UserId);
        Assert.Equal("de-DE", mail.Context.Culture.Name);
        Assert.Equal("a", mail.Context.Items["tenant"]);
    }

    [Fact]
    public async Task The_second_factor_code_carries_the_context_as_well()
    {
        await using var app = await TestApp.StartAsync(Localized());
        var user = app.Users.Get(TestApp.UserEmail);
        user.TwoFactorEnabled = true;
        await app.Users.UpdateSecurityStateAsync(user, default);

        await app.CreateClient().SendAsync(HttpMethod.Post, "/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword }, GermanTenantA);
        var mail = await app.Mail.WaitForAsync("two-factor", TestApp.UserEmail);

        Assert.Equal(SlimEmailKinds.TwoFactorCode, mail.Context!.Kind);
        Assert.Equal(user.Id, mail.Context.UserId);
        Assert.Equal("de-DE", mail.Context.Culture.Name);
        Assert.Equal("a", mail.Context.Items["tenant"]);
    }

    [Fact]
    public async Task Without_localization_the_mail_uses_the_current_culture_and_no_items()
    {
        await using var app = await TestApp.StartAsync();
        await app.CreateClient().PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail });
        var mail = await app.Mail.WaitForAsync("password-reset", TestApp.UserEmail);

        Assert.NotNull(mail.Context!.Culture);
        Assert.Empty(mail.Context.Items);
    }
}
