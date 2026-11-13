using System.Net;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// No body, a JSON <c>null</c>, an empty object or fields set to <c>null</c> are client errors: every endpoint answers
/// 4xx, never 500 – whether the caller is anonymous or signed in.
/// </summary>
public sealed class MalformedBodyTests
{
    private static readonly string[] PostEndpoints =
    [
        "/auth/login", "/auth/login/2fa", "/auth/login/password-change", "/auth/login/external/exchange", "/auth/link/external",
        "/auth/refresh", "/auth/logout", "/auth/logout-all", "/auth/register", "/auth/register/verify", "/auth/register/password",
        "/auth/forgot-password", "/auth/change-password", "/auth/change-email", "/auth/confirm-email-change",
        "/auth/invitation/info", "/auth/invitation/accept",
        "/auth/2fa/setup", "/auth/2fa/enable", "/auth/2fa/enable-email", "/auth/2fa/disable", "/auth/2fa/recovery-codes",
        "/auth/2fa/forget-device", "/auth/2fa/forget-all-devices",
        "/auth/sign-in-methods/external/remove",
        "/auth/passkeys/register/options", "/auth/passkeys/register", "/auth/passkeys/login/options", "/auth/passkeys/login",
        "/auth/sign-in-methods/passkeys/rename", "/auth/sign-in-methods/passkeys/remove",
        "/auth/backchannel-logout/Corp",
    ];

    private static readonly string[] Bodies =
    [
        "null", "{}", "[]", "\"text\"", "42",
        """{"email":null,"password":null,"token":null,"code":null,"newPassword":null,"currentPassword":null,"newEmail":null,"flowToken":null,"recoveryCode":null,"refreshToken":null,"setupToken":null,"state":null,"credential":null,"id":null,"name":null,"provider":null,"providerKey":null,"profile":null,"codeVerifier":null,"twoFactorRememberToken":null}""",
        """{"state":"x","credential":{"id":null,"rawId":null,"type":null,"response":null}}""",
        """{"state":"x","credential":{"response":{"clientDataJSON":null,"attestationObject":null,"authenticatorData":null,"signature":null,"userHandle":null}}}""",
    ];

    [Fact]
    public async Task Missing_or_null_fields_never_cause_a_server_error()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions
        {
            Builder = b =>
            {
                b.AddPasskeyStore<TestPasskeyStore>(ServiceLifetime.Singleton).AddPasskeys(o => o.RelyingPartyId = "test.local");
                b.AddExternalLoginStore<TestExternalLoginStore>(ServiceLifetime.Singleton);
                b.AddBackChannelLogout("Corp", o =>
                {
                    o.ClientId = "client";
                    o.Configuration = new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration { Issuer = "https://idp.test" };
                });
            },
        });

        var anonymous = app.CreateClient();
        var signedIn = app.CreateClient();
        signedIn.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;

        var failures = new List<string>();
        foreach (var client in new[] { anonymous, signedIn })
            foreach (var path in PostEndpoints)
                foreach (var body in Bodies)
                {
                    var response = await client.SendRawAsync(path, body, "application/json");
                    if ((int)response.StatusCode >= 500)
                        failures.Add($"{(client == signedIn ? "signed in" : "anonymous")} {path} {body[..Math.Min(body.Length, 40)]} → {(int)response.StatusCode}");
                }

        Assert.Empty(failures);
    }
}
