using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.TestHost;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// Registration with mail: <c>/register</c> takes only the address, the mailed code (<c>/register/verify</c>) or link
/// (<c>/flow</c>) proves the mailbox, and <c>/register/password</c> creates the account – with its address confirmed.
/// </summary>
public sealed class RegistrationFlowTests
{
    private const string Email = "new@test.local";

    private static IEnumerable<string?> Actions(JsonElement answer) => answer.GetProperty("actions").EnumerateArray().Select(a => a.GetString());

    private static Task<TestApp> StartAsync() =>
        TestApp.StartAsync(new TestAppOptions { Configure = o => o.Endpoints.DefaultUseCookies = false });

    private static async Task<string> NextCodeAsync(TestApp app, int before)
    {
        for (var i = 0; i < 250 && Codes(app).Count == before; i++) await Task.Delay(20);
        return Codes(app)[^1];
    }

    private static List<string> Codes(TestApp app) =>
        app.Mail.Mails.Where(m => m.Kind == "verification" && m.To == Email).Select(m => m.Payload).ToList();

    [Fact]
    public async Task A_free_a_taken_and_a_throttled_address_get_the_same_answer()
    {
        await using var app = await StartAsync();
        var client = app.CreateClient();

        var answers = new List<JsonElement> { await client.PostJsonAsync("/auth/register", new { email = TestApp.UserEmail }) };
        for (var i = 0; i < 5; i++)   // beyond the mail limit per recipient: no further mail, the same answer
            answers.Add(await client.PostJsonAsync("/auth/register", new { email = Email }));

        Assert.All(answers, a =>
        {
            Assert.Equal(["verify_email", "set_credential"], Actions(a));
            Assert.Equal(["actions", "expiresIn", "flowToken", "status"], a.EnumerateObject().Select(p => p.Name).Order());
        });
        await app.Mail.WaitForAsync("account-exists", TestApp.UserEmail);
        Assert.DoesNotContain(app.Users.All, u => u.Email == Email);   // nothing is created before the mailbox is proven
    }

    [Fact]
    public async Task The_code_completes_the_registration_with_a_confirmed_address_and_a_session()
    {
        await using var app = await StartAsync();
        var client = app.CreateClient();

        var started = await client.PostJsonAsync("/auth/register", new { email = Email });
        var verified = await client.PostJsonAsync("/auth/register/verify", new { flowToken = started.Str("flowToken"), code = await NextCodeAsync(app, 0) });
        Assert.Equal(["set_credential"], Actions(verified));
        Assert.Equal(["password"], verified.GetProperty("details").GetProperty("setCredential").GetProperty("kinds").EnumerateArray().Select(k => k.GetString()));

        var session = await client.PostJsonAsync("/auth/register/password", new { flowToken = verified.Str("flowToken"), password = "Another123!" });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
        Assert.True(app.Users.Get(Email).EmailConfirmed);

        // once: the flow is spent, the address is taken
        var again = await client.PostJsonAsync("/auth/register/password",
            new { flowToken = verified.Str("flowToken"), password = "Other-Pass-456" }, HttpStatusCode.Conflict);
        Assert.Equal("email_taken", again.Str("code"));
        await app.LoginBearerAsync(Email, "Another123!");
    }

    [Fact]
    public async Task A_wrong_code_is_refused_and_the_guesses_are_limited_per_flow_and_per_address()
    {
        await using var app = await StartAsync();
        var client = app.CreateClient();

        var first = await client.PostJsonAsync("/auth/register", new { email = Email });
        var code = await NextCodeAsync(app, 0);
        var wrong = code == "000000" ? "111111" : "000000";
        for (var i = 0; i < 5; i++)
            Assert.Equal("invalid_verification_code",
                (await client.PostJsonAsync("/auth/register/verify", new { flowToken = first.Str("flowToken"), code = wrong }, HttpStatusCode.Unauthorized)).Str("code"));
        Assert.Equal("too_many_attempts",
            (await client.PostJsonAsync("/auth/register/verify", new { flowToken = first.Str("flowToken"), code }, (HttpStatusCode)429)).Str("code"));

        // new flows for the address continue the count of the address
        var second = await client.PostJsonAsync("/auth/register", new { email = Email });
        await NextCodeAsync(app, 1);
        for (var i = 0; i < 5; i++)
            await client.PostJsonAsync("/auth/register/verify", new { flowToken = second.Str("flowToken"), code = wrong }, HttpStatusCode.Unauthorized);
        var third = await client.PostJsonAsync("/auth/register", new { email = Email });
        code = await NextCodeAsync(app, 2);
        await client.PostJsonAsync("/auth/register/verify", new { flowToken = third.Str("flowToken"), code }, (HttpStatusCode)429);
    }

    [Fact]
    public async Task The_link_proves_the_mailbox_on_another_device_and_in_its_own_mode()
    {
        await using var app = await StartAsync();
        await app.CreateClient().PostJsonAsync("/auth/register", new { email = Email });
        var token = TestApp.LinkToken((await app.Mail.WaitForAsync("verification", Email)).Link!);

        var browser = app.CreateClient();
        browser.SendCsrfHeader = true;
        var steps = await browser.PostJsonAsync("/auth/flow?useCookies=true", new { token });
        Assert.Equal(["set_credential"], Actions(steps));
        var read = await browser.PostJsonAsync("/auth/flow", new { flowToken = steps.Str("flowToken") });   // reading changes nothing
        Assert.Equal(["set_credential"], Actions(read));

        browser.SendCsrfHeader = false;
        Assert.Equal("csrf_validation_failed", (await browser.PostJsonAsync("/auth/register/password",
            new { flowToken = steps.Str("flowToken"), password = "Another123!" }, HttpStatusCode.Forbidden)).Str("code"));
        browser.SendCsrfHeader = true;
        await browser.PostJsonAsync("/auth/register/password", new { flowToken = steps.Str("flowToken"), password = "Another123!" });
        Assert.True(browser.Cookies.ContainsKey("SlimAuth"));

        // the account exists: neither the link nor the flow token goes on
        await app.CreateClient().PostJsonAsync("/auth/flow", new { token }, HttpStatusCode.Unauthorized);
        await app.CreateClient().PostJsonAsync("/auth/flow", new { flowToken = steps.Str("flowToken") }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_registration_token_is_no_sign_in_token()
    {
        await using var app = await StartAsync();
        var client = app.CreateClient();
        var started = await client.PostJsonAsync("/auth/register", new { email = Email });
        var code = await NextCodeAsync(app, 0);
        var verified = await client.PostJsonAsync("/auth/register/verify", new { flowToken = started.Str("flowToken"), code });

        await client.PostJsonAsync("/auth/login/verify-email", new { flowToken = started.Str("flowToken"), code }, HttpStatusCode.Unauthorized);
        await client.PostJsonAsync("/auth/login/2fa", new { flowToken = verified.Str("flowToken"), code = "123456" }, HttpStatusCode.Unauthorized);
        // and a sign-in flow token does not complete a registration
        await app.PreRegisterUnconfirmedAsync("pending@test.local", "Pending-Pass-123");
        var signIn = await client.PostJsonAsync("/auth/login", new { email = "pending@test.local", password = "Pending-Pass-123" });
        await client.PostJsonAsync("/auth/register/password", new { flowToken = signIn.Str("flowToken"), password = "Another123!" }, HttpStatusCode.Unauthorized);
        Assert.DoesNotContain(app.Users.All, u => u.Email == Email);
    }

    [Fact]
    public async Task A_registration_is_bound_to_its_tenant()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions
        {
            Builder = b => b.UseTenantKey(http => http.Request.Host.Host == "a.api.test" ? "a" : "b"),
        });
        var home = new ApiClient(app.App.GetTestClient()) { Host = "a.api.test" };
        var foreign = new ApiClient(app.App.GetTestClient()) { Host = "b.api.test" };

        var started = await home.PostJsonAsync("/auth/register", new { email = Email });
        var mail = await app.Mail.WaitForAsync("verification", Email);
        await foreign.PostJsonAsync("/auth/register/verify", new { flowToken = started.Str("flowToken"), code = mail.Payload }, HttpStatusCode.Unauthorized);
        await foreign.PostJsonAsync("/auth/flow", new { token = TestApp.LinkToken(mail.Link!) }, HttpStatusCode.Unauthorized);

        var verified = await home.PostJsonAsync("/auth/register/verify", new { flowToken = started.Str("flowToken"), code = mail.Payload });
        await foreign.PostJsonAsync("/auth/register/password", new { flowToken = verified.Str("flowToken"), password = "Another123!" }, HttpStatusCode.Unauthorized);
        Assert.DoesNotContain(app.Users.All, u => u.Email == Email);
    }

    [Fact]
    public async Task Unicode_normalization_forms_of_one_address_are_one_account()
    {
        // "josé@…" can arrive precomposed (NFC, U+00E9) or decomposed (NFD, e + U+0301) – both look identical
        var nfc = "josé@test.local";
        var nfd = "josé@test.local";
        await using var app = await TestApp.StartAsync();

        await app.PreRegisterUnconfirmedAsync(nfd, "Owner-Pass-123");
        await app.CreateClient().PostJsonAsync("/auth/register", new { email = nfc });

        Assert.Single(app.Users.All, u => u.Email.Normalize() == nfc);           // no second account
        await app.LoginConfirmingAsync(nfc, "Owner-Pass-123");                      // one identity, either form
        await app.LoginBearerAsync(nfd, "Owner-Pass-123");
        await app.Mail.WaitForAsync("account-exists", nfc);
    }

    [Theory]
    [InlineData("user+tag@test.local")]   // sub-addressing: a different mailbox for SlimIdentity, by design
    [InlineData("usеr@test.local")]       // Cyrillic "е" (U+0435): a homoglyph is a different address
    public async Task Look_alike_addresses_are_different_accounts(string lookAlike)
    {
        await using var app = await TestApp.StartAsync();
        Assert.Equal(HttpStatusCode.OK, (await app.RegisterAsync(lookAlike, "Other-Pass-456")).StatusCode);
        await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);   // the original is untouched
        await app.CreateClient().PostJsonAsync("/auth/login", new { email = lookAlike, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized);
    }

    [Theory]
    [InlineData("victim@test.local <attacker@evil.example>")]
    [InlineData("\"victim@test.local\" <attacker@evil.example>")]
    [InlineData("attacker@evil.example (victim@test.local)")]
    public async Task A_display_name_form_is_not_accepted_as_an_address(string address)
    {
        await using var app = await TestApp.StartAsync();
        var response = await app.CreateClient().PostAsync("/auth/register", new { email = address });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
