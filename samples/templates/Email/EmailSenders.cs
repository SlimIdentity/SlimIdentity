// SlimIdentity sample – ISlimEmailSender adapters. Copy the one you need.
//   MailKitEmailSender   → package MailKit
//   SendGridEmailSender  → package SendGrid
//   LoggingEmailSender   → no package (development)

using SlimIdentity;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace MyApp.Mail;

public sealed class SmtpSettings
{
    public string Host { get; set; } = "";
    public int Port { get; set; } = 587;
    public string User { get; set; } = "";
    public string Password { get; set; } = "";
    public string From { get; set; } = "no-reply@example.com";
    public string FromName { get; set; } = "MyApp";
}

/// <summary>
/// SMTP via MailKit. builder.Services.Configure&lt;SmtpSettings&gt;(config.GetSection("Smtp"));
/// <c>context.Culture</c> selects the language of your templates, <c>context.UserId</c> / <c>context.Items</c> the
/// account or tenant (branding) – mails are sent from a background queue, so never read HttpContext or the thread culture.
/// </summary>
public sealed class MailKitEmailSender(IOptions<SmtpSettings> settings) : ISlimEmailSender
{
    public Task SendVerificationEmailAsync(SlimEmailContext context, string email, string link, CancellationToken ct) =>
        SendAsync(email, "Please confirm your e-mail address",
            $"<p>Welcome! Please confirm your address:</p><p><a href=\"{link}\">Confirm e-mail</a></p>", ct);

    public Task SendPasswordResetEmailAsync(SlimEmailContext context, string email, string link, CancellationToken ct) =>
        SendAsync(email, "Reset your password",
            $"<p>Click the link to choose a new password (valid for one hour):</p><p><a href=\"{link}\">Reset password</a></p>" +
            "<p>If you did not request this, you can ignore this e-mail.</p>", ct);

    public Task SendTwoFactorCodeAsync(SlimEmailContext context, string email, string code, CancellationToken ct) =>
        SendAsync(email, $"Your sign-in code: {code}", $"<p>Your code is <b>{code}</b>. It expires in a few minutes.</p>", ct);

    public Task SendEmailChangeConfirmationAsync(SlimEmailContext context, string newEmail, string link, CancellationToken ct) =>
        SendAsync(newEmail, "Confirm your new e-mail address",
            $"<p>Please confirm that this address should be used for your account:</p><p><a href=\"{link}\">Confirm address</a></p>" +
            "<p>If you did not request this, you can ignore this e-mail.</p>", ct);

    // Optional (default: no mail) – sent to the old address after the change. Encode user input in HTML!
    public Task SendEmailChangedNotificationAsync(SlimEmailContext context, string oldEmail, string newEmail, CancellationToken ct) =>
        SendAsync(oldEmail, "Your e-mail address was changed",
            $"<p>The sign-in address of your account was changed to <b>{System.Net.WebUtility.HtmlEncode(newEmail)}</b>.</p>" +
            "<p>If this was not you, contact support immediately.</p>", ct);

    // Optional (default: no mail) – someone tried to register with an address that already has an account.
    public Task SendAccountExistsEmailAsync(SlimEmailContext context, string email, CancellationToken ct) =>
        SendAsync(email, "You already have an account",
            "<p>Someone (hopefully you) tried to create a new account with this address. You already have one.</p>" +
            "<p>Forgot your password? Use \"Forgot password\" on the sign-in page. Otherwise you can ignore this e-mail.</p>", ct);

    // Optional (default: no mail) – the account was locked after repeated failed sign-ins.
    public Task SendLockoutNotificationEmailAsync(SlimEmailContext context, string email, DateTimeOffset lockoutEndUtc, CancellationToken ct) =>
        SendAsync(email, "Your account was temporarily locked",
            $"<p>There were too many failed sign-ins to your account. It is locked until {lockoutEndUtc.ToString("u", context.Culture)}.</p>" +
            "<p>If this was not you, change your password after the lock ends.</p>", ct);

    private async Task SendAsync(string to, string subject, string html, CancellationToken ct)
    {
        var s = settings.Value;
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(s.FromName, s.From));
        message.To.Add(MailboxAddress.Parse(to));
        message.Subject = subject;
        message.Body = new BodyBuilder { HtmlBody = html }.ToMessageBody();

        using var client = new SmtpClient();
        await client.ConnectAsync(s.Host, s.Port, SecureSocketOptions.StartTls, ct);
        if (!string.IsNullOrEmpty(s.User)) await client.AuthenticateAsync(s.User, s.Password, ct);
        await client.SendAsync(message, ct);
        await client.DisconnectAsync(true, ct);
    }
}

/// <summary>SendGrid Web API. builder.Services.AddSingleton&lt;ISendGridClient&gt;(new SendGridClient(apiKey));</summary>
public sealed class SendGridEmailSender(ISendGridClient client, ILogger<SendGridEmailSender> logger) : ISlimEmailSender
{
    private static readonly EmailAddress From = new("no-reply@example.com", "MyApp");

    public Task SendVerificationEmailAsync(SlimEmailContext context, string email, string link, CancellationToken ct) =>
        SendAsync(email, "Please confirm your e-mail address", $"<a href=\"{link}\">Confirm e-mail</a>", ct);

    public Task SendPasswordResetEmailAsync(SlimEmailContext context, string email, string link, CancellationToken ct) =>
        SendAsync(email, "Reset your password", $"<a href=\"{link}\">Reset password</a>", ct);

    public Task SendTwoFactorCodeAsync(SlimEmailContext context, string email, string code, CancellationToken ct) =>
        SendAsync(email, $"Your sign-in code: {code}", $"Your code is <b>{code}</b>.", ct);

    public Task SendEmailChangeConfirmationAsync(SlimEmailContext context, string newEmail, string link, CancellationToken ct) =>
        SendAsync(newEmail, "Confirm your new e-mail address", $"<a href=\"{link}\">Confirm address</a>", ct);

    private async Task SendAsync(string to, string subject, string html, CancellationToken ct)
    {
        var msg = MailHelper.CreateSingleEmail(From, new EmailAddress(to), subject, null, html);
        var response = await client.SendEmailAsync(msg, ct);
        if (!response.IsSuccessStatusCode)
            logger.LogError("SendGrid returned {Status} for mail to {To}.", response.StatusCode, to);
    }
}

/// <summary>Development: writes mails to the log. Equivalent to the built-in AddNullEmailSender().</summary>
public sealed class LoggingEmailSender(ILogger<LoggingEmailSender> logger) : ISlimEmailSender
{
    public Task SendVerificationEmailAsync(SlimEmailContext context, string email, string link, CancellationToken ct)
    { logger.LogInformation("Verify {Email}: {Link}", email, link); return Task.CompletedTask; }

    public Task SendPasswordResetEmailAsync(SlimEmailContext context, string email, string link, CancellationToken ct)
    { logger.LogInformation("Reset {Email}: {Link}", email, link); return Task.CompletedTask; }

    public Task SendTwoFactorCodeAsync(SlimEmailContext context, string email, string code, CancellationToken ct)
    { logger.LogInformation("2FA code for {Email}: {Code}", email, code); return Task.CompletedTask; }

    public Task SendEmailChangeConfirmationAsync(SlimEmailContext context, string newEmail, string link, CancellationToken ct)
    { logger.LogInformation("Confirm new address {Email}: {Link}", newEmail, link); return Task.CompletedTask; }
}
