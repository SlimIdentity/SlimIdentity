namespace SlimIdentity;

/// <summary>
/// The machine-readable error codes of SlimIdentity: <c>code</c> of the problem-details error responses
/// (<see cref="Contracts.SlimProblemResponse"/>), <c>slim_error</c> of the external-login redirect, <see cref="SlimAuthResult.Error"/> and the
/// <c>Reason</c> of <see cref="SlimEventTypes.SignInFailed"/>. A sign-in guard's veto carries its own code.
/// </summary>
public static class SlimErrorCodes
{
    // ---------------------------------------------------------------- requests

    /// <summary>A required field is missing or malformed (400).</summary>
    public const string InvalidRequest = "invalid_request";
    /// <summary>Field errors in <c>errors</c> (400).</summary>
    public const string ValidationFailed = "validation_failed";
    /// <summary>A signed token or link is invalid, expired or already used.</summary>
    public const string InvalidToken = "invalid_token";
    /// <summary>The anti-forgery header is missing or the <c>Origin</c> is not allowed (403).</summary>
    public const string CsrfValidationFailed = "csrf_validation_failed";
    /// <summary>Cookie mode was requested, but cookie authentication is disabled (400).</summary>
    public const string CookieAuthDisabled = "cookie_auth_disabled";
    /// <summary>Bearer mode was requested, but no JWT secret is configured (400).</summary>
    public const string JwtAuthDisabled = "jwt_auth_disabled";
    /// <summary>The account changed at the same time; nothing was saved (409).</summary>
    public const string ConcurrentChange = "concurrent_change";
    /// <summary>The request needs a signed-in user or a valid API key (401).</summary>
    public const string Unauthenticated = "unauthenticated";
    /// <summary>The signed-in principal lacks the permission (403).</summary>
    public const string Forbidden = "forbidden";
    /// <summary>The rate limit of the endpoint is exhausted (429 with <c>Retry-After</c>).</summary>
    public const string RateLimited = "rate_limited";
    /// <summary>A dependency is temporarily unavailable; retry later (503).</summary>
    public const string ServiceUnavailable = "service_unavailable";

    // ---------------------------------------------------------------- sign-in

    /// <summary>Unknown address, wrong password – or, without <c>RevealAccountState</c>, an inactive or locked account (401).</summary>
    public const string InvalidCredentials = "invalid_credentials";
    /// <summary>Event reason: no account with this address.</summary>
    public const string UnknownUser = "unknown_user";
    /// <summary>The password is wrong (event reason; 400 when confirming a password).</summary>
    public const string InvalidPassword = "invalid_password";
    /// <summary>Event reason: a parallel attempt could not be reserved, the password was not checked.</summary>
    public const string AttemptNotReserved = "attempt_not_reserved";
    /// <summary>The account is inactive.</summary>
    public const string AccountDisabled = "account_disabled";
    /// <summary>The account is locked (423 with <c>lockoutEndUtc</c> and <c>Retry-After</c>).</summary>
    public const string LockedOut = "locked_out";
    /// <summary>
    /// The e-mail address has not been confirmed (403) – for actions that need a proven mailbox; a sign-in names it as
    /// step <c>verify_email</c> instead.
    /// </summary>
    public const string EmailNotConfirmed = "email_not_confirmed";
    /// <summary>The code of step <c>verify_email</c> is wrong (401).</summary>
    public const string InvalidVerificationCode = "invalid_verification_code";
    /// <summary>
    /// The attempts for a code are used up (429): per flow and per address and day. A registration can still be
    /// completed with the link of its mail.
    /// </summary>
    public const string TooManyAttempts = "too_many_attempts";
    /// <summary>An administrator set the password; the user chooses an own one first (action <c>change_password</c>).</summary>
    public const string PasswordChangeRequired = "password_change_required";
    /// <summary>
    /// Steps follow before a session is issued: <see cref="SlimAuthResult.ActionRequired"/>, answered with 200
    /// <c>status: "action_required"</c>, <c>actions</c> and <c>flowToken</c>.
    /// </summary>
    public const string ActionRequired = "action_required";
    /// <summary>Metrics and event reason: the second factor follows (action <c>second_factor</c>).</summary>
    public const string RequiresTwoFactor = "requires_two_factor";
    /// <summary>Two-factor authentication is enabled for the account, but no <see cref="ISlimTwoFactorStore"/> is registered.</summary>
    public const string TwoFactorUnavailable = "two_factor_unavailable";
    /// <summary>The code of the second factor is wrong (401).</summary>
    public const string InvalidTwoFactorCode = "invalid_two_factor_code";
    /// <summary>The passkey assertion could not be verified (401).</summary>
    public const string InvalidPasskey = "invalid_passkey";
    /// <summary>The session reached its maximum lifetime or could not be renewed (401).</summary>
    public const string SessionExpired = "session_expired";
    /// <summary>A sensitive change needs the password or a recent sign-in (403).</summary>
    public const string ReauthenticationRequired = "reauthentication_required";

    // ---------------------------------------------------------------- impersonation

    /// <summary>The action is not allowed during an impersonation session (403).</summary>
    public const string NotAllowedWhileImpersonating = "not_allowed_while_impersonating";
    /// <summary>The caller already impersonates someone.</summary>
    public const string AlreadyImpersonating = "already_impersonating";
    /// <summary>An administrator cannot impersonate themselves.</summary>
    public const string CannotImpersonateSelf = "cannot_impersonate_self";
    /// <summary>The impersonator is no longer active or their security state changed.</summary>
    public const string ImpersonatorInvalid = "impersonator_invalid";
    /// <summary>The current session is no impersonation.</summary>
    public const string NotImpersonating = "not_impersonating";

    // ---------------------------------------------------------------- account

    /// <summary>The new password equals the one set by the administrator (400).</summary>
    public const string PasswordUnchanged = "password_unchanged";
    /// <summary>Passwords are validated externally; SlimIdentity cannot set one (400).</summary>
    public const string PasswordManagedExternally = "password_managed_externally";
    /// <summary>The account has no password to change (409).</summary>
    public const string PasswordNotSet = "password_not_set";
    /// <summary>The account needs a password first (403).</summary>
    public const string PasswordRequired = "password_required";
    /// <summary>The new address equals the current one (400).</summary>
    public const string EmailUnchanged = "email_unchanged";
    /// <summary>The address is used by another account (400).</summary>
    public const string EmailTaken = "email_taken";
    /// <summary>The account signs in with an external provider and has no local password (409).</summary>
    public const string ExternalSignInOnly = "external_sign_in_only";
    /// <summary>The session does not exist (404).</summary>
    public const string SessionNotFound = "session_not_found";
    /// <summary>Two-factor authentication is not enabled (400).</summary>
    public const string TwoFactorDisabled = "two_factor_disabled";
    /// <summary>Removing it would leave the account without a way to sign in (409).</summary>
    public const string LastSignInMethod = "last_sign_in_method";

    // ---------------------------------------------------------------- passkeys

    /// <summary>The passkey is already registered (409).</summary>
    public const string PasskeyExists = "passkey_exists";
    /// <summary>The passkey does not exist (404).</summary>
    public const string PasskeyNotFound = "passkey_not_found";
    /// <summary>The passkey name is empty or too long (400).</summary>
    public const string InvalidName = "invalid_name";

    // ---------------------------------------------------------------- external login

    /// <summary>The provider is not configured (404).</summary>
    public const string UnknownProvider = "unknown_provider";
    /// <summary>The return URL is not allowed (400).</summary>
    public const string InvalidReturnUrl = "invalid_return_url";
    /// <summary>Bearer clients must send a PKCE <c>code_challenge</c>.</summary>
    public const string CodeChallengeRequired = "code_challenge_required";
    /// <summary>The <c>code_challenge</c> is no S256 challenge (400).</summary>
    public const string InvalidCodeChallenge = "invalid_code_challenge";
    /// <summary>The provider's authentication failed.</summary>
    public const string ExternalLoginFailed = "external_login_failed";
    /// <summary>The user cancelled at the provider.</summary>
    public const string AccessDenied = "access_denied";
    /// <summary>The callback belongs to another provider than the one the flow started with.</summary>
    public const string ProviderMismatch = "provider_mismatch";
    /// <summary>The provider sent no subject identifier.</summary>
    public const string MissingProviderKey = "missing_provider_key";
    /// <summary>The provider sent no usable e-mail address.</summary>
    public const string EmailRequired = "email_required";
    /// <summary>The provider did not verify the address; no account is created for it.</summary>
    public const string EmailNotVerified = "email_not_verified";
    /// <summary>An account with this address exists and is not linked automatically (sign in and link the provider).</summary>
    public const string AccountConflict = "account_conflict";
    /// <summary>New accounts cannot be created through the provider.</summary>
    public const string RegistrationDisabled = "registration_disabled";
    /// <summary>The external account is linked to another account (409).</summary>
    public const string ExternalLoginTaken = "external_login_taken";
    /// <summary>The external login is not linked to the account (404).</summary>
    public const string ExternalLoginNotFound = "external_login_not_found";
    /// <summary>No session could be issued after the provider's sign-in.</summary>
    public const string SignInFailed = "sign_in_failed";
}
