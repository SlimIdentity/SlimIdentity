using System.Text.Json.Serialization;
using SlimIdentity.Passkeys;

namespace SlimIdentity.Contracts;

// ---------------------------------------------------------------- passkeys (WebAuthn JSON, base64url fields)

/// <summary>Body of <c>POST /auth/passkeys/register/options</c>.</summary>
/// <param name="Password">The current password – required for accounts that have one (a stolen session must not add a way in).</param>
public sealed record SlimPasskeyRegistrationOptionsRequest(string? Password = null);

/// <summary>WebAuthn relying party.</summary>
public sealed record SlimPasskeyRelyingParty(string Id, string Name);
/// <summary>WebAuthn user entity (<c>Id</c> is base64url, no personal data).</summary>
public sealed record SlimPasskeyUser(string Id, string Name, string DisplayName);
/// <summary>A supported public key algorithm (COSE).</summary>
public sealed record SlimPasskeyCredentialParameter(string Type, int Alg);
/// <summary>A credential reference (base64url id).</summary>
public sealed record SlimPasskeyCredentialDescriptor(string Type, string Id);
/// <summary>Authenticator requirements: discoverable credential, user verification.</summary>
public sealed record SlimPasskeyAuthenticatorSelection(string ResidentKey, bool RequireResidentKey, string UserVerification);

/// <summary><c>PublicKeyCredentialCreationOptions</c> in JSON form (decode the base64url fields for <c>navigator.credentials.create</c>).</summary>
public sealed record SlimPasskeyCreationOptions(
    SlimPasskeyRelyingParty Rp, SlimPasskeyUser User, string Challenge, IReadOnlyList<SlimPasskeyCredentialParameter> PubKeyCredParams,
    int Timeout, string Attestation, SlimPasskeyAuthenticatorSelection AuthenticatorSelection, IReadOnlyList<SlimPasskeyCredentialDescriptor> ExcludeCredentials);

/// <summary><c>PublicKeyCredentialRequestOptions</c> in JSON form (for <c>navigator.credentials.get</c>).</summary>
public sealed record SlimPasskeyRequestOptions(string Challenge, string RpId, int Timeout, string UserVerification, IReadOnlyList<SlimPasskeyCredentialDescriptor> AllowCredentials);

/// <summary>Answer of the options endpoints: the options for the browser and a signed state to send back.</summary>
public sealed record SlimPasskeyCreationOptionsResponse(SlimPasskeyCreationOptions Options, string State);
/// <summary>Answer of <c>/passkeys/login/options</c>.</summary>
public sealed record SlimPasskeyRequestOptionsResponse(SlimPasskeyRequestOptions Options, string State);

/// <summary>The authenticator's response, base64url-encoded (WebAuthn <c>toJSON()</c> form).</summary>
public sealed record SlimPasskeyAuthenticatorResponse(
    [property: System.Text.Json.Serialization.JsonPropertyName("clientDataJSON")] string ClientDataJson,
    string? AttestationObject = null, string? AuthenticatorData = null, string? Signature = null, string? UserHandle = null,
    IReadOnlyList<string>? Transports = null);

/// <summary>A <c>PublicKeyCredential</c> in JSON form.</summary>
public sealed record SlimPasskeyCredential(string Id, string RawId, string Type, SlimPasskeyAuthenticatorResponse Response);

/// <summary>Body of <c>POST /auth/passkeys/register</c>.</summary>
/// <param name="State">The state of the options call.</param>
/// <param name="Credential">The result of <c>navigator.credentials.create</c>.</param>
/// <param name="Name">Display name (at most 64 characters).</param>
public sealed record SlimPasskeyRegisterRequest(string State, SlimPasskeyCredential Credential, string? Name = null);

/// <summary>Body of <c>POST /auth/passkeys/login</c>.</summary>
public sealed record SlimPasskeyLoginRequest(string State, SlimPasskeyCredential Credential, bool RememberMe = false);

/// <summary>Body of <c>POST /auth/sign-in-methods/passkeys/rename</c>.</summary>
public sealed record SlimPasskeyRenameRequest(string Id, string Name);

/// <summary>Body of <c>POST /auth/sign-in-methods/passkeys/remove</c>.</summary>
public sealed record SlimRemovePasskeyRequest(string Id, string? Password = null);

/// <summary>System.Text.Json source generation for the passkey endpoints and their signed states (Native AOT).</summary>
[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(SlimPasskeyRegistrationOptionsRequest))]
[JsonSerializable(typeof(SlimPasskeyCreationOptionsResponse))]
[JsonSerializable(typeof(SlimPasskeyRequestOptionsResponse))]
[JsonSerializable(typeof(SlimPasskeyRegisterRequest))]
[JsonSerializable(typeof(SlimPasskeyLoginRequest))]
[JsonSerializable(typeof(SlimPasskeyRenameRequest))]
[JsonSerializable(typeof(SlimRemovePasskeyRequest))]
[JsonSerializable(typeof(SlimPasskeyInfo))]
[JsonSerializable(typeof(SlimPasskeyRegistrationPayload))]
[JsonSerializable(typeof(SlimPasskeyLoginPayload))]
internal sealed partial class SlimPasskeyJsonContext : JsonSerializerContext;
