using System.Text.Json.Serialization;
using SlimIdentity.Services;

namespace SlimIdentity.Contracts;

/// <summary>
/// System.Text.Json source generation for every type SlimIdentity serializes (requests, responses, token payloads),
/// so the library works with trimming and Native AOT. Registered in front of the host's <c>HttpJsonOptions</c>.
/// </summary>
[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
// requests
[JsonSerializable(typeof(SlimLoginRequest))]
[JsonSerializable(typeof(SlimTwoFactorLoginRequest))]
[JsonSerializable(typeof(SlimRefreshRequest))]
[JsonSerializable(typeof(SlimLogoutRequest))]
[JsonSerializable(typeof(SlimRegisterRequest))]
[JsonSerializable(typeof(SlimVerifyEmailRequest))]
[JsonSerializable(typeof(SlimEmailRequest))]
[JsonSerializable(typeof(SlimResetPasswordRequest))]
[JsonSerializable(typeof(SlimChangePasswordRequest))]
[JsonSerializable(typeof(SlimTwoFactorEnableRequest))]
[JsonSerializable(typeof(SlimPasswordConfirmationRequest))]
[JsonSerializable(typeof(SlimExternalExchangeRequest))]
[JsonSerializable(typeof(SlimInvitationInfoRequest))]
[JsonSerializable(typeof(SlimAcceptInvitationRequest))]
// responses
[JsonSerializable(typeof(SlimStatusResponse))]
[JsonSerializable(typeof(SlimAuthResponse))]
[JsonSerializable(typeof(SlimLoginChallengeResponse))]
[JsonSerializable(typeof(SlimLockedResponse))]
[JsonSerializable(typeof(SlimMeResponse))]
[JsonSerializable(typeof(SlimTwoFactorStatusResponse))]
[JsonSerializable(typeof(SlimTwoFactorSetupResponse))]
[JsonSerializable(typeof(SlimRecoveryCodesResponse))]
[JsonSerializable(typeof(SlimInvitationInfoResponse))]
[JsonSerializable(typeof(SlimPasswordPolicyResponse))]
[JsonSerializable(typeof(SlimInvitation))]
[JsonSerializable(typeof(List<SlimSessionDto>))]
// route / query parameter and framework types (needed by the OpenAPI schema generator under Native AOT)
[JsonSerializable(typeof(bool?))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(Microsoft.AspNetCore.Mvc.ProblemDetails))]
[JsonSerializable(typeof(HttpValidationProblemDetails))]
// stateless token payloads and the actor claim
[JsonSerializable(typeof(SlimEmailTokenPayload))]
[JsonSerializable(typeof(SlimResetTokenPayload))]
[JsonSerializable(typeof(SlimPreAuthPayload))]
[JsonSerializable(typeof(SlimTwoFactorSetupPayload))]
[JsonSerializable(typeof(SlimExchangePayload))]
[JsonSerializable(typeof(SlimRefreshPayload))]
[JsonSerializable(typeof(SlimInvitationPayload))]
[JsonSerializable(typeof(SlimEmailChangePayload))]
[JsonSerializable(typeof(SlimChangeEmailRequest))]
[JsonSerializable(typeof(SlimConfirmEmailChangeRequest))]
[JsonSerializable(typeof(Dictionary<string, string>))]
internal sealed partial class SlimJsonContext : JsonSerializerContext;
