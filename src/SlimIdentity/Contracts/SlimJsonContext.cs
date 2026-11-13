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
[JsonSerializable(typeof(SlimRegisterPasswordRequest))]
[JsonSerializable(typeof(SlimEmailRequest))]
[JsonSerializable(typeof(SlimChangePasswordRequest))]
[JsonSerializable(typeof(SlimTwoFactorEnableRequest))]
[JsonSerializable(typeof(SlimPasswordConfirmationRequest))]
[JsonSerializable(typeof(SlimExternalExchangeRequest))]
// responses
[JsonSerializable(typeof(SlimStatusResponse))]
[JsonSerializable(typeof(SlimAuthResponse))]
[JsonSerializable(typeof(SlimActionRequiredResponse))]
[JsonSerializable(typeof(SlimFlowRequest))]
[JsonSerializable(typeof(SlimProblemResponse))]
[JsonSerializable(typeof(SlimMeResponse))]
[JsonSerializable(typeof(SlimTwoFactorStatusResponse))]
[JsonSerializable(typeof(SlimTwoFactorSetupResponse))]
[JsonSerializable(typeof(SlimRecoveryCodesResponse))]
[JsonSerializable(typeof(SlimPasswordPolicyResponse))]
[JsonSerializable(typeof(SlimInvitation))]
[JsonSerializable(typeof(SlimPasswordReset))]
[JsonSerializable(typeof(SlimSignInMethodsResponse))]
[JsonSerializable(typeof(SlimRemoveExternalLoginRequest))]
[JsonSerializable(typeof(SlimExternalLinkRequest))]
[JsonSerializable(typeof(SlimExternalLinkPayload))]
[JsonSerializable(typeof(SlimPasswordChangeLoginRequest))]
[JsonSerializable(typeof(SlimVerifyEmailLoginRequest))]
[JsonSerializable(typeof(List<SlimSessionDto>))]
// route / query parameter and framework types (needed by the OpenAPI schema generator under Native AOT)
[JsonSerializable(typeof(bool?))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(Microsoft.AspNetCore.Mvc.ProblemDetails))]
[JsonSerializable(typeof(HttpValidationProblemDetails))]
// stateless token payloads and the actor claim
[JsonSerializable(typeof(SlimLinkPayload))]
[JsonSerializable(typeof(SlimFlowPayload))]
[JsonSerializable(typeof(SlimTwoFactorSetupPayload))]
[JsonSerializable(typeof(SlimExchangePayload))]
[JsonSerializable(typeof(SlimRefreshPayload))]
[JsonSerializable(typeof(SlimEmailChangePayload))]
[JsonSerializable(typeof(SlimRememberDevicePayload))]
[JsonSerializable(typeof(SlimChangeEmailRequest))]
[JsonSerializable(typeof(SlimConfirmEmailChangeRequest))]
[JsonSerializable(typeof(Dictionary<string, string>))]
internal sealed partial class SlimJsonContext : JsonSerializerContext;
