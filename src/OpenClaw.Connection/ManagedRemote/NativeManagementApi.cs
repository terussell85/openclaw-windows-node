using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using OpenClaw.Shared;

namespace OpenClaw.Connection;

/// <summary>Only the documented owner-bound native and existing activation REST contracts.</summary>
internal sealed class NativeManagementApi(HttpClient http, IManagedIdentity identity)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private const int MaximumResponseBytes = 64 * 1024;

    public Task<NativeConnection> DiscoverAsync(ManagedRemoteOptions options, CancellationToken ct) =>
        SendAsync<NativeConnection>(options, HttpMethod.Get, "/api/native/connection", null, null, ct);

    public async Task StartAsync(ManagedRemoteOptions options, TimeSpan pollInterval, CancellationToken ct)
    {
        var activation = await SendAsync<NativeActivation>(
            options, HttpMethod.Post, "/api/control/activations", null, null, ct).ConfigureAwait(false);
        if (activation.Status == "Ready") return;
        if (activation.Status != "Starting")
            throw new ManagedConnectionException(ManagedConnectionState.Offline);
        var resource = ManagedEndpointPolicy.RequireServiceRoute(
            ManagedEndpointPolicy.ValidateConfiguration(options),
            activation.ResourceUrl ?? "", "/api/control/activates");
        while (activation.Status == "Starting")
        {
            await Task.Delay(pollInterval, ct).ConfigureAwait(false);
            activation = await SendAsync<NativeActivation>(
                options, HttpMethod.Get, resource.AbsoluteUri, null, null, ct).ConfigureAwait(false);
        }
        if (activation.Status != "Ready")
            throw new ManagedConnectionException(ManagedConnectionState.Offline);
    }

    public Task<NativeEnrollment> CreateEnrollmentAsync(GatewayRecord record, DeviceIdentity device, CancellationToken ct) =>
        SendAsync<NativeEnrollment>(record.ManagedRemote!.Options, HttpMethod.Post,
            record.ManagedRemote.EnrollmentUrl!,
            new { schemaVersion = 1, deviceId = device.DeviceId, publicKey = device.PublicKeyBase64Url },
            record.ManagedRemote, ct);

    public async Task ApproveAsync(GatewayRecord record, NativeEnrollment enrollment, string requestId, string stage, CancellationToken ct)
    {
        if (enrollment.ExpiresAt <= DateTimeOffset.UtcNow)
            throw new ManagedConnectionException(ManagedConnectionState.EnrollmentExpired);
        var approval = await SendAsync<NativeApproval>(
            record.ManagedRemote!.Options, HttpMethod.Post,
            record.ManagedRemote.EnrollmentUrl!.TrimEnd('/') + "/" + Uri.EscapeDataString(enrollment.EnrollmentId) + "/approve",
            new { schemaVersion = 1, requestId, stage }, record.ManagedRemote, ct).ConfigureAwait(false);
        if (approval.SchemaVersion != 1 || !approval.Approved ||
            approval.EnrollmentId != enrollment.EnrollmentId || approval.Stage != stage)
            throw new ManagedConnectionException(ManagedConnectionState.CompatibilityError);
    }

    private async Task<T> SendAsync<T>(ManagedRemoteOptions options, HttpMethod method, string route,
        object? body, ManagedRemoteProfile? binding, CancellationToken ct)
    {
        var service = ManagedEndpointPolicy.ValidateConfiguration(options);
        var prefix = binding is null
            ? (route.Contains("/api/control/", StringComparison.Ordinal) ? "/api/control" : "/api/native/connection")
            : "/api/native/enrollments";
        var target = ManagedEndpointPolicy.RequireServiceRoute(service, route, prefix);
        if (!string.IsNullOrEmpty(target.Query))
            throw new ManagedConnectionException(ManagedConnectionState.CompatibilityError);
        var token = await identity.AcquireAsync(options, false, ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(token.Value) || token.ExpiresAt <= DateTimeOffset.UtcNow)
            throw new ManagedConnectionException(ManagedConnectionState.SignInRequired);
        using var request = new HttpRequestMessage(method, target);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Value);
        if (binding is not null)
        {
            request.Headers.Add("X-Claw-Id", binding.ClawId);
            request.Headers.Add("X-Claw-Assignment-Version", binding.AssignmentVersion);
        }
        if (body is not null) request.Content = JsonContent.Create(body, options: JsonOptions);
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            var state = response.StatusCode switch
            {
                HttpStatusCode.Unauthorized => ManagedConnectionState.SignInRequired,
                HttpStatusCode.Forbidden => ManagedConnectionState.AccessDenied,
                HttpStatusCode.Conflict => ManagedConnectionState.StaleAssignment,
                HttpStatusCode.Gone => ManagedConnectionState.EnrollmentExpired,
                HttpStatusCode.NotFound => ManagedConnectionState.NotAssigned,
                HttpStatusCode.ServiceUnavailable => ManagedConnectionState.Unavailable,
                _ => ManagedConnectionState.Unavailable,
            };
            try
            {
                await response.Content.LoadIntoBufferAsync(MaximumResponseBytes, ct).ConfigureAwait(false);
                using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
                if (problem.RootElement.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String)
                    state = code.GetString() switch
                    {
                        "setupRequired" => ManagedConnectionState.SetupRequired,
                        "staleAssignment" or "activationRequired" => ManagedConnectionState.StaleAssignment,
                        "enrollmentExpired" => ManagedConnectionState.EnrollmentExpired,
                        "gatewayIncompatible" or "invalidGatewayResponse" => ManagedConnectionState.CompatibilityError,
                        "invalidHumanIdentity" or "invalidTokenLifetime" or "tokenExpired" => ManagedConnectionState.SignInRequired,
                        _ => state,
                    };
            }
            catch (JsonException) { /* Auth challenges may have an empty or non-JSON body. */ }
            throw new ManagedConnectionException(state);
        }
        try
        {
            await response.Content.LoadIntoBufferAsync(MaximumResponseBytes, ct).ConfigureAwait(false);
            return await response.Content.ReadFromJsonAsync<T>(JsonOptions, ct).ConfigureAwait(false)
                ?? throw new ManagedConnectionException(ManagedConnectionState.CompatibilityError);
        }
        catch (JsonException) { throw new ManagedConnectionException(ManagedConnectionState.CompatibilityError); }
    }
}
