using System.Text.Json;
using System.Text.RegularExpressions;
using OpenClaw.Shared;

namespace OpenClaw.Connection;

public interface IManagedGatewayEnrollment
{
    Task EnrollAsync(GatewayRecord record, string identityDirectory,
        IGatewayTransportAuthentication authentication, Action<ManagedConnectionState> state, CancellationToken ct);
}

/// <summary>
/// A staged operator-only socket. It is never published to UI consumers or used to
/// advertise this laptop. The manager creates the normal client after the final grant.
/// </summary>
internal sealed class ManagedGatewayEnrollment(NativeManagementApi api) : IManagedGatewayEnrollment
{
    private static readonly Regex RequestIdPattern = new("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$");
    private const int UpgradeTimeoutMilliseconds = 120_000;

    public async Task EnrollAsync(GatewayRecord record, string identityDirectory,
        IGatewayTransportAuthentication authentication, Action<ManagedConnectionState> state, CancellationToken ct)
    {
        var identity = new DeviceIdentity(identityDirectory, NullLogger.Instance);
        identity.Initialize();
        if (ManagedOperatorGrant.IsReady(identity.DeviceTokenScopes) &&
            !string.IsNullOrWhiteSpace(identity.DeviceToken)) return;
        state(ManagedConnectionState.Enrolling);
        var enrollment = await api.CreateEnrollmentAsync(record, identity, ct).ConfigureAwait(false);
        ValidateEnrollment(record, enrollment);
        var setup = SetupCodeDecoder.Decode(enrollment.SetupCode);
        if (!setup.Success || string.IsNullOrWhiteSpace(setup.Token) ||
            !Uri.TryCreate(setup.Url, UriKind.Absolute, out var setupUri) ||
            setupUri != new Uri(record.Url))
            throw new ManagedConnectionException(ManagedConnectionState.CompatibilityError);

        DeviceTokenReceivedEventArgs? issued = null;
        OpenClawGatewayClient CreateClient() => new(
            record.Url, setup.Token, NullLogger.Instance,
            tokenIsBootstrapToken: true, bootstrapPairAsNode: false,
            identityPath: identityDirectory, persistHandshakeDeviceTokens: false,
            ephemeralOperatorCredential: issued,
            requireExistingIdentity: true)
        {
            TransportAuthentication = authentication,
            RequestedOperatorScopes = ["operator.read"],
            SuppressInitialStateRequests = true,
            ReconnectAuthorizationAsync = _ => Task.FromResult(new ReconnectAuthorizationResult(false)),
        };

        using (var initial = CreateClient())
        {
            var outcome = await ConnectStagedAsync(initial, ct).ConfigureAwait(false);
            if (outcome is not null)
            {
                state(ManagedConnectionState.Approving);
                await api.ApproveAsync(record, enrollment, outcome, "initial", ct).ConfigureAwait(false);
            }
            else
            {
                issued = ReadIssuedCredential(initial);
            }
        }
        using var admitted = CreateClient();
        if (await ConnectStagedAsync(admitted, ct).ConfigureAwait(false) is not null)
            throw new ManagedConnectionException(ManagedConnectionState.AccessDenied);
        issued = ReadIssuedCredential(admitted);
        // An interrupted upgrade can resume using this same identity, never a new keypair.
        identity.StoreDeviceTokenWithScopes(issued.Token, issued.Scopes);
        state(ManagedConnectionState.Upgrading);
        try
        {
            var request = await admitted.SendWizardRequestAsync("device.scopes.requestUpgrade",
                new { scopes = ManagedOperatorGrant.Scopes }, UpgradeTimeoutMilliseconds).WaitAsync(ct).ConfigureAwait(false);
            var requestId = RequireRequestId(request);
            var waiter = admitted.SendWizardRequestAsync("device.scopes.waitUpgrade",
                new { requestId }, UpgradeTimeoutMilliseconds);
            await api.ApproveAsync(record, enrollment, requestId, "admin", ct).ConfigureAwait(false);
            var result = await waiter.WaitAsync(ct).ConfigureAwait(false);
            if (result.GetProperty("requestId").GetString() != requestId)
                throw new ManagedConnectionException(ManagedConnectionState.CompatibilityError);
            var status = result.GetProperty("status").GetString();
            if (status != "approved")
                throw new ManagedConnectionException(status == "expired"
                    ? ManagedConnectionState.EnrollmentExpired : ManagedConnectionState.AccessDenied);
            var token = result.GetProperty("deviceToken").GetString();
            var scopes = result.GetProperty("scopes").EnumerateArray().Select(s => s.GetString()!).ToArray();
            if (string.IsNullOrWhiteSpace(token) || !ManagedOperatorGrant.IsReady(scopes))
                throw new ManagedConnectionException(ManagedConnectionState.CompatibilityError);
            ct.ThrowIfCancellationRequested();
            identity.StoreDeviceTokenWithScopes(token, scopes);
        }
        catch (ManagedConnectionException) { throw; }
        catch (OperationCanceledException) { throw; }
        catch (Exception) { throw new ManagedConnectionException(ManagedConnectionState.CompatibilityError); }
    }

    private static DeviceTokenReceivedEventArgs ReadIssuedCredential(OpenClawGatewayClient client)
    {
        if (string.IsNullOrWhiteSpace(client.ConnectAuthToken) ||
            !client.GrantedOperatorScopes.Contains("operator.read"))
            throw new ManagedConnectionException(ManagedConnectionState.CompatibilityError);
        return new DeviceTokenReceivedEventArgs(client.ConnectAuthToken, client.GrantedOperatorScopes.ToArray(), "operator");
    }

    private static async Task<string?> ConnectStagedAsync(OpenClawGatewayClient client, CancellationToken ct)
    {
        var completed = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.HandshakeSucceeded += (_, _) => completed.TrySetResult(null);
        client.PairingRequired += (_, id) =>
        {
            if (id is not null && RequestIdPattern.IsMatch(id)) completed.TrySetResult(id);
            else completed.TrySetException(new ManagedConnectionException(ManagedConnectionState.CompatibilityError));
        };
        client.AuthenticationFailed += (_, _) => completed.TrySetException(
            new ManagedConnectionException(ManagedConnectionState.AccessDenied));
        client.StatusChanged += (_, status) =>
        {
            if (status == ConnectionStatus.Error) completed.TrySetException(
                new ManagedConnectionException(ManagedConnectionState.Unavailable));
        };
        using var registration = ct.Register(client.Dispose);
        await client.ConnectAsync().ConfigureAwait(false);
        return await completed.Task.WaitAsync(ct).ConfigureAwait(false);
    }

    private static string RequireRequestId(JsonElement request)
    {
        if (request.TryGetProperty("requestId", out var id) && id.GetString() is { } value &&
            RequestIdPattern.IsMatch(value)) return value;
        throw new ManagedConnectionException(ManagedConnectionState.CompatibilityError);
    }

    private static void ValidateEnrollment(GatewayRecord record, NativeEnrollment enrollment)
    {
        if (enrollment.ExpiresAt <= DateTimeOffset.UtcNow)
            throw new ManagedConnectionException(ManagedConnectionState.EnrollmentExpired);
        if (enrollment.SchemaVersion != 1 || !Guid.TryParse(enrollment.EnrollmentId, out _) ||
            enrollment.ClawId != record.ManagedRemote!.ClawId ||
            enrollment.AssignmentVersion != record.ManagedRemote.AssignmentVersion ||
            enrollment.InitialScopes is not ["operator.read"] ||
            !ManagedOperatorGrant.IsReady(enrollment.OperatorScopes) ||
            enrollment.OperatorScopes.Length != ManagedOperatorGrant.Scopes.Count)
            throw new ManagedConnectionException(ManagedConnectionState.CompatibilityError);
    }
}
