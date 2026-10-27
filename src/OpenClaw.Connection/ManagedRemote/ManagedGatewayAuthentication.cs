using OpenClaw.Shared;

namespace OpenClaw.Connection;

internal sealed class ManagedGatewayAuthentication(
    GatewayRecord record,
    IManagedIdentity identity,
    Func<CancellationToken, Task> validateBinding,
    CancellationToken lifetime) : IGatewayTransportAuthentication
{
    private readonly ManagedRemoteProfile _profile = record.ManagedRemote
        ?? throw new ArgumentException("A managed profile is required.", nameof(record));

    public Uri HttpBaseUri => ManagedEndpointPolicy.RequireServiceRoute(
        ManagedEndpointPolicy.ValidateConfiguration(_profile.Options),
        _profile.HttpBaseUrl!, "/api/native/gateway");

    public async Task<IReadOnlyDictionary<string, string>> GetHeadersAsync(Uri target, CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime);
        var service = ManagedEndpointPolicy.ValidateConfiguration(_profile.Options);
        ManagedEndpointPolicy.RequireServiceRoute(
            service, target.AbsoluteUri, "/api/native/gateway", target.Scheme == "wss");
        await validateBinding(linked.Token).ConfigureAwait(false);
        var token = await identity.AcquireAsync(_profile.Options, false, linked.Token).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(token.Value) || token.ExpiresAt <= DateTimeOffset.UtcNow)
            throw new ManagedConnectionException(ManagedConnectionState.SignInRequired);
        linked.Token.ThrowIfCancellationRequested();
        return new Dictionary<string, string>
        {
            ["Authorization"] = "Bearer " + token.Value,
            ["X-Claw-Id"] = _profile.ClawId!,
            ["X-Claw-Assignment-Version"] = _profile.AssignmentVersion!,
        };
    }
}
