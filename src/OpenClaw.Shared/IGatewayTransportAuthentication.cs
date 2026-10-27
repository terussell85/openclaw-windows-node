namespace OpenClaw.Shared;

/// <summary>
/// Separate admission authentication for a hosted Gateway. Gateway protocol credentials
/// still belong to the signed connect envelope, not this transport header provider.
/// </summary>
public interface IGatewayTransportAuthentication
{
    Uri HttpBaseUri { get; }
    Task<IReadOnlyDictionary<string, string>> GetHeadersAsync(
        Uri target, CancellationToken cancellationToken);
}
