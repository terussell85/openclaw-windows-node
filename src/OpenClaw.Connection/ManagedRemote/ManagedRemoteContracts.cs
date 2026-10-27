using OpenClaw.Shared;

namespace OpenClaw.Connection;

public sealed record ManagedRemoteProfile(
    ManagedRemoteOptions Options,
    string? ClawId = null,
    string? AssignmentVersion = null,
    string? HttpBaseUrl = null,
    string? EnrollmentUrl = null,
    bool EnrollmentAttempted = false);

public enum ManagedConnectionState
{
    Disabled, SetupRequired, SignInRequired, SigningIn, Discovering,
    NotAssigned, Starting, Offline, Enrolling, Approving, Upgrading,
    Connecting, Ready, StaleAssignment, EnrollmentExpired, CompatibilityError,
    AccessDenied, Unavailable, SignedOut, ServiceSetupRequired,
}

public sealed class ManagedConnectionException(ManagedConnectionState state)
    : Exception($"Managed connection: {state}.")
{
    public ManagedConnectionState State { get; } = state;
}

public sealed record ManagedAccessToken(string Value, DateTimeOffset ExpiresAt)
{
    public override string ToString() => nameof(ManagedAccessToken);
}

public interface IManagedIdentity
{
    Task<ManagedAccessToken> AcquireAsync(ManagedRemoteOptions options, bool interactive, CancellationToken ct);
    Task SignOutAsync(ManagedRemoteOptions options, CancellationToken ct);
}

public interface IManagedGatewayProvider
{
    Task<GatewayRecord> PrepareAsync(GatewayRecord record, CancellationToken ct);
    IGatewayTransportAuthentication CreateAuthentication(GatewayRecord record);
}

internal sealed record NativeConnection(
    int SchemaVersion, string State, string? ClawId, string? AssignmentVersion,
    string? ActivationResourceUrl, NativeGatewayRoutes? Gateway);
internal sealed record NativeGatewayRoutes(string WebSocketUrl, string HttpBaseUrl, string EnrollmentUrl);
internal sealed record NativeActivation(string Status, string? ResourceUrl, string? ErrorDetails);
internal sealed record NativeEnrollment(
    int SchemaVersion, string EnrollmentId, string ClawId, string AssignmentVersion,
    string SetupCode, DateTimeOffset ExpiresAt, string[] InitialScopes, string[] OperatorScopes)
{
    public override string ToString() => nameof(NativeEnrollment);
}
internal sealed record NativeApproval(int SchemaVersion, string EnrollmentId, string Stage, bool Approved);

public static class ManagedOperatorGrant
{
    public static IReadOnlyList<string> Scopes { get; } = Array.AsReadOnly(new[]
    {
        "operator.admin", "operator.pairing", "operator.read", "operator.write",
        "operator.approvals", "operator.questions", "operator.talk.secrets",
    });

    public static bool IsReady(IEnumerable<string>? scopes) =>
        scopes is not null && Scopes.All(s => scopes.Contains(s, StringComparer.Ordinal));
}
