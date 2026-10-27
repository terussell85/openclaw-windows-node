namespace OpenClaw.Shared;

/// <summary>Non-secret developer configuration for a public desktop client.</summary>
public sealed record ManagedRemoteOptions
{
    public bool Enabled { get; init; }
    public string Authority { get; init; } = "";
    public string ClientId { get; init; } = "";
    public string ApiScope { get; init; } = "";
    public string ServiceBaseUrl { get; init; } = "";
}
