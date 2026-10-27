using OpenClaw.Shared;
using System.Diagnostics.CodeAnalysis;

namespace OpenClaw.Connection;

public static class ManagedEndpointPolicy
{
    public static bool IsIdentityConfigured(ManagedRemoteOptions options) =>
        options.Enabled &&
        Guid.TryParse(options.ClientId, out _) &&
        Uri.TryCreate(options.Authority, UriKind.Absolute, out var authority) &&
        authority.Scheme == "https" && string.IsNullOrEmpty(authority.UserInfo) &&
        string.IsNullOrEmpty(authority.Query) && string.IsNullOrEmpty(authority.Fragment) &&
        authority.AbsolutePath.Trim('/') is not ("" or "common" or "consumers") &&
        !string.IsNullOrWhiteSpace(options.ApiScope) && !options.ApiScope.Any(char.IsWhiteSpace);

    public static void ValidateIdentityConfiguration(ManagedRemoteOptions options)
    {
        if (!IsIdentityConfigured(options))
            throw new ManagedConnectionException(ManagedConnectionState.SetupRequired);
    }

    public static bool TryGetServiceOrigin(
        ManagedRemoteOptions options, [NotNullWhen(true)] out Uri? service)
    {
        if (Uri.TryCreate(options.ServiceBaseUrl, UriKind.Absolute, out service) &&
            service.Scheme == "https" && string.IsNullOrEmpty(service.UserInfo) &&
            string.IsNullOrEmpty(service.Query) && string.IsNullOrEmpty(service.Fragment) &&
            service.AbsolutePath == "/")
            return true;
        service = null;
        return false;
    }

    public static Uri ValidateConfiguration(ManagedRemoteOptions options)
    {
        ValidateIdentityConfiguration(options);
        if (!TryGetServiceOrigin(options, out var service))
            throw new ManagedConnectionException(ManagedConnectionState.SetupRequired);
        return service;
    }

    public static Uri RequireServiceRoute(Uri service, string value, string prefix, bool webSocket = false)
    {
        if (!Uri.TryCreate(service, value, out var target) ||
            target.Scheme != (webSocket ? "wss" : "https") ||
            !string.Equals(target.Host, service.Host, StringComparison.OrdinalIgnoreCase) ||
            target.Port != service.Port || !string.IsNullOrEmpty(target.UserInfo) ||
            !string.IsNullOrEmpty(target.Fragment) ||
            !(target.AbsolutePath == prefix || target.AbsolutePath.StartsWith(prefix + "/", StringComparison.Ordinal)) ||
            HasUnsafePath(value.Split('?', 2)[0]))
            throw new ManagedConnectionException(ManagedConnectionState.CompatibilityError);
        return target;
    }

    internal static bool HasUnsafePath(string path)
    {
        for (var i = 0; i < 3; i++)
        {
            if (path.Contains('\\') || path.Any(char.IsControl) ||
                path.Split('/').Any(s => s is "." or ".."))
                return true;
            var decoded = Uri.UnescapeDataString(path);
            if (decoded == path) return false;
            path = decoded;
        }
        return true;
    }
}
