using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Identity.Client;
using OpenClaw.Shared;
using OpenClaw.Shared.Mcp;

namespace OpenClaw.Connection;

/// <summary>DPAPI-only MSAL persistence. A concurrent writer fails closed instead of losing its cache.</summary>
internal sealed class ProtectedMsalCache(string path)
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("OpenClaw.ManagedRemote.Msal.v1");
    private const int MaximumCacheBytes = 16 * 1024 * 1024;
    private byte[]? _baseline;
    internal string? SelectedHomeAccountId { get; private set; }
    private sealed record CacheEnvelope(int OpenClawCacheVersion, string? SelectedHomeAccountId, byte[] MsalCache);

    public void Attach(ITokenCache cache)
    {
        cache.SetBeforeAccess(args =>
        {
            using var lease = PersistenceFileLease.Acquire(path);
            _baseline = ReadCiphertext();
            var plain = _baseline is null ? null : Unprotect(_baseline);
            SelectedHomeAccountId = null;
            byte[]? cacheBytes = null;
            try
            {
                cacheBytes = ReadCacheEnvelope(plain);
                args.TokenCache.DeserializeMsalV3(cacheBytes, shouldClearExistingCache: true);
            }
            finally
            {
                if (plain is not null) CryptographicOperations.ZeroMemory(plain);
                if (cacheBytes is not null && !ReferenceEquals(cacheBytes, plain))
                    CryptographicOperations.ZeroMemory(cacheBytes);
            }
        });
        cache.SetAfterAccess(args =>
        {
            if (!args.HasStateChanged) return;
            var plain = args.TokenCache.SerializeMsalV3();
            try { WriteCacheEnvelope(plain, SelectedHomeAccountId); }
            finally { CryptographicOperations.ZeroMemory(plain); }
        });
    }

    private byte[]? ReadCacheEnvelope(byte[]? plain)
    {
        if (plain is null) return null;
        using var json = JsonDocument.Parse(plain);
        // Older versions wrote raw MSAL V3 data. Keep its accounts, but require
        // explicit selection rather than guessing which account the user intended.
        if (!json.RootElement.TryGetProperty(nameof(CacheEnvelope.OpenClawCacheVersion), out var version))
            return plain;
        if (version.GetInt32() != 1)
            throw new InvalidDataException("The protected identity cache version is unsupported.");
        var envelope = JsonSerializer.Deserialize<CacheEnvelope>(plain)
            ?? throw new InvalidDataException("The protected identity cache is invalid.");
        SelectedHomeAccountId = envelope.SelectedHomeAccountId;
        return envelope.MsalCache;
    }

    internal void SelectAccount(string homeAccountId, ITokenCache cache)
    {
        if (string.IsNullOrWhiteSpace(homeAccountId))
            throw new InvalidDataException("Sign-in did not identify the selected account.");
        var plain = ((ITokenCacheSerializer)cache).SerializeMsalV3();
        try
        {
            WriteCacheEnvelope(plain, homeAccountId);
            SelectedHomeAccountId = homeAccountId;
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    private void WriteCacheEnvelope(byte[] msalCache, string? selectedHomeAccountId)
    {
        var plain = JsonSerializer.SerializeToUtf8Bytes(new CacheEnvelope(1, selectedHomeAccountId, msalCache));
        try { Write(plain); }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    internal byte[]? ReadCiphertext()
    {
        if (!File.Exists(path)) return null;
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (file.Length is < 1 or > MaximumCacheBytes)
            throw new InvalidDataException("The protected identity cache is invalid.");
        var bytes = new byte[(int)file.Length];
        file.ReadExactly(bytes);
        return bytes;
    }

    internal void Clear()
    {
        using var lease = PersistenceFileLease.Acquire(path);
        if (File.Exists(path)) File.Delete(path);
        _baseline = null;
        SelectedHomeAccountId = null;
    }

    internal static byte[] Unprotect(byte[] bytes)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        return ProtectedData.Unprotect(bytes, Entropy, DataProtectionScope.CurrentUser);
    }

    internal void Write(byte[] plain)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using var lease = PersistenceFileLease.Acquire(path);
        var current = ReadCiphertext();
        if (!Equal(current, _baseline))
            throw new IOException("The protected identity cache changed. Retry sign-in.");
        var ciphertext = ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var staging = path + "." + Guid.NewGuid().ToString("N") + ".pending";
        try
        {
            using (var file = new FileStream(staging, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                file.Write(ciphertext);
                file.Flush(flushToDisk: true);
            }
            McpAuthToken.TryRestrictSensitiveFileAcl(staging);
            File.Move(staging, path, overwrite: true);
            _baseline = ciphertext;
        }
        finally { if (File.Exists(staging)) File.Delete(staging); }
    }

    private static bool Equal(byte[]? a, byte[]? b) =>
        a is null ? b is null : b is not null && a.AsSpan().SequenceEqual(b);
}
