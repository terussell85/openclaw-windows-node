using System.Security.Cryptography;
using System.Text;
using Microsoft.Identity.Client;
using OpenClaw.Shared;

namespace OpenClaw.Connection;

/// <summary>Public client authorization code/PKCE through the system browser and MSAL loopback listener.</summary>
public sealed class MsalManagedIdentity : IManagedIdentity
{
    private readonly string _dataDirectory;
    private readonly Func<ManagedRemoteOptions, IPublicClientApplication> _applicationFactory;
    private readonly Func<IPublicClientApplication, ManagedRemoteOptions, CancellationToken, Task<AuthenticationResult>>
        _interactiveAuthentication;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private sealed record IdentitySession(string Key, IPublicClientApplication App, ProtectedMsalCache Cache);
    private readonly Dictionary<string, IdentitySession> _applications = new(StringComparer.Ordinal);

    public MsalManagedIdentity(string dataDirectory)
        : this(dataDirectory,
            options => PublicClientApplicationBuilder.Create(options.ClientId)
                .WithAuthority(options.Authority)
                .WithRedirectUri("http://localhost")
                .Build(),
            (app, options, ct) => app.AcquireTokenInteractive([options.ApiScope])
                .WithUseEmbeddedWebView(false)
                .WithPrompt(Prompt.SelectAccount)
                .ExecuteAsync(ct))
    {
    }

    internal MsalManagedIdentity(string dataDirectory,
        Func<ManagedRemoteOptions, IPublicClientApplication> applicationFactory,
        Func<IPublicClientApplication, ManagedRemoteOptions, CancellationToken, Task<AuthenticationResult>> interactiveAuthentication)
    {
        _dataDirectory = dataDirectory;
        _applicationFactory = applicationFactory;
        _interactiveAuthentication = interactiveAuthentication;
    }

    private IdentitySession GetApplication(ManagedRemoteOptions options)
    {
        ManagedEndpointPolicy.ValidateIdentityConfiguration(options);
        var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{options.Authority}\n{options.ClientId}\n{options.ApiScope}\n{options.ServiceBaseUrl}")));
        if (_applications.TryGetValue(key, out var existing)) return existing;
        var app = _applicationFactory(options);
        var cache = new ProtectedMsalCache(Path.Combine(_dataDirectory, "managed-identity", key + ".dpapi"));
        cache.Attach(app.UserTokenCache);
        var session = new IdentitySession(key, app, cache);
        _applications.Add(key, session);
        return session;
    }

    public async Task<ManagedAccessToken> AcquireAsync(
        ManagedRemoteOptions options, bool interactive, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var session = GetApplication(options);
            IAccount[] accounts;
            try { accounts = (await session.App.GetAccountsAsync().ConfigureAwait(false)).ToArray(); }
            catch (CryptographicException) when (interactive)
            {
                session.Cache.Clear();
                _applications.Remove(session.Key);
                session = GetApplication(options);
                accounts = [];
            }
            var app = session.App;
            AuthenticationResult result;
            try
            {
                var selected = accounts.SingleOrDefault(account =>
                    string.Equals(account.HomeAccountId.Identifier, session.Cache.SelectedHomeAccountId, StringComparison.Ordinal));
                if (interactive || selected is null)
                    throw new MsalUiRequiredException("interaction_required", "Sign in to the managed connection.");
                result = await app.AcquireTokenSilent([options.ApiScope], selected)
                    .ExecuteAsync(ct).ConfigureAwait(false);
            }
            catch (MsalUiRequiredException)
            {
                if (!interactive)
                    throw new ManagedConnectionException(ManagedConnectionState.SignInRequired);
                result = await _interactiveAuthentication(app, options, ct).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                if (result.Account?.HomeAccountId.Identifier is not { Length: > 0 } homeAccountId)
                    throw new ManagedConnectionException(ManagedConnectionState.SignInRequired);
                session.Cache.SelectAccount(homeAccountId, app.UserTokenCache);
            }
            return new ManagedAccessToken(result.AccessToken, result.ExpiresOn);
        }
        catch (MsalException) { throw new ManagedConnectionException(ManagedConnectionState.SignInRequired); }
        catch (CryptographicException) { throw new ManagedConnectionException(ManagedConnectionState.SignInRequired); }
        catch (IOException) { throw new ManagedConnectionException(ManagedConnectionState.Unavailable); }
        finally { _gate.Release(); }
    }

    public async Task SignOutAsync(ManagedRemoteOptions options, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var session = GetApplication(options);
            try
            {
                foreach (var account in await session.App.GetAccountsAsync().ConfigureAwait(false))
                    await session.App.RemoveAsync(account).ConfigureAwait(false);
            }
            catch (CryptographicException)
            {
                // Explicit local sign-out can discard this app's unreadable protected cache.
            }
            finally
            {
                session.Cache.Clear();
                _applications.Remove(session.Key);
            }
        }
        catch (MsalException) { throw new ManagedConnectionException(ManagedConnectionState.Unavailable); }
        catch (IOException) { throw new ManagedConnectionException(ManagedConnectionState.Unavailable); }
        finally { _gate.Release(); }
    }
}
