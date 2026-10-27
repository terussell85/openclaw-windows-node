using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using Microsoft.Identity.Client;
using OpenClaw.Shared;
using OpenClaw.TestSupport;

namespace OpenClaw.Connection.Tests;

public sealed class MsalManagedIdentityTests
{
    [Theory]
    [InlineData("")]
    [InlineData("http://localhost:7443/")]
    public async Task InteractiveMsalAuthenticationDoesNotRequireServiceOrigin(string serviceUrl)
    {
        using var data = new TempDirectory("managed-msal-auth-first-");
        var options = ManagedRemoteConnectionTests.Options with { ServiceBaseUrl = serviceUrl };
        using var network = new ForbiddenNetwork();
        var interactions = 0;
        var identity = new MsalManagedIdentity(data.Path,
            settings => PublicClientApplicationBuilder.Create(settings.ClientId)
                .WithAuthority(settings.Authority).WithRedirectUri("http://localhost")
                .WithHttpClientFactory(network).WithInstanceDiscovery(false).Build(),
            (app, settings, _) =>
            {
                interactions++;
                ((ITokenCacheSerializer)app.UserTokenCache).DeserializeMsalV3(
                    SeedCache(settings, [UserA]), shouldClearExistingCache: true);
                return Task.FromResult(new AuthenticationResult(
                    "fixture-access-" + UserA, false, UserA, DateTimeOffset.UtcNow.AddHours(1),
                    DateTimeOffset.UtcNow.AddHours(1), Tenant, new FixtureAccount(UserA), "",
                    [settings.ApiScope], Guid.NewGuid()));
            });
        Assert.Equal("fixture-access-" + UserA, (await identity.AcquireAsync(options, true, default)).Value);
        Assert.Equal(1, interactions);
        Assert.Equal(0, network.Requests);
        Assert.Throws<ManagedConnectionException>(() => ManagedEndpointPolicy.ValidateConfiguration(options));
    }

    private const string Tenant = "11111111-1111-1111-1111-111111111111";
    private const string UserA = "33333333-3333-3333-3333-333333333333";
    private const string UserB = "44444444-4444-4444-4444-444444444444";

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task LegacyCacheWithoutSelectionRetainsAccountsButNeverGuessesOne(int accountCount)
    {
        using var data = new TempDirectory("managed-legacy-accounts-");
        var options = ManagedRemoteConnectionTests.Options;
        var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{options.Authority}\n{options.ClientId}\n{options.ApiScope}\n{options.ServiceBaseUrl}")));
        new ProtectedMsalCache(data.Combine("managed-identity", key + ".dpapi"))
            .Write(SeedCache(options, accountCount == 1 ? [UserA] : [UserA, UserB]));
        using var network = new ForbiddenNetwork();
        IPublicClientApplication? app = null;
        var identity = new MsalManagedIdentity(data.Path,
            settings => app = PublicClientApplicationBuilder.Create(settings.ClientId)
                .WithAuthority(settings.Authority).WithRedirectUri("http://localhost")
                .WithHttpClientFactory(network).WithInstanceDiscovery(false).Build(),
            (_, _, _) => throw new Xunit.Sdk.XunitException("Silent import must not open a browser."));
        var result = await Assert.ThrowsAsync<ManagedConnectionException>(() => identity.AcquireAsync(options, false, default));
        Assert.Equal(ManagedConnectionState.SignInRequired, result.State);
        Assert.Equal(accountCount, (await app!.GetAccountsAsync()).Count());
        Assert.Equal(0, network.Requests);
    }

    [Fact]
    public async Task ExplicitSecondAccountRemainsSelectedForRealMsalSilentAcquisitionAcrossRestart()
    {
        using var data = new TempDirectory("managed-accounts-");
        var options = ManagedRemoteConnectionTests.Options;
        using var network = new ForbiddenNetwork();
        IPublicClientApplication? lastApplication = null;
        IPublicClientApplication CreateApplication(ManagedRemoteOptions settings) =>
            lastApplication = PublicClientApplicationBuilder.Create(settings.ClientId)
                .WithAuthority(settings.Authority).WithRedirectUri("http://localhost")
                .WithHttpClientFactory(network).WithInstanceDiscovery(false).Build();
        var interactions = 0;
        Task<AuthenticationResult> SelectAccount(IPublicClientApplication app, ManagedRemoteOptions settings, CancellationToken ct)
        {
            var user = ++interactions == 1 ? UserA : UserB;
            // Only browser interaction is substituted. Account enumeration and every
            // silent acquisition below use MSAL 4.91.1 with a network-blocked cache.
            ((ITokenCacheSerializer)app.UserTokenCache).DeserializeMsalV3(SeedCache(settings, interactions == 1 ? [UserA] : [UserA, UserB]),
                shouldClearExistingCache: true);
            return Task.FromResult(new AuthenticationResult(
                "fixture-access-" + user, false, user, DateTimeOffset.UtcNow.AddHours(1),
                DateTimeOffset.UtcNow.AddHours(1), Tenant, new FixtureAccount(user), "",
                [settings.ApiScope], Guid.NewGuid()));
        }

        var identity = new MsalManagedIdentity(data.Path, CreateApplication, SelectAccount);
        Assert.Equal("fixture-access-" + UserA, (await identity.AcquireAsync(options, true, default)).Value);
        Assert.Single(await lastApplication!.GetAccountsAsync());
        Assert.Equal("fixture-access-" + UserA, (await identity.AcquireAsync(options, false, default)).Value);
        Assert.Equal("fixture-access-" + UserB, (await identity.AcquireAsync(options, true, default)).Value);
        Assert.Equal(2, (await lastApplication!.GetAccountsAsync()).Count());
        Assert.Equal("fixture-access-" + UserB, (await identity.AcquireAsync(options, false, default)).Value);

        var restarted = new MsalManagedIdentity(data.Path, CreateApplication,
            (_, _, _) => throw new Xunit.Sdk.XunitException("Silent restart must not open a browser."));
        Assert.Equal("fixture-access-" + UserB, (await restarted.AcquireAsync(options, false, default)).Value);
        Assert.Equal(2, (await lastApplication!.GetAccountsAsync()).Count());
        var persisted = File.ReadAllBytes(Directory.GetFiles(data.Combine("managed-identity"), "*.dpapi").Single());
        Assert.DoesNotContain(UserB, Encoding.UTF8.GetString(persisted));
        Assert.DoesNotContain("fixture-access-", Encoding.UTF8.GetString(persisted));

        var selected = (await lastApplication.GetAccountsAsync()).Single(a => a.HomeAccountId.Identifier == UserB + "." + Tenant);
        await lastApplication.RemoveAsync(selected);
        var missing = await Assert.ThrowsAsync<ManagedConnectionException>(() => restarted.AcquireAsync(options, false, default));
        Assert.Equal(ManagedConnectionState.SignInRequired, missing.State);
        Assert.Single(await lastApplication.GetAccountsAsync());

        await restarted.SignOutAsync(options, default);
        Assert.Empty(Directory.GetFiles(data.Combine("managed-identity")));
        var afterSignOut = new MsalManagedIdentity(data.Path, CreateApplication,
            (_, _, _) => throw new Xunit.Sdk.XunitException("Sign-out cannot select an account."));
        var signedOut = await Assert.ThrowsAsync<ManagedConnectionException>(() => afterSignOut.AcquireAsync(options, false, default));
        Assert.Equal(ManagedConnectionState.SignInRequired, signedOut.State);
        Assert.Equal(0, network.Requests);
    }

    private static byte[] SeedCache(ManagedRemoteOptions options, string[] users)
    {
        var accounts = new Dictionary<string, object>();
        var tokens = new Dictionary<string, object>();
        var idTokens = new Dictionary<string, object>();
        var refreshTokens = new Dictionary<string, object>();
        var now = DateTimeOffset.UtcNow;
        foreach (var user in users)
        {
            var home = user + "." + Tenant;
            accounts[$"{home}-login.microsoftonline.com-{Tenant}"] = new
            {
                home_account_id = home, environment = "login.microsoftonline.com", realm = Tenant,
                local_account_id = user, username = user + "@example.invalid",
                authority_type = "MSSTS", name = "Fixture account",
                client_info = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new { uid = user, utid = Tenant }))
                    .TrimEnd('=').Replace('+', '-').Replace('/', '_'),
            };
            tokens[$"{home}-login.microsoftonline.com-accesstoken-{options.ClientId}-{Tenant}-{options.ApiScope}--"] = new
            {
                home_account_id = home, environment = "login.microsoftonline.com",
                credential_type = "AccessToken", client_id = options.ClientId, realm = Tenant,
                target = options.ApiScope, secret = "fixture-access-" + user, token_type = "Bearer",
                cached_at = now.AddMinutes(-1).ToUnixTimeSeconds().ToString(),
                expires_on = now.AddHours(1).ToUnixTimeSeconds().ToString(),
                extended_expires_on = now.AddHours(1).ToUnixTimeSeconds().ToString(),
            };
            idTokens[$"{home}-login.microsoftonline.com-idtoken-{options.ClientId}-{Tenant}-"] = new
            {
                home_account_id = home, environment = "login.microsoftonline.com",
                credential_type = "IdToken", client_id = options.ClientId, realm = Tenant,
                secret = Base64Url(new { alg = "RS256", typ = "JWT" }) + "." +
                    Base64Url(new
                    {
                        aud = options.ClientId, iss = $"https://login.microsoftonline.com/{Tenant}/v2.0",
                        iat = now.AddMinutes(-1).ToUnixTimeSeconds(), exp = now.AddHours(1).ToUnixTimeSeconds(),
                        oid = user, tid = Tenant, sub = user, preferred_username = user + "@example.invalid",
                    }) + ".Zml4dHVyZQ",
            };
            refreshTokens[$"{home}-login.microsoftonline.com-refreshtoken-{options.ClientId}--"] = new
            {
                home_account_id = home, environment = "login.microsoftonline.com",
                credential_type = "RefreshToken", client_id = options.ClientId,
                secret = "fixture-refresh-" + user,
            };
        }
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            Account = accounts, AccessToken = tokens,
            RefreshToken = refreshTokens, IdToken = idTokens, AppMetadata = new { },
        });
    }

    private static string Base64Url(object value) =>
        Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(value)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed class FixtureAccount(string user) : IAccount
    {
        public string Username => user + "@example.invalid";
        public string Environment => "login.microsoftonline.com";
        public AccountId HomeAccountId => new(user + "." + Tenant, user, Tenant);
    }

    private sealed class ForbiddenNetwork : HttpMessageHandler, IMsalHttpClientFactory
    {
        public int Requests;
        public HttpClient GetHttpClient() => new(this, disposeHandler: false);
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref Requests);
            throw new Xunit.Sdk.XunitException("MSAL cache regression must not make network requests.");
        }
    }
}
