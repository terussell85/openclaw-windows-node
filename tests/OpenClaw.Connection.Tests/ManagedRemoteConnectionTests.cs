using System.Net;
using System.Net.Http.Json;
using System.Text;
using OpenClaw.Shared;
using OpenClaw.TestSupport;

namespace OpenClaw.Connection.Tests;

public sealed class ManagedRemoteConnectionTests
{
    [Theory]
    [InlineData("")]
    [InlineData("http://localhost:7443/")]
    [InlineData("https://service.example/not-an-origin")]
    public async Task InvalidServiceOriginStillRejectsApiCallsBeforeTokenAcquisition(string serviceUrl)
    {
        var identity = new Identity();
        using var http = new HttpClient(new Handler(_ =>
            throw new Xunit.Sdk.XunitException("An invalid service origin must not receive an API request.")));
        var api = new NativeManagementApi(http, identity);
        var options = Options with { ServiceBaseUrl = serviceUrl };
        Assert.True(ManagedEndpointPolicy.IsIdentityConfigured(options));
        Assert.False(ManagedEndpointPolicy.TryGetServiceOrigin(options, out var origin));
        Assert.Null(origin);
        var error = await Assert.ThrowsAsync<ManagedConnectionException>(() => api.DiscoverAsync(options, default));
        Assert.Equal(ManagedConnectionState.SetupRequired, error.State);
        Assert.Equal(0, identity.Calls);
    }

    internal static ManagedRemoteOptions Options => new()
    {
        Enabled = true,
        Authority = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111",
        ClientId = "22222222-2222-2222-2222-222222222222",
        ApiScope = "api://fixture/access_as_user",
        ServiceBaseUrl = "https://service.example/",
    };

    internal static NativeConnection Ready(string version = "generation-1") => new(
        1, "ready", "claw-1", version, null,
        new NativeGatewayRoutes("wss://service.example/api/native/gateway",
            "https://service.example/api/native/gateway", "https://service.example/api/native/enrollments"));

    [Fact]
    public void SensitiveIdentityAndEnrollmentRecordsDoNotFormatCredentials()
    {
        Assert.DoesNotContain("sensitive-human-token", new ManagedAccessToken(
            "sensitive-human-token", DateTimeOffset.UtcNow.AddHours(1)).ToString());
        Assert.DoesNotContain("sensitive-setup-code", new NativeEnrollment(
            1, Guid.NewGuid().ToString(), "claw", "version", "sensitive-setup-code",
            DateTimeOffset.UtcNow.AddMinutes(1), ["operator.read"], []).ToString());
    }

    [Fact]
    public void DeveloperConfigurationChangeReplacesOnlyAnActiveManagedProfile()
    {
        using var data = new TempDirectory();
        var registry = new GatewayRegistry(data.Path);
        using var provider = new ManagedGatewayProvider(registry, new Identity());
        var first = provider.EnsureProfile(Options);
        var changed = provider.EnsureProfile(Options with { ApiScope = "api://fixture/other-scope" });
        Assert.NotEqual(first.Id, changed.Id);
        Assert.Equal(changed.Id, registry.ActiveGatewayId);
        var ordinary = new GatewayRecord { Id = Guid.NewGuid().ToString(), Url = "wss://ordinary.example/" };
        registry.AddOrUpdate(ordinary);
        registry.SetActive(ordinary.Id);
        registry.Save();
        provider.EnsureProfile(Options);
        Assert.Equal(ordinary.Id, registry.ActiveGatewayId);
    }

    [Fact]
    public async Task MissingConfigurationIsSetupRequiredWithoutIdentityOrNetwork()
    {
        using var data = new TempDirectory();
        var identity = new Identity();
        using var provider = new ManagedGatewayProvider(new GatewayRegistry(data.Path), identity,
            new Handler(_ => throw new Xunit.Sdk.XunitException("No network allowed")));
        var record = provider.EnsureProfile(new ManagedRemoteOptions { Enabled = true });
        var error = await Assert.ThrowsAsync<ManagedConnectionException>(() => provider.PrepareAsync(record, default));
        Assert.Equal(ManagedConnectionState.SetupRequired, error.State);
        Assert.Equal(0, identity.Calls);
        Assert.Empty(Directory.GetDirectories(data.Path, "managed-identity"));
    }

    [Theory]
    [InlineData("notAssigned", ManagedConnectionState.NotAssigned)]
    [InlineData("offline", ManagedConnectionState.Offline)]
    [InlineData("unknown", ManagedConnectionState.Unavailable)]
    public async Task DiscoveryStatesDoNotProvisionOrRepair(string state, ManagedConnectionState expected)
    {
        using var data = new TempDirectory();
        var calls = 0;
        using var provider = new ManagedGatewayProvider(new GatewayRegistry(data.Path), new Identity(), new Handler(r =>
        {
            calls++;
            Assert.Equal(HttpMethod.Get, r.Method);
            Assert.Equal("/api/native/connection", r.RequestUri!.AbsolutePath);
            return Json(Ready() with { State = state });
        }));
        var error = await Assert.ThrowsAsync<ManagedConnectionException>(() =>
            provider.PrepareAsync(provider.EnsureProfile(Options), default));
        Assert.Equal(expected, error.State);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task ActivationUsesExistingBodylessPostAndExactPollContract()
    {
        using var data = new TempDirectory();
        var paths = new List<string>();
        var discovery = 0;
        using var provider = new ManagedGatewayProvider(new GatewayRegistry(data.Path), new Identity(), new Handler(r =>
        {
            paths.Add(r.Method + " " + r.RequestUri!.AbsolutePath);
            Assert.Equal("Bearer human-1", r.Headers.Authorization!.ToString());
            if (r.RequestUri.AbsolutePath == "/api/native/connection")
                return Json(++discovery == 1 ? Ready() with { State = "activationRequired" } : Ready());
            if (r.Method == HttpMethod.Post)
            {
                Assert.Null(r.Content);
                return Json(new NativeActivation("Starting", "/api/control/activates/claw-1", null), HttpStatusCode.Accepted);
            }
            return Json(new NativeActivation("Ready", null, null));
        }), new GrantEnrollment(), TimeSpan.Zero);
        var bound = await provider.PrepareAsync(provider.EnsureProfile(Options), default);
        Assert.NotNull(bound.ManagedRemote);
        Assert.Equal(new[]
        {
            "GET /api/native/connection", "POST /api/control/activations",
            "GET /api/control/activates/claw-1", "GET /api/native/connection",
        }, paths);
    }

    [Fact]
    public async Task StableAssignmentIdentityAndCredentialAreReusedButNewGenerationGetsNewKey()
    {
        using var data = new TempDirectory();
        var registry = new GatewayRegistry(data.Path);
        var version = "generation-1";
        var enrollment = new GrantEnrollment();
        using var provider = new ManagedGatewayProvider(registry, new Identity(),
            new Handler(_ => Json(Ready(version))), enrollment);
        var profile = provider.EnsureProfile(Options);
        var first = await provider.PrepareAsync(profile, default);
        var firstKey = new DeviceIdentity(registry.GetIdentityDirectory(first.Id));
        firstKey.LoadExisting();
        var second = await provider.PrepareAsync(profile, default);
        Assert.Equal(first.Id, second.Id);
        Assert.Equal(1, enrollment.Calls);
        version = "generation-2";
        var next = await provider.PrepareAsync(profile, default);
        var nextKey = new DeviceIdentity(registry.GetIdentityDirectory(next.Id));
        nextKey.LoadExisting();
        Assert.NotEqual(first.Id, next.Id);
        Assert.NotEqual(firstKey.DeviceId, nextKey.DeviceId);
        Assert.Equal(2, enrollment.Calls);
        var json = File.ReadAllText(Path.Combine(data.Path, "gateways.json"));
        Assert.DoesNotContain("human-1", json);
        Assert.DoesNotContain("fixture-device-credential", json);
    }

    [Fact]
    public async Task InterruptedEnrollmentRequiresExplicitFreshIntentAndKeepsKey()
    {
        using var data = new TempDirectory();
        var registry = new GatewayRegistry(data.Path);
        var enrollment = new GrantEnrollment { Fail = true };
        using var provider = new ManagedGatewayProvider(registry, new Identity(),
            new Handler(_ => Json(Ready())), enrollment);
        var profile = provider.EnsureProfile(Options);
        await Assert.ThrowsAsync<ManagedConnectionException>(() => provider.PrepareAsync(profile, default));
        var key = enrollment.DeviceId;
        var error = await Assert.ThrowsAsync<ManagedConnectionException>(() => provider.PrepareAsync(profile, default));
        Assert.Equal(ManagedConnectionState.EnrollmentExpired, error.State);
        Assert.Equal(1, enrollment.Calls);
        await provider.SignInAsync(Options, default);
        enrollment.Fail = false;
        await provider.PrepareAsync(profile, default);
        Assert.Equal(key, enrollment.DeviceId);
    }

    [Fact]
    public async Task RejectedDeviceCredentialRequiresExplicitFreshEnrollmentWithoutRotatingSigningIdentity()
    {
        using var data = new TempDirectory();
        var registry = new GatewayRegistry(data.Path);
        var enrollment = new GrantEnrollment();
        using var provider = new ManagedGatewayProvider(registry, new Identity(),
            new Handler(_ => Json(Ready())), enrollment);
        var profile = provider.EnsureProfile(Options);
        var bound = await provider.PrepareAsync(profile, default);
        var key = enrollment.DeviceId;
        provider.RequireFreshEnrollment(bound.Id);
        var error = await Assert.ThrowsAsync<ManagedConnectionException>(() => provider.PrepareAsync(bound, default));
        Assert.Equal(ManagedConnectionState.EnrollmentExpired, error.State);
        Assert.Equal(1, enrollment.Calls);
        await provider.SignInAsync(Options, default);
        await provider.PrepareAsync(bound, default);
        Assert.Equal(2, enrollment.Calls);
        Assert.Equal(key, enrollment.DeviceId);
    }

    [Fact]
    public async Task HeadersRenewSilentlyRejectWrongOriginsAndInvalidateAfterSignOutOrAssignmentChange()
    {
        using var data = new TempDirectory();
        var identity = new Identity();
        var version = "generation-1";
        using var provider = new ManagedGatewayProvider(new GatewayRegistry(data.Path), identity,
            new Handler(_ => Json(Ready(version))), new GrantEnrollment());
        var record = await provider.PrepareAsync(provider.EnsureProfile(Options), default);
        var authentication = provider.CreateAuthentication(record);
        identity.Value = "renewed-human";
        var headers = await authentication.GetHeadersAsync(new Uri(record.Url), default);
        Assert.Equal("Bearer renewed-human", headers["Authorization"]);
        Assert.Equal("claw-1", headers["X-Claw-Id"]);
        Assert.Equal("generation-1", headers["X-Claw-Assignment-Version"]);
        Assert.DoesNotContain("X-Claw-Gateway-Token", headers.Keys);
        await Assert.ThrowsAsync<ManagedConnectionException>(() =>
            authentication.GetHeadersAsync(new Uri("https://untrusted.example/api/native/gateway/file"), default));
        version = "generation-2";
        var stale = await Assert.ThrowsAsync<ManagedConnectionException>(() =>
            authentication.GetHeadersAsync(authentication.HttpBaseUri, default));
        Assert.Equal(ManagedConnectionState.StaleAssignment, stale.State);
        await provider.SignOutAsync(Options, default);
        Assert.True(identity.SignedOut);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            authentication.GetHeadersAsync(authentication.HttpBaseUri, default));
    }

    [Theory]
    [InlineData(401, ManagedConnectionState.SignInRequired)]
    [InlineData(403, ManagedConnectionState.AccessDenied)]
    [InlineData(409, ManagedConnectionState.StaleAssignment)]
    [InlineData(410, ManagedConnectionState.EnrollmentExpired)]
    [InlineData(503, ManagedConnectionState.Unavailable)]
    public async Task RestErrorsRemainTypedAndNeverExposeResponseCredentials(int status, ManagedConnectionState expected)
    {
        using var data = new TempDirectory();
        using var provider = new ManagedGatewayProvider(new GatewayRegistry(data.Path), new Identity(),
            new Handler(_ => new HttpResponseMessage((HttpStatusCode)status)
            { Content = new StringContent("secret bootstrap payload") }));
        var exception = await Assert.ThrowsAsync<ManagedConnectionException>(() =>
            provider.PrepareAsync(provider.EnsureProfile(Options), default));
        Assert.Equal(expected, exception.State);
        Assert.DoesNotContain("secret", exception.ToString());
    }

    [Theory]
    [InlineData("https://other.example/api/native/gateway")]
    [InlineData("http://service.example/api/native/gateway")]
    [InlineData("https://service.example/api/native/gateway/../secrets")]
    [InlineData("https://service.example/api/native/gateway/%252e%252e/secrets")]
    [InlineData("https://user:secret@service.example/api/native/gateway")]
    public void UntrustedRoutesAreRejectedBeforeTokenAcquisition(string route)
    {
        Assert.Throws<ManagedConnectionException>(() =>
            ManagedEndpointPolicy.RequireServiceRoute(new Uri(Options.ServiceBaseUrl), route, "/api/native/gateway"));
    }

    [Fact]
    public async Task RealMsalAdapterWithEmptyCacheRequiresExplicitSignInAndCanSignOutWithoutNetwork()
    {
        using var data = new TempDirectory();
        var identity = new MsalManagedIdentity(data.Path);
        var error = await Assert.ThrowsAsync<ManagedConnectionException>(() => identity.AcquireAsync(Options, false, default));
        Assert.Equal(ManagedConnectionState.SignInRequired, error.State);
        await identity.SignOutAsync(Options, default);
        Assert.Empty(Directory.GetFiles(data.Path, "*", SearchOption.AllDirectories));
    }

    [Theory]
    [InlineData(503, "setupRequired", ManagedConnectionState.SetupRequired)]
    [InlineData(409, "enrollmentExpired", ManagedConnectionState.EnrollmentExpired)]
    [InlineData(502, "gatewayIncompatible", ManagedConnectionState.CompatibilityError)]
    [InlineData(409, "staleAssignment", ManagedConnectionState.StaleAssignment)]
    public async Task ProblemDetailsTopLevelCodesRemainActionable(int status, string code, ManagedConnectionState expected)
    {
        using var data = new TempDirectory();
        using var provider = new ManagedGatewayProvider(new GatewayRegistry(data.Path), new Identity(),
            new Handler(_ => Json(new { status, code, detail = "never display raw credentials" }, (HttpStatusCode)status)));
        var error = await Assert.ThrowsAsync<ManagedConnectionException>(() =>
            provider.PrepareAsync(provider.EnsureProfile(Options), default));
        Assert.Equal(expected, error.State);
        Assert.DoesNotContain("credentials", error.ToString());
    }

    [Fact]
    public void ProtectedCacheWritesOnlyDpapiCiphertextAndRejectsConcurrentReplacement()
    {
        using var data = new TempDirectory();
        var path = data.Combine("cache.dpapi");
        var cache = new ProtectedMsalCache(path);
        var plain = Encoding.UTF8.GetBytes("fixture-sensitive-msal-cache");
        cache.Write(plain);
        Assert.DoesNotContain("fixture-sensitive-msal-cache", Encoding.UTF8.GetString(File.ReadAllBytes(path)));
        Assert.Equal(plain, ProtectedMsalCache.Unprotect(File.ReadAllBytes(path)));
        var stale = new ProtectedMsalCache(path);
        Assert.Throws<IOException>(() => stale.Write(plain));
    }

    internal sealed class Identity : IManagedIdentity
    {
        public string Value = "human-1";
        public int Calls;
        public bool SignedOut;
        public Task<ManagedAccessToken> AcquireAsync(ManagedRemoteOptions options, bool interactive, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(new ManagedAccessToken(Value, DateTimeOffset.UtcNow.AddHours(1)));
        }
        public Task SignOutAsync(ManagedRemoteOptions options, CancellationToken ct)
        { SignedOut = true; return Task.CompletedTask; }
    }

    internal sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(response(request));
    }

    internal sealed class GrantEnrollment : IManagedGatewayEnrollment
    {
        public int Calls;
        public bool Fail;
        public string? DeviceId;
        public Task EnrollAsync(GatewayRecord record, string directory, IGatewayTransportAuthentication authentication,
            Action<ManagedConnectionState> state, CancellationToken ct)
        {
            Calls++;
            var device = new DeviceIdentity(directory);
            device.LoadExisting();
            DeviceId = device.DeviceId;
            if (Fail) throw new ManagedConnectionException(ManagedConnectionState.Unavailable);
            device.StoreDeviceTokenWithScopes("fixture-device-credential", ManagedOperatorGrant.Scopes);
            return Task.CompletedTask;
        }
    }

    internal static HttpResponseMessage Json(object value, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = JsonContent.Create(value) };
}
