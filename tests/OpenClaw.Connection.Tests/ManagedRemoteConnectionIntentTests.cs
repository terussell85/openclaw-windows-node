using OpenClaw.Shared;
using OpenClaw.TestSupport;

namespace OpenClaw.Connection.Tests;

public sealed class ManagedRemoteConnectionIntentTests
{
    [Theory]
    [InlineData("")]
    [InlineData("http://localhost:7443/")]
    [InlineData("https://service.example/not-an-origin")]
    public async Task SignInCompletesBeforeServiceConfigurationIsRequired(string serviceUrl)
    {
        using var data = new TempDirectory("managed-auth-first-");
        var registry = CreateRegistry(data.Path);
        var identity = new DelayedIdentity();
        var provider = new ManagedGatewayProvider(registry, identity,
            new ManagedRemoteConnectionTests.Handler(_ =>
                throw new Xunit.Sdk.XunitException("Invalid service configuration must never receive a token.")),
            new ManagedRemoteConnectionTests.GrantEnrollment());
        var factory = new CountingFactory();
        await using var manager = new GatewayConnectionManager(new CredentialResolver(DeviceIdentityFileReader.Instance),
            factory, registry, NullLogger.Instance, managedGatewayProvider: provider);
        using var service = new ManagedRemoteConnectionService(provider, manager, registry,
            ManagedRemoteConnectionTests.Options with { ServiceBaseUrl = serviceUrl });
        service.Initialize();
        Assert.True(service.CanSignIn);
        Assert.Equal(ManagedConnectionState.SignInRequired, service.State);
        var signIn = service.SignInAndConnectAsync();
        await identity.Entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        identity.Release.TrySetResult(new ManagedAccessToken("fixture-selected-human", DateTimeOffset.UtcNow.AddHours(1)));
        await signIn.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(1, identity.InteractiveCalls);
        Assert.Equal(ManagedConnectionState.ServiceSetupRequired, service.State);
        Assert.Equal("ordinary-a", registry.ActiveGatewayId);
        Assert.Empty(factory.CreatedUrls);
    }

    [Theory]
    [InlineData("switch")]
    [InlineData("disconnect")]
    [InlineData("away-back")]
    public async Task DelayedBrowserAuthenticationCannotOverrideNewerConnectionIntent(string newerIntent)
    {
        using var data = new TempDirectory("managed-intent-");
        var registry = CreateRegistry(data.Path);
        var identity = new DelayedIdentity();
        var calls = 0;
        var provider = new ManagedGatewayProvider(registry, identity,
            new ManagedRemoteConnectionTests.Handler(_ =>
            {
                calls++;
                return ManagedRemoteConnectionTests.Json(ManagedRemoteConnectionTests.Ready());
            }), new ManagedRemoteConnectionTests.GrantEnrollment());
        var factory = new CountingFactory();
        await using var manager = new GatewayConnectionManager(new CredentialResolver(DeviceIdentityFileReader.Instance),
            factory, registry, NullLogger.Instance, managedGatewayProvider: provider);
        using var service = new ManagedRemoteConnectionService(provider, manager, registry, ManagedRemoteConnectionTests.Options);
        service.Initialize();
        var signIn = service.SignInAndConnectAsync();
        await identity.Entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        if (newerIntent == "disconnect")
            await manager.DisconnectByUserAsync();
        else
        {
            await manager.SwitchGatewayAsync("ordinary-b");
            if (newerIntent == "away-back")
                await manager.SwitchGatewayAsync("ordinary-a");
        }
        Assert.True(identity.AuthenticationCancellation.IsCancellationRequested);
        // Model a browser/identity boundary that returns success despite cancellation.
        identity.Release.TrySetResult(new ManagedAccessToken("fixture-selected-human", DateTimeOffset.UtcNow.AddHours(1)));
        await signIn.WaitAsync(TimeSpan.FromSeconds(2));

        Assert.Equal(newerIntent == "switch" ? "ordinary-b" : "ordinary-a", registry.ActiveGatewayId);
        Assert.Equal(0, calls);
        Assert.DoesNotContain("wss://service.example/api/native/gateway", factory.CreatedUrls);
        if (newerIntent == "disconnect")
        {
            Assert.Null(manager.OperatorClient);
            Assert.False(manager.IsAutomaticReconnectAllowed("ordinary-a"));
        }
    }

    [Fact]
    public async Task QueuedSignInCannotAcquireFreshAuthorityAfterANewerDisconnect()
    {
        using var data = new TempDirectory("managed-queued-signin-");
        var registry = CreateRegistry(data.Path);
        var identity = new DelayedIdentity();
        var calls = 0;
        var provider = new ManagedGatewayProvider(registry, identity,
            new ManagedRemoteConnectionTests.Handler(_ =>
            {
                calls++;
                return ManagedRemoteConnectionTests.Json(ManagedRemoteConnectionTests.Ready());
            }), new ManagedRemoteConnectionTests.GrantEnrollment());
        await using var manager = new GatewayConnectionManager(new CredentialResolver(DeviceIdentityFileReader.Instance),
            new CountingFactory(), registry, NullLogger.Instance, managedGatewayProvider: provider);
        using var service = new ManagedRemoteConnectionService(provider, manager, registry, ManagedRemoteConnectionTests.Options);
        service.Initialize();
        var first = service.SignInAndConnectAsync();
        await identity.Entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var queued = service.SignInAndConnectAsync();
        await manager.DisconnectByUserAsync();
        identity.Release.TrySetResult(new ManagedAccessToken("fixture-selected-human", DateTimeOffset.UtcNow.AddHours(1)));
        await Task.WhenAll(first, queued).WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(1, identity.InteractiveCalls);
        Assert.Equal(0, calls);
        Assert.Equal("ordinary-a", registry.ActiveGatewayId);
        Assert.False(manager.IsAutomaticReconnectAllowed("ordinary-a"));
    }

    [Fact]
    public async Task CurrentAuthenticationIntentCanCommitThroughTheCanonicalManager()
    {
        using var data = new TempDirectory("managed-current-intent-");
        var registry = CreateRegistry(data.Path);
        var provider = new ManagedGatewayProvider(registry, new ManagedRemoteConnectionTests.Identity(),
            new ManagedRemoteConnectionTests.Handler(_ => ManagedRemoteConnectionTests.Json(ManagedRemoteConnectionTests.Ready())),
            new ManagedRemoteConnectionTests.GrantEnrollment());
        var factory = new CountingFactory();
        await using var manager = new GatewayConnectionManager(new CredentialResolver(DeviceIdentityFileReader.Instance),
            factory, registry, NullLogger.Instance, managedGatewayProvider: provider);
        using var service = new ManagedRemoteConnectionService(provider, manager, registry, ManagedRemoteConnectionTests.Options);
        service.Initialize();
        await service.SignInAndConnectAsync();
        Assert.Equal("generation-1", registry.GetActive()!.ManagedRemote!.AssignmentVersion);
        Assert.Equal(new[] { "wss://service.example/api/native/gateway" }, factory.CreatedUrls);
    }

    [Fact]
    public async Task ConditionalSwitchRechecksIntentAfterWaitingForLifecycleAdmission()
    {
        using var data = new TempDirectory("managed-queued-intent-");
        var registry = CreateRegistry(data.Path);
        await using var manager = new GatewayConnectionManager(new CredentialResolver(DeviceIdentityFileReader.Instance),
            new CountingFactory(), registry, NullLogger.Instance);
        using var held = await manager.BeginManualGatewayLifecycleOperationAsync();
        using var intent = manager.CaptureConnectionIntent();
        var queued = manager.SwitchGatewayIfIntentCurrentAsync("ordinary-b", intent);
        await manager.DisconnectByUserAsync();
        Assert.False(await queued.WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.Equal("ordinary-a", registry.ActiveGatewayId);
    }

    [Fact]
    public async Task DisposingAnIntentCancelsItsQueuedConditionalSwitch()
    {
        using var data = new TempDirectory("managed-disposed-intent-");
        var registry = CreateRegistry(data.Path);
        await using var manager = new GatewayConnectionManager(new CredentialResolver(DeviceIdentityFileReader.Instance),
            new CountingFactory(), registry, NullLogger.Instance);
        using var held = await manager.BeginManualGatewayLifecycleOperationAsync();
        using var intent = manager.CaptureConnectionIntent();
        var queued = manager.SwitchGatewayIfIntentCurrentAsync("ordinary-b", intent);
        intent.Dispose();
        Assert.False(await queued.WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.Equal("ordinary-a", registry.ActiveGatewayId);
    }

    [Fact]
    public async Task ConditionalSwitchRejectsAnotherManagerAndConsumedIntent()
    {
        using var data = new TempDirectory("managed-owner-intent-");
        var registry = CreateRegistry(data.Path);
        await using var first = new GatewayConnectionManager(new CredentialResolver(DeviceIdentityFileReader.Instance),
            new CountingFactory(), registry, NullLogger.Instance);
        await using var second = new GatewayConnectionManager(new CredentialResolver(DeviceIdentityFileReader.Instance),
            new CountingFactory(), registry, NullLogger.Instance);
        using var intent = first.CaptureConnectionIntent();
        Assert.False(await second.SwitchGatewayIfIntentCurrentAsync("ordinary-b", intent));
        Assert.False(intent.CancellationToken.IsCancellationRequested);
        Assert.True(await first.SwitchGatewayIfIntentCurrentAsync("ordinary-b", intent));
        Assert.True(intent.CancellationToken.IsCancellationRequested);
        Assert.False(await first.SwitchGatewayIfIntentCurrentAsync("ordinary-a", intent));
        Assert.Equal("ordinary-b", registry.ActiveGatewayId);
    }

    private static GatewayRegistry CreateRegistry(string path)
    {
        var registry = new GatewayRegistry(path);
        registry.AddOrUpdate(new GatewayRecord
        { Id = "ordinary-a", Url = "wss://ordinary-a.example/", SharedGatewayToken = "fixture-a" });
        registry.AddOrUpdate(new GatewayRecord
        { Id = "ordinary-b", Url = "wss://ordinary-b.example/", SharedGatewayToken = "fixture-b" });
        registry.SetActive("ordinary-a");
        registry.Save();
        return registry;
    }

    private sealed class DelayedIdentity : IManagedIdentity
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<ManagedAccessToken> Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public CancellationToken AuthenticationCancellation;
        public int InteractiveCalls;
        public Task<ManagedAccessToken> AcquireAsync(ManagedRemoteOptions options, bool interactive, CancellationToken ct)
        {
            if (!interactive)
                return Task.FromResult(new ManagedAccessToken("fixture-selected-human", DateTimeOffset.UtcNow.AddHours(1)));
            Interlocked.Increment(ref InteractiveCalls);
            AuthenticationCancellation = ct;
            Entered.TrySetResult();
            return Release.Task;
        }
        public Task SignOutAsync(ManagedRemoteOptions options, CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class CountingFactory : IGatewayClientFactory
    {
        public List<string> CreatedUrls { get; } = [];
        public IGatewayClientLifecycle Create(string url, GatewayCredential credential, string identityPath, IOpenClawLogger logger)
        {
            CreatedUrls.Add(url);
            return new GatewayConnectionManagerTests.MockLifecycle(url, identityPath);
        }
    }
}
