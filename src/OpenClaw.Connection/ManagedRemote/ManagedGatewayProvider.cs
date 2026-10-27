using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using OpenClaw.Shared;

namespace OpenClaw.Connection;

/// <summary>Managed discovery and enrollment. Published client lifetime remains in the canonical manager.</summary>
public sealed class ManagedGatewayProvider : IManagedGatewayProvider, IDisposable
{
    private static readonly TimeSpan StartupTimeout = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan EnrollmentTimeout = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(2);
    private readonly GatewayRegistry _registry;
    private readonly IManagedIdentity _identity;
    private readonly HttpClient _http;
    private readonly NativeManagementApi _api;
    private readonly IManagedGatewayEnrollment _enrollment;
    private readonly TimeSpan _pollInterval;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private CancellationTokenSource _session = new();
    private bool _allowFreshEnrollment;
    private bool _signedOut;
    private readonly ConcurrentDictionary<string, byte> _rejectedCredentials = new(StringComparer.Ordinal);

    public ManagedGatewayProvider(GatewayRegistry registry, IManagedIdentity identity,
        HttpMessageHandler? handler = null, IManagedGatewayEnrollment? enrollment = null,
        TimeSpan? pollInterval = null)
    {
        _registry = registry;
        _identity = identity;
        _http = new HttpClient(handler ?? new HttpClientHandler { AllowAutoRedirect = false });
        _api = new NativeManagementApi(_http, identity);
        _enrollment = enrollment ?? new ManagedGatewayEnrollment(_api);
        _pollInterval = pollInterval ?? DefaultPollInterval;
    }

    public ManagedConnectionState State { get; private set; } = ManagedConnectionState.Disabled;
    public event EventHandler<ManagedConnectionState>? StateChanged;

    internal void SetState(ManagedConnectionState state)
    {
        State = state;
        StateChanged?.Invoke(this, state);
    }

    internal void RequireFreshEnrollment(string gatewayId)
    {
        _rejectedCredentials.TryAdd(gatewayId, 0);
        SetState(ManagedConnectionState.EnrollmentExpired);
    }

    public GatewayRecord EnsureProfile(ManagedRemoteOptions options) => EnsureProfile(options, select: true);

    internal GatewayRecord EnsureProfileForSignIn(ManagedRemoteOptions options) => EnsureProfile(options, select: false);

    private GatewayRecord EnsureProfile(ManagedRemoteOptions options, bool select)
    {
        var id = StableId(JsonSerializer.Serialize(options));
        var active = _registry.GetActive();
        var existing = active?.ManagedRemote?.Options == options ? active :
            _registry.GetAll().FirstOrDefault(r => r.ManagedRemote?.Options == options);
        var record = existing ?? new GatewayRecord
        {
            Id = id, Url = "", ManagedRemote = new ManagedRemoteProfile(options),
        };
        var changed = existing is null;
        if (existing is null) _registry.AddOrUpdate(record);
        if (select && (active is null || active.ManagedRemote is not null && active.ManagedRemote.Options != options))
        {
            _registry.SetActive(record.Id);
            changed = true;
        }
        if (changed) _registry.Save();
        if (State is ManagedConnectionState.Disabled or ManagedConnectionState.SetupRequired)
        {
            try { ManagedEndpointPolicy.ValidateIdentityConfiguration(options); SetState(ManagedConnectionState.SignInRequired); }
            catch (ManagedConnectionException ex) { SetState(ex.State); }
        }
        return record;
    }

    public async Task SignInAsync(ManagedRemoteOptions options, CancellationToken ct)
    {
        if (_signedOut)
        {
            _session.Dispose();
            _session = new CancellationTokenSource();
        }
        _signedOut = false;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _session.Token);
        SetState(ManagedConnectionState.SigningIn);
        try
        {
            await _identity.AcquireAsync(options, true, linked.Token).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            _allowFreshEnrollment = true;
            SetState(ManagedConnectionState.Discovering);
        }
        catch (ManagedConnectionException ex)
        {
            if (!_signedOut) SetState(ex.State);
            throw;
        }
    }

    public void RevokeSession()
    {
        _signedOut = true;
        _session.Cancel();
        SetState(ManagedConnectionState.SignedOut);
    }

    public async Task SignOutAsync(ManagedRemoteOptions options, CancellationToken ct)
    {
        RevokeSession();
        try { await _identity.SignOutAsync(options, ct).ConfigureAwait(false); }
        finally { SetState(ManagedConnectionState.SignedOut); }
    }

    public async Task<GatewayRecord> PrepareAsync(GatewayRecord record, CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _session.Token);
        await _gate.WaitAsync(linked.Token).ConfigureAwait(false);
        try
        {
            if (_signedOut) throw new ManagedConnectionException(ManagedConnectionState.SignInRequired);
            var options = record.ManagedRemote!.Options;
            var service = ManagedEndpointPolicy.ValidateConfiguration(options);
            SetState(ManagedConnectionState.Discovering);
            using var startup = CancellationTokenSource.CreateLinkedTokenSource(linked.Token);
            startup.CancelAfter(StartupTimeout);
            var discovery = await _api.DiscoverAsync(options, startup.Token).ConfigureAwait(false);
            if (discovery.State == "activationRequired")
            {
                SetState(ManagedConnectionState.Starting);
                await _api.StartAsync(options, _pollInterval, startup.Token).ConfigureAwait(false);
                discovery = await _api.DiscoverAsync(options, startup.Token).ConfigureAwait(false);
            }
            while (discovery.State == "starting")
            {
                SetState(ManagedConnectionState.Starting);
                await Task.Delay(_pollInterval, startup.Token).ConfigureAwait(false);
                discovery = await _api.DiscoverAsync(options, startup.Token).ConfigureAwait(false);
            }
            if (discovery.State != "ready")
                throw new ManagedConnectionException(discovery.State switch
                {
                    "notAssigned" => ManagedConnectionState.NotAssigned,
                    "offline" => ManagedConnectionState.Offline,
                    _ => ManagedConnectionState.Unavailable,
                });
            if (discovery.SchemaVersion != 1 || discovery.Gateway is null ||
                !IsBindingValue(discovery.ClawId) || !IsBindingValue(discovery.AssignmentVersion))
                throw new ManagedConnectionException(ManagedConnectionState.CompatibilityError);
            var url = ManagedEndpointPolicy.RequireServiceRoute(service, discovery.Gateway.WebSocketUrl,
                "/api/native/gateway", webSocket: true);
            var http = ManagedEndpointPolicy.RequireServiceRoute(service, discovery.Gateway.HttpBaseUrl, "/api/native/gateway");
            var enroll = ManagedEndpointPolicy.RequireServiceRoute(service, discovery.Gateway.EnrollmentUrl, "/api/native/enrollments");
            if (url.Query.Length != 0 || http.Query.Length != 0 || enroll.Query.Length != 0)
                throw new ManagedConnectionException(ManagedConnectionState.CompatibilityError);
            var id = StableId(JsonSerializer.Serialize(options) + "\n" + discovery.ClawId + "\n" + discovery.AssignmentVersion);
            var existing = _registry.GetById(id);
            var profile = new ManagedRemoteProfile(options, discovery.ClawId, discovery.AssignmentVersion,
                http.AbsoluteUri, enroll.AbsoluteUri, existing?.ManagedRemote?.EnrollmentAttempted ?? false);
            var bound = new GatewayRecord
            {
                Id = id, Url = url.AbsoluteUri, ManagedRemote = profile,
                FriendlyName = existing?.FriendlyName,
                LastConnected = existing?.LastConnected,
            };
            linked.Token.ThrowIfCancellationRequested();
            _registry.AddOrUpdate(bound);
            _registry.SetActive(id);
            _registry.Save();
            var identityDirectory = _registry.GetIdentityDirectory(id);
            var device = new DeviceIdentity(identityDirectory, NullLogger.Instance);
            device.Initialize();
            if (_rejectedCredentials.ContainsKey(id))
            {
                if (!_allowFreshEnrollment)
                    throw new ManagedConnectionException(ManagedConnectionState.EnrollmentExpired);
                if (!string.IsNullOrWhiteSpace(device.DeviceToken) &&
                    !DeviceIdentity.TryClearDeviceToken(identityDirectory, NullLogger.Instance))
                    throw new ManagedConnectionException(ManagedConnectionState.Unavailable);
                device.LoadExisting();
            }
            if (string.IsNullOrWhiteSpace(device.DeviceToken) || !ManagedOperatorGrant.IsReady(device.DeviceTokenScopes))
            {
                if (profile.EnrollmentAttempted && !_allowFreshEnrollment)
                    throw new ManagedConnectionException(ManagedConnectionState.EnrollmentExpired);
                _allowFreshEnrollment = false;
                bound = bound with { ManagedRemote = profile with { EnrollmentAttempted = true } };
                linked.Token.ThrowIfCancellationRequested();
                _registry.AddOrUpdate(bound);
                _registry.Save();
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(linked.Token);
                timeout.CancelAfter(EnrollmentTimeout);
                await _enrollment.EnrollAsync(bound, identityDirectory, CreateAuthentication(bound),
                    SetState, timeout.Token).ConfigureAwait(false);
                device.LoadExisting();
                if (string.IsNullOrWhiteSpace(device.DeviceToken) || !ManagedOperatorGrant.IsReady(device.DeviceTokenScopes))
                    throw new ManagedConnectionException(ManagedConnectionState.CompatibilityError);
                _rejectedCredentials.TryRemove(id, out _);
            }
            linked.Token.ThrowIfCancellationRequested();
            SetState(ManagedConnectionState.Connecting);
            return bound;
        }
        catch (ManagedConnectionException ex) { SetState(ex.State); throw; }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested && !_session.IsCancellationRequested)
        {
            SetState(ManagedConnectionState.Unavailable);
            throw new ManagedConnectionException(ManagedConnectionState.Unavailable);
        }
        catch (OperationCanceledException)
        {
            if (!_session.IsCancellationRequested) SetState(ManagedConnectionState.Offline);
            throw;
        }
        catch (HttpRequestException)
        {
            SetState(ManagedConnectionState.Unavailable);
            throw new ManagedConnectionException(ManagedConnectionState.Unavailable);
        }
        finally { _gate.Release(); }
    }

    public IGatewayTransportAuthentication CreateAuthentication(GatewayRecord record) =>
        new ManagedGatewayAuthentication(record, _identity, async ct =>
        {
            try
            {
                var current = await _api.DiscoverAsync(record.ManagedRemote!.Options, ct).ConfigureAwait(false);
                if (current.State != "ready" || current.ClawId != record.ManagedRemote.ClawId ||
                    current.AssignmentVersion != record.ManagedRemote.AssignmentVersion ||
                    !Uri.TryCreate(current.Gateway?.WebSocketUrl, UriKind.Absolute, out var socket) ||
                    socket != new Uri(record.Url) ||
                    !Uri.TryCreate(current.Gateway?.HttpBaseUrl, UriKind.Absolute, out var http) ||
                    http != new Uri(record.ManagedRemote.HttpBaseUrl!))
                    throw new ManagedConnectionException(ManagedConnectionState.StaleAssignment);
            }
            catch (ManagedConnectionException ex) { SetState(ex.State); throw; }
        }, _session.Token);

    private static bool IsBindingValue(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 512 &&
        !value.Any(c => char.IsControl(c) || c > 127);

    private static string StableId(string value) =>
        new Guid(SHA256.HashData(Encoding.UTF8.GetBytes(value)).AsSpan(0, 16)).ToString();

    public void Dispose()
    {
        _session.Cancel();
        _session.Dispose();
        _http.Dispose();
    }
}
