using OpenClaw.Shared;

namespace OpenClaw.Connection;

/// <summary>User intent and presentation seam. It never constructs a published Gateway client.</summary>
public sealed class ManagedRemoteConnectionService : IDisposable
{
    private readonly ManagedGatewayProvider _provider;
    private readonly IGatewayConnectionManager _manager;
    private readonly GatewayRegistry _registry;
    private readonly ManagedRemoteOptions _options;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly SemaphoreSlim _actions = new(1, 1);
    private int _disposed;

    public ManagedRemoteConnectionService(ManagedGatewayProvider provider, IGatewayConnectionManager manager,
        GatewayRegistry registry, ManagedRemoteOptions options)
    {
        _provider = provider;
        _manager = manager;
        _registry = registry;
        _options = options;
        _manager.StateChanged += OnConnectionStateChanged;
    }

    public ManagedConnectionState State => _provider.State;
    public bool CanSignIn => Volatile.Read(ref _disposed) == 0 &&
        ManagedEndpointPolicy.IsIdentityConfigured(_options);
    public event EventHandler<ManagedConnectionState>? StateChanged
    {
        add => _provider.StateChanged += value;
        remove => _provider.StateChanged -= value;
    }

    public void Initialize() => _provider.EnsureProfile(_options);

    public async Task SignInAndConnectAsync()
    {
        GatewayConnectionIntent? intent = null;
        CancellationTokenSource? action = null;
        var entered = false;
        try
        {
            if (Volatile.Read(ref _disposed) != 0) return;
            intent = _manager.CaptureConnectionIntent();
            if (intent is null)
            {
                _provider.SetState(ManagedConnectionState.Unavailable);
                return;
            }
            action = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, intent.CancellationToken);
            entered = await TryEnterActionAsync(action.Token).ConfigureAwait(false);
            if (!entered) return;
            var record = _provider.EnsureProfileForSignIn(_options);
            await _provider.SignInAsync(_options, action.Token).ConfigureAwait(false);
            action.Token.ThrowIfCancellationRequested();
            if (!ManagedEndpointPolicy.TryGetServiceOrigin(_options, out _))
            {
                _provider.SetState(ManagedConnectionState.ServiceSetupRequired);
                return;
            }
            if (!await _manager.SwitchGatewayIfIntentCurrentAsync(record.Id, intent, _lifetime.Token)
                .ConfigureAwait(false))
                SetObsoleteActionState();
        }
        catch (ManagedConnectionException) { /* Provider publishes the actionable typed state. */ }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested ||
            _provider.State == ManagedConnectionState.SignedOut) { }
        catch (OperationCanceledException) when (intent?.CancellationToken.IsCancellationRequested == true)
        {
            SetObsoleteActionState();
        }
        catch (Exception) { _provider.SetState(ManagedConnectionState.Unavailable); }
        finally
        {
            action?.Dispose();
            intent?.Dispose();
            if (entered) _actions.Release();
        }
    }

    private void SetObsoleteActionState()
    {
        if (_provider.State is ManagedConnectionState.SigningIn or ManagedConnectionState.Discovering)
            _provider.SetState(ManagedConnectionState.Offline);
    }

    public async Task SignOutAsync()
    {
        if (Volatile.Read(ref _disposed) != 0) return;
        // Cancel authentication and enrollment before waiting for the manager's operation gate.
        _provider.RevokeSession();
        if (!await TryEnterActionAsync().ConfigureAwait(false)) return;
        try
        {
            if (_registry.GetActive()?.ManagedRemote is not null)
                await _manager.DisconnectAsync().ConfigureAwait(false);
            await _provider.SignOutAsync(_options, _lifetime.Token).ConfigureAwait(false);
        }
        catch (ManagedConnectionException ex) { _provider.SetState(ex.State); }
        catch (Exception) { _provider.SetState(ManagedConnectionState.Unavailable); }
        finally { _actions.Release(); }
    }

    private void OnConnectionStateChanged(object? sender, GatewayConnectionSnapshot snapshot)
    {
        if (_registry.GetActive()?.ManagedRemote is null || State == ManagedConnectionState.SignedOut) return;
        if (snapshot.OperatorErrorKind == GatewayErrorKind.DeviceTokenMismatch &&
            snapshot.GatewayId is { } rejectedId)
        {
            _provider.RequireFreshEnrollment(rejectedId);
            return;
        }
        if (snapshot.OperatorState == RoleConnectionState.Connected)
            _provider.SetState(ManagedConnectionState.Ready);
        else if (snapshot.OperatorState == RoleConnectionState.Error &&
            State is ManagedConnectionState.Connecting or ManagedConnectionState.Ready)
            _provider.SetState(snapshot.OperatorErrorKind switch
            {
                GatewayErrorKind.ProtocolMismatch => ManagedConnectionState.CompatibilityError,
                GatewayErrorKind.Auth or GatewayErrorKind.ScopeMismatch or GatewayErrorKind.PairingRejected =>
                    ManagedConnectionState.AccessDenied,
                GatewayErrorKind.Network => ManagedConnectionState.Offline,
                _ => ManagedConnectionState.Unavailable,
            });
        else if (State == ManagedConnectionState.Ready)
            _provider.SetState(snapshot.OperatorState == RoleConnectionState.Connecting
                ? ManagedConnectionState.Connecting : ManagedConnectionState.Offline);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _manager.StateChanged -= OnConnectionStateChanged;
        _lifetime.Cancel();
        _provider.Dispose();
        _lifetime.Dispose();
    }

    private async Task<bool> TryEnterActionAsync(CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _disposed) != 0) return false;
        try
        {
            using var waiting = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
            await _actions.WaitAsync(waiting.Token).ConfigureAwait(false);
            if (Volatile.Read(ref _disposed) == 0) return true;
            _actions.Release();
            return false;
        }
        catch (OperationCanceledException) { return false; }
        catch (ObjectDisposedException) { return false; }
    }
}
