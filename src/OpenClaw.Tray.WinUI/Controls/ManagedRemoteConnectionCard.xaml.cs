using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using OpenClaw.Connection;
using OpenClaw.Shared;
using OpenClawTray.Helpers;

namespace OpenClawTray.Controls;

public sealed partial class ManagedRemoteConnectionCard : UserControl
{
    private ManagedRemoteConnectionService? _service;
    public ManagedRemoteConnectionCard()
    {
        InitializeComponent();
        Unloaded += (_, _) =>
        {
            if (_service is not null) _service.StateChanged -= OnStateChanged;
            _service = null;
        };
    }

    public void Initialize(ManagedRemoteConnectionService? service)
    {
        if (_service is not null) _service.StateChanged -= OnStateChanged;
        _service = service;
        Visibility = Visibility.Visible;
        if (service is null)
        {
            Apply(ManagedConnectionState.SetupRequired);
            return;
        }
        service.StateChanged += OnStateChanged;
        Apply(service.State);
    }

    private void OnStateChanged(object? sender, ManagedConnectionState state) =>
        DispatcherQueue.TryEnqueue(() =>
        {
            if (_service?.State == state) Apply(state);
        });

    private void Apply(ManagedConnectionState state)
    {
        StatusText.Text = LocalizationHelper.GetString("ManagedRemote_State_" + state);
        ConnectButton.IsEnabled = _service?.CanSignIn == true && state is not (
            ManagedConnectionState.SigningIn or ManagedConnectionState.Discovering or
            ManagedConnectionState.Starting or ManagedConnectionState.Enrolling or
            ManagedConnectionState.Approving or ManagedConnectionState.Upgrading or
            ManagedConnectionState.Connecting);
    }

    private void OnConnect(object sender, RoutedEventArgs e)
    {
        if (_service is { } service)
            AsyncEventHandlerGuard.Run(service.SignInAndConnectAsync, new AppLogger(), nameof(OnConnect));
    }

}
