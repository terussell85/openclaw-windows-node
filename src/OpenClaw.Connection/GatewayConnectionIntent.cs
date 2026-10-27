namespace OpenClaw.Connection;

/// <summary>
/// Manager-bound authority for an asynchronous action. A newer connection intent
/// cancels this lease even when the active Gateway ID does not change.
/// </summary>
public sealed class GatewayConnectionIntent : IDisposable
{
    private readonly object _owner;
    private readonly long _epoch;
    private readonly CancellationTokenSource _cancellation;
    private int _disposed;

    internal GatewayConnectionIntent(object owner, long epoch, CancellationToken token)
    {
        _owner = owner;
        _epoch = epoch;
        _cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        CancellationToken = _cancellation.Token;
    }

    public CancellationToken CancellationToken { get; }

    internal bool Matches(object owner, long epoch) =>
        Volatile.Read(ref _disposed) == 0 && ReferenceEquals(_owner, owner) &&
        _epoch == epoch && !CancellationToken.IsCancellationRequested;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            try { _cancellation.Cancel(); }
            finally { _cancellation.Dispose(); }
        }
    }
}
