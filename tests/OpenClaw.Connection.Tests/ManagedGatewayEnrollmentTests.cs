using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using OpenClaw.Shared;
using OpenClaw.TestSupport;

namespace OpenClaw.Connection.Tests;

public sealed class ManagedGatewayEnrollmentTests
{
    // Independent pinned Gateway v2026.9.4 scope-upgrade contract.
    private static readonly string[] FinalScopes =
    [
        "operator.admin", "operator.pairing", "operator.read", "operator.write",
        "operator.approvals", "operator.questions", "operator.talk.secrets",
    ];

    [Fact]
    public async Task LimitedOperatorPairsExactRequestThenWaitsForIdentityBoundRotatedOwnerGrant()
    {
        using var data = new TempDirectory();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var reserve = new TcpListener(IPAddress.Loopback, 0);
        reserve.Start();
        var port = ((IPEndPoint)reserve.LocalEndpoint).Port;
        reserve.Stop();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();
        var url = $"ws://127.0.0.1:{port}/";
        var enrollmentId = Guid.NewGuid().ToString();
        var approved = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stages = new List<string>();
        string? deviceId = null;
        string? publicKey = null;
        var initialApproved = false;

        using var http = new HttpClient(new ManagedRemoteConnectionTests.Handler(request =>
        {
            Assert.Equal("Bearer human-1", request.Headers.Authorization!.ToString());
            Assert.Equal("claw-1", request.Headers.GetValues("X-Claw-Id").Single());
            Assert.Equal("generation-1", request.Headers.GetValues("X-Claw-Assignment-Version").Single());
            using var body = JsonDocument.Parse(request.Content!.ReadAsStringAsync(deadline.Token).GetAwaiter().GetResult());
            if (request.RequestUri!.AbsolutePath == "/api/native/enrollments")
            {
                deviceId = body.RootElement.GetProperty("deviceId").GetString();
                publicKey = body.RootElement.GetProperty("publicKey").GetString();
                var code = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
                { url, bootstrapToken = "fixture-limited-bootstrap" })));
                return ManagedRemoteConnectionTests.Json(new NativeEnrollment(
                    1, enrollmentId, "claw-1", "generation-1", code,
                    DateTimeOffset.UtcNow.AddMinutes(2), ["operator.read"], FinalScopes));
            }
            Assert.Equal($"/api/native/enrollments/{enrollmentId}/approve", request.RequestUri.AbsolutePath);
            var stage = body.RootElement.GetProperty("stage").GetString()!;
            var id = body.RootElement.GetProperty("requestId").GetString();
            stages.Add(stage);
            Assert.Equal(stage == "initial" ? "exact-initial-1" : "exact-admin-1", id);
            if (stage == "initial") initialApproved = true;
            else approved.TrySetResult();
            return ManagedRemoteConnectionTests.Json(new NativeApproval(1, enrollmentId, stage, true));
        }));
        var api = new NativeManagementApi(http, new ManagedRemoteConnectionTests.Identity());
        var record = new GatewayRecord
        {
            Id = Guid.NewGuid().ToString(), Url = url,
            ManagedRemote = new ManagedRemoteProfile(ManagedRemoteConnectionTests.Options,
                "claw-1", "generation-1", "https://service.example/api/native/gateway",
                "https://service.example/api/native/enrollments"),
        };
        var protocol = Task.Run(async () =>
        {
            for (var connection = 0; connection < 2; connection++)
            {
                var context = await listener.GetContextAsync().WaitAsync(deadline.Token);
                Assert.Equal("Bearer fixture-human-header", context.Request.Headers["Authorization"]);
                using var socket = (await context.AcceptWebSocketAsync(null)).WebSocket;
                await Send(socket, new { type = "event", @event = "connect.challenge",
                    payload = new { nonce = "fixture-nonce", ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() } }, deadline.Token);
                var connect = await Receive(socket, deadline.Token);
                var parameters = connect.GetProperty("params");
                Assert.Equal("cli", parameters.GetProperty("client").GetProperty("id").GetString());
                Assert.Equal("cli", parameters.GetProperty("client").GetProperty("mode").GetString());
                Assert.Equal("operator", parameters.GetProperty("role").GetString());
                Assert.Equal(new[] { "operator.read" }, parameters.GetProperty("scopes").EnumerateArray().Select(s => s.GetString()));
                Assert.Equal(deviceId, parameters.GetProperty("device").GetProperty("id").GetString());
                Assert.Equal(publicKey, parameters.GetProperty("device").GetProperty("publicKey").GetString());
                Assert.False(string.IsNullOrWhiteSpace(parameters.GetProperty("device").GetProperty("signature").GetString()));
                Assert.Equal("fixture-limited-bootstrap", parameters.GetProperty("auth").GetProperty("bootstrapToken").GetString());
                var id = connect.GetProperty("id").GetString();
                if (connection == 0)
                {
                    await Send(socket, new { type = "res", id, ok = false,
                        error = new { code = "NOT_PAIRED", message = "pairing required",
                            details = new { code = "PAIRING_REQUIRED", requestId = "exact-initial-1" } } }, deadline.Token);
                    // Disposal of this failed staged client closes the first socket.
                    continue;
                }
                Assert.True(initialApproved);
                await Send(socket, new { type = "res", id, ok = true,
                    payload = new { type = "hello-ok", protocol = 4,
                        auth = new { role = "operator", deviceToken = "fixture-read-token", scopes = new[] { "operator.read" } } } }, deadline.Token);
                var upgrade = await Receive(socket, deadline.Token);
                Assert.Equal("device.scopes.requestUpgrade", upgrade.GetProperty("method").GetString());
                Assert.Equal(FinalScopes, upgrade.GetProperty("params").GetProperty("scopes").EnumerateArray().Select(s => s.GetString()));
                await Send(socket, new { type = "res", id = upgrade.GetProperty("id").GetString(), ok = true,
                    payload = new { requestId = "exact-admin-1" } }, deadline.Token);
                var wait = await Receive(socket, deadline.Token);
                Assert.Equal("device.scopes.waitUpgrade", wait.GetProperty("method").GetString());
                Assert.Equal("exact-admin-1", wait.GetProperty("params").GetProperty("requestId").GetString());
                await approved.Task.WaitAsync(deadline.Token);
                await Send(socket, new { type = "res", id = wait.GetProperty("id").GetString(), ok = true,
                    payload = new { status = "approved", requestId = "exact-admin-1",
                        deviceToken = "fixture-rotated-owner-token", scopes = FinalScopes } }, deadline.Token);
                // Keep the accepted transport alive until the client disposes it.
                var buffer = new byte[1024];
                try { await socket.ReceiveAsync(buffer.AsMemory(), deadline.Token); }
                catch (WebSocketException) { }
            }
        }, deadline.Token);
        var states = new List<ManagedConnectionState>();
        await new ManagedGatewayEnrollment(api).EnrollAsync(record, data.Path,
            new FixtureAdmission(), states.Add, deadline.Token);
        await protocol.WaitAsync(deadline.Token);
        var identity = new DeviceIdentity(data.Path);
        identity.LoadExisting();
        Assert.Equal(deviceId, identity.DeviceId);
        Assert.Equal("fixture-rotated-owner-token", identity.DeviceToken);
        Assert.Equal(FinalScopes.Order(), identity.DeviceTokenScopes!.Order());
        Assert.Null(identity.NodeDeviceToken);
        Assert.Equal(new[] { "initial", "admin" }, stages);
        Assert.Equal(new[] { ManagedConnectionState.Enrolling, ManagedConnectionState.Approving, ManagedConnectionState.Upgrading }, states);
        Assert.DoesNotContain("fixture-limited-bootstrap", File.ReadAllText(data.Combine("device-key-ed25519.json")));
    }

    private sealed class FixtureAdmission : IGatewayTransportAuthentication
    {
        public Uri HttpBaseUri => new("https://service.example/api/native/gateway");
        public Task<IReadOnlyDictionary<string, string>> GetHeadersAsync(Uri target, CancellationToken ct) =>
            Task.FromResult<IReadOnlyDictionary<string, string>>(new Dictionary<string, string>
            { ["Authorization"] = "Bearer fixture-human-header" });
    }

    private static Task Send(WebSocket socket, object value, CancellationToken ct) =>
        socket.SendAsync(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value)),
            WebSocketMessageType.Text, true, ct);

    private static async Task<JsonElement> Receive(WebSocket socket, CancellationToken ct)
    {
        var bytes = new byte[16 * 1024];
        var result = await socket.ReceiveAsync(bytes.AsMemory(), ct);
        Assert.True(result.EndOfMessage);
        using var json = JsonDocument.Parse(bytes.AsMemory(0, result.Count));
        return json.RootElement.Clone();
    }
}
