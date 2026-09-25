using System.Net;
using System.Net.Sockets;
using Proxify.Common.Networking;

namespace Proxify.SelfTest;

/// <summary>
/// Упрощённый сниффер для самопроверки.
/// </summary>
internal sealed class SniffSocket : IDisposable
{
    private readonly Socket _socket;
    private readonly Task<CapturedPacket?> _captureTask;

    public SniffSocket(IPAddress bindIp)
    {
        _socket = PlatformSockets.CreateSnifferSocket();

        _captureTask = Task.Run(ReceiveLoop);
    }

    public CapturedPacket? WaitForReply(ushort gamePort, TimeSpan timeout)
    {
        var result = _captureTask.WaitAsync(timeout).GetAwaiter().GetResult();
        return result;
    }

    private CapturedPacket? ReceiveLoop()
    {
        var buffer = new byte[65535];
        while (true)
        {
            EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            var received = _socket.ReceiveFrom(buffer, ref from);
            if (!Packets.TryParseUdp(buffer, received, out var srcIp, out var dstIp, out var srcPort, out var dstPort, out _))
                continue;

            if (!IPAddress.IsLoopback(srcIp))
                continue;

            return new CapturedPacket(srcIp, srcPort, dstIp, dstPort);
        }
    }

    public void Dispose() => _socket.Dispose();
}

internal sealed record CapturedPacket(IPAddress SourceIp, ushort SourcePort, IPAddress DestinationIp, ushort DestinationPort);