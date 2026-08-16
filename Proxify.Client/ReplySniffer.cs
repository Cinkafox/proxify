using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Proxify.Common;

namespace Proxify.Client;

/// <summary>
/// Перехват ответов игрового сервера «сырым» сокетом.
///
/// Windows: SIO_RCVALL на loopback-интерфейсе. Linux: raw IP-сокет протокола UDP.
/// После добавления IP реального клиента в loopback-алиасы ответы игрового сервера
/// на этот IP маршрутизируются в loopback, где попадают в данный сокет.
/// Ответ заворачивается в туннельный кадр и отправляется прокси-серверу, который
/// доставляет его реальному клиенту. Требуются права администратора / root.
///
/// Сессионный ключ может меняться при повторной авторизации, поэтому шифрование
/// запрашивается через <see cref="Func{TunnelCipher}"/>.
/// </summary>
public sealed class ReplySniffer : IDisposable
{
    private readonly Socket _socket;
    private readonly ConcurrentDictionary<IPEndPoint, DateTime> _knownClients;
    private readonly ushort _gamePort;
    private readonly UdpClient _tunnel;
    private readonly IPEndPoint _proxyServer;
    private readonly Func<TunnelCipher?> _cipherGetter;
    private readonly TunnelStats _stats;
    private readonly CancellationToken _cancellationToken;
    private readonly byte[] _buffer = new byte[65535];

    public ReplySniffer(
        IPAddress bindIp,
        ushort gamePort,
        ConcurrentDictionary<IPEndPoint, DateTime> knownClients,
        UdpClient tunnel,
        IPEndPoint proxyServer,
        Func<TunnelCipher?> cipherGetter,
        TunnelStats stats,
        CancellationToken cancellationToken)
    {
        _knownClients = knownClients;
        _gamePort = gamePort;
        _tunnel = tunnel;
        _proxyServer = proxyServer;
        _cipherGetter = cipherGetter;
        _stats = stats;
        _cancellationToken = cancellationToken;

        _socket = PlatformSockets.CreateSnifferSocket();

        Console.WriteLine($"[sniff] Перехват ответов на loopback включён");
    }

    public void Run()
    {
        while (!_cancellationToken.IsCancellationRequested)
        {
            EndPoint from = new IPEndPoint(IPAddress.Any, 0);

            int received;
            try
            {
                received = _socket.ReceiveFrom(_buffer, ref from);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
            {
                continue;
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"[sniff] Ошибка приёма: {ex.Message}");
                continue;
            }
            catch
            {
                break;
            }

            if (!Packets.TryParseUdp(_buffer, received, out var srcIp, out var dstIp, out var srcPort, out var dstPort, out var payload))
                continue;

            // Ответ игрового сервера: source port = порт игры. Источник не обязан быть
            // loopback: на Linux, когда IP клиента добавлен на lo, адрес ответа сервера
            // (source) совпадает с этим IP, а не с 127.0.0.1.
            if (srcPort != _gamePort)
                continue;

            var client = new IPEndPoint(dstIp, dstPort);
            if (!_knownClients.ContainsKey(client))
                continue;

            Interlocked.Increment(ref _stats.RepliesCaptured);
            var cipher = _cipherGetter();
            if (cipher == null)
                continue;
            var frame = Frame.EncodeData(dstIp, dstPort, payload, cipher);

            try
            {
                _tunnel.Send(frame, _proxyServer);
                Interlocked.Increment(ref _stats.PacketsOut);
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"[sniff] Ошибка отправки прокси-серверу: {ex.Message}");
            }
        }
    }

    public void Dispose()
    {
        _socket.Dispose();
    }
}
