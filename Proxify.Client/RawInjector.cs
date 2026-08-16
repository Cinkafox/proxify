using System.Net;
using System.Net.Sockets;
using Proxify.Common;

namespace Proxify.Client;

/// <summary>
/// Отправка «сырых» IPv4/UDP-пакетов игровому серверу с подменённым исходным IP.
/// Реальный IP клиента берётся из поля Source адресного заголовка.
///
/// Windows отбросит пакет, если исходный адрес не назначен ни одному интерфейсу,
/// поэтому перед инжектом адрес клиента должен быть добавлен в loopback-алиасы
/// (см. LoopbackAliasManager). Linux принимает пакеты с произвольным source,
/// алиасы нужны только для возврата ответов сервера.
/// Требуются права администратора / root (CAP_NET_RAW).
/// </summary>
public sealed class RawInjector : IDisposable
{
    private readonly Socket _socket;
    private readonly IPAddress _gameIp;
    private readonly ushort _gamePort;
    private readonly object _sendLock = new();
    private ushort _ipId;

    public RawInjector(IPAddress gameIp, ushort gamePort)
    {
        _gameIp = gameIp;
        _gamePort = gamePort;

        if (OperatingSystem.IsWindows())
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        }
        else
        {
            // Linux: raw-сокет протокола IPPROTO_RAW (255) — позволяет отправлять
            // IP-пакеты любого протокола с произвольным (в т.ч. чужим) source.
            // SOCK_RAW + IPPROTO_IP (0) на Linux недопустим (EPROTONOSUPPORT).
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Raw);
            _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
        }
    }

    public void Inject(IPAddress clientIp, ushort clientPort, ReadOnlySpan<byte> payload)
    {
        ushort id;
        lock (_sendLock)
        {
            id = ++_ipId;
        }

        var packet = Packets.BuildIpv4Udp(clientIp, _gameIp, clientPort, _gamePort, payload, id);

        try
        {
            _socket.SendTo(packet, new IPEndPoint(_gameIp, 0));
        }
        catch (SocketException ex)
        {
            Console.WriteLine($"[inject] Ошибка отправки пакета для {clientIp}:{clientPort}: {ex.Message} ({ex.SocketErrorCode})");
        }
    }

    public void Dispose()
    {
        _socket.Dispose();
    }
}
