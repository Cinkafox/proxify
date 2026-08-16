using System.Net;
using System.Net.Sockets;

namespace Proxify.Common;

/// <summary>
/// Создание платформенно-зависимых «сырых» сокетов.
/// </summary>
public static class PlatformSockets
{
    private const int SioRcvall = unchecked((int)0x98000001);

    /// <summary>
    /// Создаёт сокет для перехвата ответов игрового сервера.
    ///
    /// Windows: raw IP-сокет с опцией SIO_RCVALL на loopback-интерфейсе.
    /// Linux: raw IP-сокет протокола UDP (SOCK_RAW + IPPROTO_UDP) — получает копии
    /// всех UDP-датаграмм хоста, включая loopback. Алиасы клиентских IP не нужны:
    /// Linux принимает пакеты с произвольным source, а ответы сервера маршрутизируются
    /// в loopback благодаря адресу, добавленному на lo (см. LoopbackAliasManager).
    ///
    /// В обоих случаях Receive отдаёт полный IPv4-пакет (заголовок + UDP).
    /// Требуются права администратора (Windows) / root или CAP_NET_RAW (Linux).
    /// </summary>
    public static Socket CreateSnifferSocket()
    {
        if (OperatingSystem.IsWindows())
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            socket.ReceiveTimeout = 500;
            socket.IOControl(SioRcvall, BitConverter.GetBytes(1), null);
            return socket;
        }

        var raw = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
        raw.ReceiveTimeout = 500;
        // На Linux Socket.ReceiveFrom требует, чтобы сокет был привязан.
        // 0.0.0.0:0 не фильтрует адреса — получаем все UDP-датаграммы хоста.
        raw.Bind(new IPEndPoint(IPAddress.Any, 0));
        return raw;
    }
}
