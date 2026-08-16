using System.Net;
using System.Net.Sockets;

namespace Proxify.Common;

public static class NetUtils
{
    /// <summary>
    /// Определяет первый не-loopback IPv4-адрес машины.
    /// </summary>
    public static IPAddress GetLocalIpv4()
    {
        try
        {
            foreach (var ip in Dns.GetHostAddresses(Dns.GetHostName()))
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
                    return ip;
            }
        }
        catch
        {
            // ignored
        }

        return IPAddress.Loopback;
    }

    /// <summary>
    /// Разбирает строку вида "ip:port" (поддерживаются и DNS-имена хостов).
    /// </summary>
    public static bool TryParseEndpoint(string? text, out IPEndPoint endpoint)
    {
        endpoint = null!;
        if (string.IsNullOrWhiteSpace(text))
            return false;

        var parts = text.Split(':');
        if (parts.Length != 2)
            return false;

        if (!IPAddress.TryParse(parts[0], out var ip))
        {
            // Хостнейм (например, имя сервиса docker-compose): резолвим через DNS.
            try
            {
                var resolved = Dns.GetHostAddresses(parts[0])
                    .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (resolved == null)
                    return false;
                ip = resolved;
            }
            catch (SocketException)
            {
                return false;
            }
        }

        if (!int.TryParse(parts[1], out var port) || port < 1 || port > 65535)
            return false;

        endpoint = new IPEndPoint(ip, port);
        return true;
    }

    /// <summary>
    /// Разбирает порт: целое число от 1 до 65535.
    /// </summary>
    public static bool TryParsePort(string? text, out int port)
    {
        if (int.TryParse(text, out var value) && value is >= 1 and <= 65535)
        {
            port = value;
            return true;
        }

        port = 0;
        return false;
    }

    /// <summary>
    /// Пытается разобрать булев флаг из строки.
    /// </summary>
    public static bool TryParseBool(string? text, bool defaultValue)
    {
        if (string.IsNullOrWhiteSpace(text))
            return defaultValue;
        return bool.TryParse(text, out var value) ? value : defaultValue;
    }
}
