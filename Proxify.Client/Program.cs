using System.Net;
using System.Net.Sockets;
using System.Text;
using Proxify.Client;
using Proxify.Common;

Console.OutputEncoding = Encoding.UTF8;

var cli = new ArgParser("Proxify.Client")
    .Add("server", "IP или имя хоста прокси-сервера (машина A). Трафик туннеля уходит на его --tunnel-port", required: true, shortName: 's')
    .Add("tunnel-port", "UDP-порт туннеля ПРОКСИ-СЕРВЕРА (машины A); должен совпадать с --tunnel-port сервера", required: true, shortName: 't')
    .Add("game-ip", "IP игрового сервера, обычно 127.0.0.1", shortName: 'g', defaultValue: "127.0.0.1")
    .Add("game-port", "UDP-порт игрового сервера", defaultValue: "7777")
    .Add("capture", "Перехватывать ответы игрового сервера (true/false)", defaultValue: "true")
    .Add("aliases", "Добавлять IP клиентов в loopback-алиасы (true/false)", defaultValue: "true")
    .Add("key", "Ключ шифрования (одинаковый у сервера и клиента). Обязателен — кадры всегда шифруются AES-256-GCM", required: true, shortName: 'k');

if (!cli.TryParse(args))
{
    Console.WriteLine($"[ошибка конфигурации] {cli.Error}");
    cli.PrintUsage();
    return 1;
}
if (cli.HelpRequested)
    return 0;

var serverHost = cli.Get("server")!;
if (string.IsNullOrWhiteSpace(serverHost))
{
    Console.WriteLine("[ошибка конфигурации] '--server' не может быть пустым (ожидается IP или имя хоста машины A).");
    cli.PrintUsage();
    return 1;
}

if (!NetUtils.TryParsePort(cli.Get("tunnel-port"), out var tunnelPort))
{
    Console.WriteLine($"[ошибка конфигурации] '--tunnel-port {cli.Get("tunnel-port")}' не является допустимым (ожидается число от 1 до 65535).");
    cli.PrintUsage();
    return 1;
}

// Адрес прокси-сервера: хост из --server, порт туннеля из --tunnel-port.
if (!NetUtils.TryParseEndpoint($"{serverHost}:{tunnelPort}", out var proxyServer))
{
    Console.WriteLine($"[ошибка конфигурации] Не удалось разрешить адрес прокси-сервера '{serverHost}'.");
    cli.PrintUsage();
    return 1;
}

if (!IPAddress.TryParse(cli.Get("game-ip"), out var gameIp))
{
    Console.WriteLine($"[ошибка конфигурации] '--game-ip {cli.Get("game-ip")}' не является IP-адресом.");
    cli.PrintUsage();
    return 1;
}
if (gameIp.AddressFamily != AddressFamily.InterNetwork)
{
    Console.WriteLine("[ошибка конфигурации] '--game-ip' должен быть IPv4-адресом.");
    cli.PrintUsage();
    return 1;
}

if (!NetUtils.TryParsePort(cli.Get("game-port"), out var gamePort))
{
    Console.WriteLine($"[ошибка конфигурации] '--game-port {cli.Get("game-port")}' не является допустимым (ожидается число от 1 до 65535).");
    cli.PrintUsage();
    return 1;
}

if (!bool.TryParse(cli.Get("capture"), out var captureReplies))
{
    Console.WriteLine($"[ошибка конфигурации] '--capture {cli.Get("capture")}' должен быть true или false.");
    cli.PrintUsage();
    return 1;
}

if (!bool.TryParse(cli.Get("aliases"), out var loopbackAliases))
{
    Console.WriteLine($"[ошибка конфигурации] '--aliases {cli.Get("aliases")}' должен быть true или false.");
    cli.PrintUsage();
    return 1;
}

var key = cli.Get("key")!;
if (string.IsNullOrWhiteSpace(key))
{
    Console.WriteLine("[ошибка конфигурации] '--key' не может быть пустым.");
    cli.PrintUsage();
    return 1;
}

var cipher = TunnelCipher.FromPassphrase(key);

using var session = new ProxySession(proxyServer, gameIp, (ushort)gamePort, tunnelPort, captureReplies, loopbackAliases, cipher);

try
{
    var (handshakeOk, serverTcpEnabled) = await session.HandshakeAsync();
    session.ServerTcp.Set(serverTcpEnabled);
    await session.RunAsync();
}
catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
{
    Console.WriteLine($"[!] Недостаточно прав: {ex.Message}");
    if (OperatingSystem.IsWindows())
    {
        Console.WriteLine("[!] Создание RawSocket требует прав администратора.");
        Console.WriteLine("[!] Запустите консоль от имени администратора и повторите попытку.");
    }
    else
    {
        Console.WriteLine("[!] Создание RawSocket требует прав root или CAP_NET_RAW.");
        Console.WriteLine("[!] Запустите: sudo Proxify.Client ...");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"[!] Необработанная ошибка: {ex.Message}");
    Console.WriteLine(ex);
}

return 0;
