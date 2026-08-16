using System.Net;
using System.Net.Sockets;
using System.Text;
using Proxify.Common;
using Proxify.Server;

Console.OutputEncoding = Encoding.UTF8;

var cli = new ArgParser("Proxify.Server")
    .Add("port", "UDP-порт, на который подключаются клиенты игры", required: true, shortName: 'p')
    .Add("tunnel-port", "UDP-порт туннеля, на который прокси-клиент (машина B) шлёт кадры", required: true, shortName: 't')
    .Add("key", "Ключ шифрования (одинаковый у сервера и клиента). Обязателен — кадры всегда шифруются AES-256-GCM", required: true, shortName: 'k')
    .Add("tcp", "Проксировать TCP-трафик клиентов на игровой сервер (true/false). TCP-порт совпадает с --port", defaultValue: "false")
    .Add("client-ip", "Разрешить только этому IPv4 выступать прокси-клиентом (машина B). Без указания — сервер принимает первого аутентифицированного клиента и фиксирует его адрес", shortName: 'c');

if (!cli.TryParse(args))
{
    Console.WriteLine($"[ошибка конфигурации] {cli.Error}");
    cli.PrintUsage();
    return 1;
}
if (cli.HelpRequested)
    return 0;

if (!NetUtils.TryParsePort(cli.Get("port"), out var listenPort))
{
    Console.WriteLine($"[ошибка конфигурации] '--port {cli.Get("port")}' не является допустимым (ожидается число от 1 до 65535).");
    cli.PrintUsage();
    return 1;
}

if (!NetUtils.TryParsePort(cli.Get("tunnel-port"), out var tunnelPort))
{
    Console.WriteLine($"[ошибка конфигурации] '--tunnel-port {cli.Get("tunnel-port")}' не является допустимым (ожидается число от 1 до 65535).");
    cli.PrintUsage();
    return 1;
}

if (tunnelPort == listenPort)
{
    Console.WriteLine("[ошибка конфигурации] '--tunnel-port' не может совпадать с '--port'.");
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

if (!bool.TryParse(cli.Get("tcp"), out var tcpEnabled))
{
    Console.WriteLine($"[ошибка конфигурации] '--tcp {cli.Get("tcp")}' должен быть true или false.");
    cli.PrintUsage();
    return 1;
}

IPAddress? allowedClientIp = null;
var clientIpText = cli.Get("client-ip");
if (!string.IsNullOrWhiteSpace(clientIpText))
{
    if (!IPAddress.TryParse(clientIpText, out allowedClientIp) || allowedClientIp.AddressFamily != AddressFamily.InterNetwork)
    {
        Console.WriteLine($"[ошибка конфигурации] '--client-ip {clientIpText}' не является IPv4-адресом.");
        cli.PrintUsage();
        return 1;
    }
}

var cipher = TunnelCipher.FromPassphrase(key);

using var session = new ProxySession(listenPort, tunnelPort, tcpEnabled, allowedClientIp, cipher);
using var statsTimer = new Timer(_ => session.Stats.Print("прокси-сервер"), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));

session.PrintBanner();

try
{
    await session.RunAsync();
}
catch (Exception ex)
{
    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] {ex.Message}");
}

return 0;
