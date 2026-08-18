using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using Proxify.Client;
using Proxify.Common;

Console.OutputEncoding = Encoding.UTF8;

var cli = new ArgParser("Proxify.Client")
    .Add("server", "Адрес прокси-сервера (машина A): host или host:порт туннеля. Если порт не указан, используется --tunnel-port", shortName: 's')
    .Add("tunnel-port", "UDP-порт туннеля ПРОКСИ-СЕРВЕРА (машины A), если он не указан в --server", shortName: 't')
    .Add("local-port", "Локальный UDP-порт туннеля клиента. Если не задан, ОС выберет свободный (port 0). Полезно для файрволов.", shortName: 'l')
    .Add("key", "Путь к закрытому ключу клиента (PEM, PKCS#8). Создаётся командой --keygen", shortName: 'k')
    .Add("keygen", "Сгенерировать пару ключей в указанном каталоге (client-private.pem, client-public.pem) и выйти", shortName: 'g');

if (!cli.TryParse(args))
{
    Console.WriteLine($"[ошибка конфигурации] {cli.Error}");
    cli.PrintUsage();
    return 1;
}
if (cli.HelpRequested)
    return 0;

// --- Режим генерации ключей ---
var keygenDir = cli.Get("keygen");
if (!string.IsNullOrWhiteSpace(keygenDir))
{
    if (!TunnelKeys.TryGenerateKeyPair(keygenDir, out var privatePath, out var publicPath, out var keygenError))
    {
        Console.WriteLine($"[ошибка конфигурации] {keygenError}");
        return 1;
    }
    Console.WriteLine($"Закрытый ключ клиента : {privatePath}");
    Console.WriteLine($"Публичный ключ клиента: {publicPath}");
    Console.WriteLine("Передайте файл client-public.pem на машину A и укажите его в конфиге сервера.");
    Console.WriteLine("На машине A можно сгенерировать шаблон конфига:");
    Console.WriteLine("  Proxify.Server --configgen <каталог с client-public.pem>");
    return 0;
}

var serverText = cli.Get("server")!;
if (string.IsNullOrWhiteSpace(serverText))
{
    Console.WriteLine("[ошибка конфигурации] '--server' не может быть пустым (ожидается host или host:порт машины A).");
    cli.PrintUsage();
    return 1;
}

// Разбор host[:порт]. Порт может быть указан в --server или отдельным --tunnel-port.
var (serverHost, inlinePort) = SplitHostPort(serverText);
var tunnelPortText = inlinePort ?? cli.Get("tunnel-port");

if (string.IsNullOrWhiteSpace(tunnelPortText) ||
    !NetUtils.TryParsePort(tunnelPortText, out var tunnelPort))
{
    Console.WriteLine("[ошибка конфигурации] Не указан порт туннеля. Добавьте его к --server (host:порт) или задайте --tunnel-port.");
    cli.PrintUsage();
    return 1;
}

if (!NetUtils.TryParseEndpoint($"{serverHost}:{tunnelPort}", out var proxyServer))
{
    Console.WriteLine($"[ошибка конфигурации] Не удалось разрешить адрес прокси-сервера '{serverHost}'.");
    cli.PrintUsage();
    return 1;
}

var keyPath = cli.Get("key")!;
if (string.IsNullOrWhiteSpace(keyPath) || !File.Exists(keyPath))
{
    Console.WriteLine($"[ошибка конфигурации] Закрытый ключ не найден: '{keyPath}'. Создайте его командой --keygen.");
    cli.PrintUsage();
    return 1;
}

ECDsa identityKey;
try
{
    identityKey = TunnelKeys.ImportPrivatePem(File.ReadAllText(keyPath));
    Console.WriteLine($"[диагностика] Закрытый ключ загружен: {keyPath}");
}
catch (Exception ex)
{
    Console.WriteLine($"[ошибка конфигурации] Не удалось загрузить закрытый ключ '{keyPath}': {ex.Message}");
    return 1;
}

int? localPort = null;
var localPortText = cli.Get("local-port");
if (!string.IsNullOrWhiteSpace(localPortText))
{
    if (!NetUtils.TryParsePort(localPortText, out var lp))
    {
        Console.WriteLine($"[ошибка конфигурации] Неверный локальный порт '{localPortText}'.");
        return 1;
    }
    localPort = lp;
}

using var session = new ProxySession(proxyServer, identityKey, localPort);

try
{
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

/// <summary>
/// Разделяет "host[:порт]" на хост и порт. Возвращает порт только если он числовой.
/// </summary>
static (string Host, string? Port) SplitHostPort(string text)
{
    var idx = text.LastIndexOf(':');
    if (idx <= 0)
        return (text, null);

    var port = text[(idx + 1)..];
    if (port.Length > 0 && port.All(char.IsAsciiDigit))
        return (text[..idx], port);

    return (text, null);
}
