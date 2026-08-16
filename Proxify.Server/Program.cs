using System.Text;
using Proxify.Common;
using Proxify.Server;

Console.OutputEncoding = Encoding.UTF8;

var cli = new ArgParser("Proxify.Server")
    .Add("config", "Путь к JSON-конфигу с клиентами (порт, публичный ключ, игровые параметры)", shortName: 'c')
    .Add("tunnel-port", "UDP-порт туннеля, на который прокси-клиенты (машина B) шлют кадры", shortName: 't')
    .Add("configgen", "Сгенерировать шаблон server.json из client-public.pem в указанном каталоге и выйти", shortName: 'g');

if (!cli.TryParse(args))
{
    Console.WriteLine($"[ошибка конфигурации] {cli.Error}");
    cli.PrintUsage();
    return 1;
}
if (cli.HelpRequested)
    return 0;

// --- Режим генерации конфига ---
var configgenDir = cli.Get("configgen");
if (!string.IsNullOrWhiteSpace(configgenDir))
{
    if (!ServerConfig.TryGenerateTemplate(configgenDir, out var path, out var genError))
    {
        Console.WriteLine($"[ошибка конфигурации] {genError}");
        return 1;
    }
    Console.WriteLine($"Сгенерирован шаблон конфига: {path}");
    Console.WriteLine("Отредактируйте порт/игровые параметры при необходимости и запустите сервер с --config.");
    return 0;
}

if (!NetUtils.TryParsePort(cli.Get("tunnel-port"), out var tunnelPort))
{
    Console.WriteLine($"[ошибка конфигурации] '--tunnel-port {cli.Get("tunnel-port")}' не является допустимым (ожидается число от 1 до 65535).");
    cli.PrintUsage();
    return 1;
}
var configPath = cli.Get("config");
if (string.IsNullOrWhiteSpace(configPath))
{
    Console.WriteLine("[ошибка конфигурации] Не задан '--config'. Используйте --configgen, чтобы создать шаблон, или укажите путь к конфигу.");
    cli.PrintUsage();
    return 1;
}
if (!ServerConfig.TryLoad(configPath, out var clients, out var configError))
{
    Console.WriteLine($"[ошибка конфигурации] {configError}");
    return 1;
}

foreach (var client in clients)
{
    if (tunnelPort == client.Port || (client.TcpEnabled && tunnelPort == client.TcpPort))
    {
        Console.WriteLine($"[ошибка конфигурации] '--tunnel-port {tunnelPort}' совпадает с портом клиента '{client.DisplayName()}' — конфликт.");
        return 1;
    }
}

using var server = new ProxyServer(clients, tunnelPort);
using var statsTimer = new Timer(_ => server.Stats.Print("прокси-сервер"), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));

server.PrintBanner();

try
{
    await server.RunAsync();
}
catch (Exception ex)
{
    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] {ex.Message}");
}

return 0;

internal static class ConfigExtensions
{
    public static string DisplayName(this ClientConfig config)
        => string.IsNullOrWhiteSpace(config.Name) ? "(без имени)" : config.Name;
}
