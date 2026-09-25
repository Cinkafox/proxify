using System.Text;
using Proxify.Server.Cli;
using Proxify.Server.Core;

Console.OutputEncoding = Encoding.UTF8;

var options = ServerCli.Parse(args);
if (options.Error != null)
{
    Console.WriteLine($"[ошибка конфигурации] {options.Error}");
    if (options.ShowUsage)
        ServerCli.CreateParser().PrintUsage();
    return 1;
}
if (options.HelpRequested)
    return 0;

// --- Режим генерации шаблона конфига ---
if (options.ConfiggenDir != null)
{
    var genError = ServerCli.GenerateTemplate(options.ConfiggenDir);
    if (genError != null)
    {
        Console.WriteLine($"[ошибка конфигурации] {genError}");
        return 1;
    }
    return 0;
}

using var server = new ProxyServer(options.Clients, options.TunnelPort);
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