using System.Text;
using Proxify.Common.Metrics;
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

// Метрики Prometheus. Без --metrics-port экспорт не поднимается: счётчики
// накапливаются, но никто их не забирает.
using var metrics = new TunnelMetrics(MetricsRole.Server, perClientLabels: true);

MetricsExporter? exporter;
try
{
    exporter = MetricsExporter.TryStart(metrics, options.MetricsPort);
}
catch (Exception ex)
{
    Console.WriteLine($"[ошибка конфигурации] {ex.Message}");
    return 1;
}

using (exporter)
using (var server = new ProxyServer(options.Clients, options.TunnelPort, metrics))
{
    server.PrintBanner();

    try
    {
        await server.RunAsync();
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] {ex.Message}");
    }
}

return 0;
