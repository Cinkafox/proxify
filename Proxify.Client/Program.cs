using System.Net.Sockets;
using System.Text;
using Proxify.Client.Cli;
using Proxify.Client.Sessions;
using Proxify.Common.Metrics;

Console.OutputEncoding = Encoding.UTF8;

var options = ClientCli.Parse(args);
if (options.Error != null)
{
    Console.WriteLine($"[ошибка конфигурации] {options.Error}");
    if (options.ShowUsage)
        ClientCli.CreateParser().PrintUsage();
    return 1;
}
if (options.HelpRequested)
    return 0;

// --- Режим генерации ключей ---
if (options.KeygenDir != null)
{
    var keygenError = ClientCli.GenerateKeys(options.KeygenDir);
    if (keygenError != null)
    {
        Console.WriteLine($"[ошибка конфигурации] {keygenError}");
        return 1;
    }
    return 0;
}

// Метрики Prometheus. Без --metrics-port экспорт не поднимается: счётчики
// накапливаются, но никто их не забирает.
using var metrics = new TunnelMetrics(MetricsRole.Client, perClientLabels: false);

var session = await ProxySession.CreateAsync(
    options.ProxyServer,
    options.IdentityKey,
    options.LocalPort,
    options.WireObfuscationMode,
    options.QuicServerName,
    metrics);
if (session == null)
    return 1;

using var exporter = TryStartExporter(metrics, options.MetricsPort);
using (session)
{
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
}

return 0;

// Поднимает экспорт метрик, если задан --metrics-port. Порт занят — предупреждение,
// а не отказ: прокси продолжает работать без метрик.
static MetricsExporter? TryStartExporter(TunnelMetrics metrics, int? metricsPort)
{
    try
    {
        return MetricsExporter.TryStart(metrics, metricsPort);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[warn] Метрики Prometheus выключены: {ex.Message}");
        return null;
    }
}