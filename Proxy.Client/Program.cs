using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Proxify.Client;
using Proxify.Common;

Console.OutputEncoding = Encoding.UTF8;

PrintUsage();

IPEndPoint proxyServer = NetUtils.TryParseEndpoint(args.Length > 0 ? args[0] : null, out var ps)
    ? ps
    : new IPEndPoint(IPAddress.Loopback, 27015);

IPAddress gameIp = args.Length > 1 && IPAddress.TryParse(args[1], out var gi)
    ? gi
    : IPAddress.Loopback;

int gamePort = args.Length > 2 && int.TryParse(args[2], out int gp) && gp is >= 1 and <= 65535
    ? gp
    : 7777;

int tunnelBindPort = args.Length > 3 && int.TryParse(args[3], out int tp) && tp is >= 1 and <= 65535
    ? tp
    : 5600;

bool captureReplies = NetUtils.TryParseBool(args.Length > 4 ? args[4] : null, true);
bool loopbackAliases = NetUtils.TryParseBool(args.Length > 5 ? args[5] : null, true);

string? key = args.Length > 6 ? args[6] : null;
TunnelCipher? cipher = string.IsNullOrEmpty(key) ? null : TunnelCipher.FromPassphrase(key);

Console.WriteLine("=== Прокси-клиент (RealIP) ===");
Console.WriteLine($"Прокси-сервер (машина A) : {proxyServer}");
Console.WriteLine($"Игровой сервер (локально): {gameIp}:{gamePort}");
Console.WriteLine($"Порт туннеля            : {tunnelBindPort}");
Console.WriteLine($"Перехват ответов       : {(captureReplies ? "вкл" : "выкл")}");
Console.WriteLine($"Loopback-алиасы        : {(loopbackAliases ? "вкл" : "выкл")}");
Console.WriteLine($"Шифрование туннеля      : {(cipher != null ? "вкл (AES-256-GCM)" : "выкл")}");
Console.WriteLine();

try
{
    await RunAsync(proxyServer, gameIp, (ushort)gamePort, tunnelBindPort, captureReplies, loopbackAliases, cipher);
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
        Console.WriteLine("[!] Запустите: sudo Proxy.Client ...");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"[!] Необработанная ошибка: {ex.Message}");
    Console.WriteLine(ex);
}

static void PrintUsage()
{
    Console.WriteLine("Прокси-клиент: принимает трафик от прокси-сервера и впрыскивает его");
    Console.WriteLine("в локальный игровой UDP-сервер с подменённым (настоящим) IP клиента,");
    Console.WriteLine("используя RawSocket. Ответы сервера перехватываются и возвращаются");
    Console.WriteLine("клиенту через прокси-сервер.");
    Console.WriteLine();
    Console.WriteLine("Использование: Proxy.Client [proxyServerIp:proxyServerPort] [gameIp] [gamePort]");
    Console.WriteLine("                        [tunnelBindPort] [captureReplies] [loopbackAliases] [key]");
    Console.WriteLine("  proxyServerIp:port - адрес прокси-сервера на машине A (по умолч. 127.0.0.1:27015)");
    Console.WriteLine("  gameIp             - IP игрового сервера, обычно 127.0.0.1 (по умолч. 127.0.0.1)");
    Console.WriteLine("  gamePort           - UDP-порт игрового сервера (по умолч. 7777)");
    Console.WriteLine("  tunnelBindPort     - локальный порт туннеля (по умолч. 5600)");
    Console.WriteLine("  captureReplies     - перехватывать ответы сервера (true/false, по умолч. true)");
    Console.WriteLine("  loopbackAliases    - добавлять IP клиентов в loopback-алиасы (true/false, по умолч. true)");
    Console.WriteLine("  key                - ключ шифрования (одинаковый у сервера и клиента). Если задан -");
    Console.WriteLine("                       кадры туннеля шифруются AES-256-GCM; если нет - без шифрования.");
    Console.WriteLine();
    Console.WriteLine("ВАЖНО: требуются права администратора (Windows) / root (Linux).");
    Console.WriteLine("Игровой сервер должен быть");
    Console.WriteLine("привязан к 0.0.0.0:{gamePort} (или 127.0.0.1:{gamePort}), чтобы видеть");
    Console.WriteLine("подменённые пакеты с настоящими IP клиентов.");
    Console.WriteLine();
}

static async Task RunAsync(
    IPEndPoint proxyServer,
    IPAddress gameIp,
    ushort gamePort,
    int tunnelBindPort,
    bool captureReplies,
    bool loopbackAliases,
    TunnelCipher? cipher)
{
    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) =>
    {
        e.Cancel = true;
        cts.Cancel();
    };

    var knownClients = new ConcurrentDictionary<IPEndPoint, DateTime>();
    var activeIps = new ConcurrentDictionary<IPAddress, DateTime>();

    var aliases = new LoopbackAliasManager(loopbackAliases);
    using var injector = new RawInjector(gameIp, gamePort);
    using var tunnel = new UdpClient(new IPEndPoint(IPAddress.Any, tunnelBindPort));

    ReplySniffer? sniffer = null;
    var tasks = new List<Task>
    {
        Task.Run(() => ReceiveLoop(tunnel, aliases, injector, knownClients, activeIps, cipher, cts.Token))
    };

    if (captureReplies)
    {
        sniffer = new ReplySniffer(IPAddress.Loopback, gamePort, knownClients, tunnel, proxyServer, cipher, cts.Token);
        tasks.Add(Task.Run(sniffer.Run));
    }

    tasks.Add(Task.Run(() => CleanupLoop(aliases, knownClients, activeIps, cts.Token)));

    Console.WriteLine("Ожидание кадров от прокси-сервера...");
    Console.WriteLine("Нажмите Ctrl+C для остановки.");
    Console.WriteLine();

    try
    {
        await Task.WhenAll(tasks);
    }
    catch (OperationCanceledException)
    {
        // плановое завершение
    }
    finally
    {
        sniffer?.Dispose();
        aliases.Dispose();
        Console.WriteLine("Прокси-клиент остановлен.");
    }
}

static async Task ReceiveLoop(
    UdpClient tunnel,
    LoopbackAliasManager aliases,
    RawInjector injector,
    ConcurrentDictionary<IPEndPoint, DateTime> knownClients,
    ConcurrentDictionary<IPAddress, DateTime> activeIps,
    TunnelCipher? cipher,
    CancellationToken ct)
{
    while (!ct.IsCancellationRequested)
    {
        UdpReceiveResult result;
        try
        {
            result = await tunnel.ReceiveAsync(ct);
        }
        catch (OperationCanceledException)
        {
            break;
        }
        catch (ObjectDisposedException)
        {
            break;
        }
        catch (SocketException ex)
        {
            Console.WriteLine($"[tunnel] Ошибка приёма: {ex.Message}");
            continue;
        }

        byte? frameType = Frame.PeekFrameType(result.Buffer, result.Buffer.Length);
        if (frameType == Frame.TypeData && cipher != null)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен незашифрованный кадр, но шифрование включено. Проверьте ключ у прокси-сервера.");
            continue;
        }
        if (frameType == Frame.TypeDataEncrypted && cipher == null)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен зашифрованный кадр, но ключ не задан. Запустите с тем же ключом, что и прокси-сервер.");
            continue;
        }

        if (!Frame.TryDecodeData(result.Buffer, result.Buffer.Length, cipher, out var clientIp, out ushort clientPort, out var payload))
            continue;

        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [клиент ->] {clientIp}:{clientPort} ({payload.Length} байт)");

        aliases.Add(clientIp);
        knownClients[new IPEndPoint(clientIp, clientPort)] = DateTime.UtcNow;
        activeIps[clientIp] = DateTime.UtcNow;

        injector.Inject(clientIp, clientPort, payload);
    }
}

static void CleanupLoop(
    LoopbackAliasManager aliases,
    ConcurrentDictionary<IPEndPoint, DateTime> knownClients,
    ConcurrentDictionary<IPAddress, DateTime> activeIps,
    CancellationToken ct)
{
    TimeSpan idleTimeout = TimeSpan.FromMinutes(10);

    while (!ct.IsCancellationRequested)
    {
        if (ct.WaitHandle.WaitOne(TimeSpan.FromSeconds(60)))
            break;

        var now = DateTime.UtcNow;

        foreach (var entry in knownClients)
        {
            if (now - entry.Value > idleTimeout)
                knownClients.TryRemove(entry.Key, out _);
        }

        foreach (var entry in activeIps)
        {
            if (now - entry.Value > idleTimeout && activeIps.TryRemove(entry.Key, out _))
                aliases.Remove(entry.Key);
        }
    }
}
