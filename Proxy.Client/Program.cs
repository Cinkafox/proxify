using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using Proxify.Client;
using Proxify.Common;

Console.OutputEncoding = Encoding.UTF8;

PrintUsage();

IPEndPoint proxyServer = new IPEndPoint(IPAddress.Loopback, 27015);
if (args.Length > 0)
{
    if (!NetUtils.TryParseEndpoint(args[0], out var ps))
    {
        Console.WriteLine($"[ошибка конфигурации] Адрес прокси-сервера '{args[0]}' не распознан (ожидается 'ip:port').");
        return 1;
    }
    proxyServer = ps;
}

IPAddress gameIp = IPAddress.Loopback;
if (args.Length > 1)
{
    if (!IPAddress.TryParse(args[1], out var gi))
    {
        Console.WriteLine($"[ошибка конфигурации] gameIp '{args[1]}' не является IP-адресом.");
        return 1;
    }
    gameIp = gi;
}
if (gameIp.AddressFamily != AddressFamily.InterNetwork)
{
    Console.WriteLine("[ошибка конфигурации] gameIp должен быть IPv4-адресом.");
    return 1;
}

int gamePort = 7777;
if (args.Length > 2 && !NetUtils.TryParsePort(args[2], out gamePort))
{
    Console.WriteLine($"[ошибка конфигурации] gamePort '{args[2]}' не является допустимым (ожидается число от 1 до 65535).");
    return 1;
}

int tunnelBindPort = 5600;
if (args.Length > 3 && !NetUtils.TryParsePort(args[3], out tunnelBindPort))
{
    Console.WriteLine($"[ошибка конфигурации] Порт туннеля '{args[3]}' не является допустимым (ожидается число от 1 до 65535).");
    return 1;
}

bool captureReplies = true;
if (args.Length > 4 && !bool.TryParse(args[4], out captureReplies))
{
    Console.WriteLine($"[ошибка конфигурации] captureReplies '{args[4]}' должен быть true или false.");
    return 1;
}

bool loopbackAliases = true;
if (args.Length > 5 && !bool.TryParse(args[5], out loopbackAliases))
{
    Console.WriteLine($"[ошибка конфигурации] loopbackAliases '{args[5]}' должен быть true или false.");
    return 1;
}

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
    await HandshakeAsync(proxyServer, cipher);
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

return 0;

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
    Console.WriteLine("При запуске выполняется PING/PONG к прокси-серверу — результат связи");
    Console.WriteLine("печатается как [диагностика]. Раз в минуту печатается статистика [stats].");
    Console.WriteLine();
}

/// Проверка связи с прокси-сервером: отправляет PING (3 попытки по 2 с) и ждёт PONG.
/// Работает даже при несовпадении ключа — сервер ответит «не разобранным» PING,
/// и клиент это увидит в логе сервера. При неудаче клиент всё равно продолжает работу.
static async Task<bool> HandshakeAsync(IPEndPoint proxyServer, TunnelCipher? cipher)
{
    Console.WriteLine("[диагностика] Проверка связи с прокси-сервером (PING/PONG)...");

    var token = Guid.NewGuid().ToByteArray();
    var ping = Frame.EncodeControl(Frame.TypePing, token, cipher);

    using var socket = new UdpClient();
    socket.Client.ReceiveTimeout = 2000;

    for (int attempt = 1; attempt <= 3; attempt++)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            await socket.SendAsync(ping, ping.Length, proxyServer);
        }
        catch (SocketException ex)
        {
            Console.WriteLine($"[диагностика] Попытка {attempt}/3: ошибка отправки: {ex.Message}");
            continue;
        }

        bool timeout = true;
        var deadline = DateTime.UtcNow.AddSeconds(2);
        while (DateTime.UtcNow < deadline)
        {
            EndPoint ep = new IPEndPoint(IPAddress.Any, 0);
            byte[] resp;
            try
            {
                IPEndPoint? remote = null;
                resp = socket.Receive(ref remote);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
            {
                break; // ждём до истечения таймаута, дальше — следующая попытка
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"[диагностика] Попытка {attempt}/3: ошибка приёма: {ex.Message}");
                timeout = false;
                break;
            }

            if (Frame.TryDecodeControl(resp, resp.Length, Frame.TypePong, cipher, out var pongToken)
                && pongToken.AsSpan().SequenceEqual(token))
            {
                sw.Stop();
                Console.WriteLine($"[диагностика] OK: сервер {proxyServer} ответил на PING за {sw.ElapsedMilliseconds} мс.");
                return true;
            }

            Console.WriteLine("[диагностика] Получен несоответствующий PONG — жду дальше.");
        }

        if (timeout)
            Console.WriteLine($"[диагностика] Попытка {attempt}/3: сервер не ответил за 2 с.");
    }

    Console.WriteLine("[!] Связь с прокси-сервером не установлена. Проверьте:");
    Console.WriteLine("[!]   1) прокси-сервер запущен и слушает UDP-порт (по умолчанию 27015);");
    Console.WriteLine("[!]   2) файрвол машины A пропускает UDP-трафик на порт туннеля;");
    Console.WriteLine("[!]   3) ключ шифрования совпадает у сервера и клиента (если используется).");
    Console.WriteLine("[!] Прокси-клиент продолжит работу и выведет [диагностика], как только получит первый кадр.");
    return false;
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
    var stats = new TunnelStats();
    int firstServerFrame = 0;

    var aliases = new LoopbackAliasManager(loopbackAliases);
    using var injector = new RawInjector(gameIp, gamePort);
    using var tunnel = new UdpClient(new IPEndPoint(IPAddress.Any, tunnelBindPort));
    using var statsTimer = new Timer(_ => stats.Print("прокси-клиент"), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));

    ReplySniffer? sniffer = null;
    var tasks = new List<Task>
    {
        Task.Run(() => ReceiveLoop(tunnel, aliases, injector, knownClients, activeIps, cipher, stats,
            () => Interlocked.Exchange(ref firstServerFrame, 1) == 0, cts.Token))
    };

    if (captureReplies)
    {
        sniffer = new ReplySniffer(IPAddress.Loopback, gamePort, knownClients, tunnel, proxyServer, cipher, stats, cts.Token);
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
        stats.Print("прокси-клиент");
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
    TunnelStats stats,
    Func<bool> reportFirstFrame,
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
            Interlocked.Increment(ref stats.BadFrames);
            continue;
        }
        if (frameType == Frame.TypeDataEncrypted && cipher == null)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен зашифрованный кадр, но ключ не задан. Запустите с тем же ключом, что и прокси-сервер.");
            Interlocked.Increment(ref stats.BadFrames);
            continue;
        }
        if (frameType is Frame.TypePing or Frame.TypePong)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Служебный кадр 0x{frameType:X2} на порту туннеля — игнорирую.");
            continue;
        }

        if (!Frame.TryDecodeData(result.Buffer, result.Buffer.Length, cipher, out var clientIp, out ushort clientPort, out var payload))
        {
            Interlocked.Increment(ref stats.BadFrames);
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать кадр ({result.Buffer.Length} байт).");
            continue;
        }

        Interlocked.Increment(ref stats.PacketsIn);
        if (reportFirstFrame())
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Получен первый кадр туннеля от прокси-сервера — канал работает.");

        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [клиент ->] {clientIp}:{clientPort} ({payload.Length} байт)");

        aliases.Add(clientIp);
        knownClients[new IPEndPoint(clientIp, clientPort)] = DateTime.UtcNow;
        activeIps[clientIp] = DateTime.UtcNow;

        injector.Inject(clientIp, clientPort, payload);
        Interlocked.Increment(ref stats.Injected);
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
