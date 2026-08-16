using System.Collections.Concurrent;
using System.Diagnostics;
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

Console.WriteLine("=== Прокси-клиент (RealIP) ===");
Console.WriteLine($"Прокси-сервер (машина A) : {proxyServer} (порт туннеля)");
Console.WriteLine($"Игровой сервер (локально): {gameIp}:{gamePort}");
Console.WriteLine($"Порт туннеля            : {tunnelPort} (порт туннеля сервера)");
Console.WriteLine($"Перехват ответов       : {(captureReplies ? "вкл" : "выкл")}");
Console.WriteLine($"Loopback-алиасы        : {(loopbackAliases ? "вкл" : "выкл")}");
Console.WriteLine("Шифрование туннеля      : вкл (AES-256-GCM)");
Console.WriteLine();

try
{
    using var tunnel = new UdpClient();
    var serverTcp = new ServerTcpStatus();
    var (handshakeOk, serverTcpEnabled) = await HandshakeAsync(proxyServer, tunnel, cipher);
    serverTcp.Set(serverTcpEnabled);
    await RunAsync(proxyServer, gameIp, (ushort)gamePort, tunnel, captureReplies, loopbackAliases, serverTcp, cipher);
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

/// Проверка связи с прокси-сервером: отправляет PING (3 попытки по 2 с) и ждёт PONG.
/// PING уходит с туннельного сокета — сервер по нему определяет адрес туннеля.
/// Работает даже при несовпадении ключа — сервер ответит «не разобранным» PING,
/// и клиент это увидит в логе сервера. При неудаче клиент всё равно продолжает работу.
/// Возвращает результат связи и флаг TCP-проксирования, который сервер передаёт в PONG.
static async Task<(bool Ok, bool TcpEnabled)> HandshakeAsync(IPEndPoint proxyServer, UdpClient socket, TunnelCipher? cipher)
{
    Console.WriteLine("[диагностика] Проверка связи с прокси-сервером (PING/PONG)...");

    var token = Guid.NewGuid().ToByteArray();
    var ping = Frame.EncodeControl(Frame.TypePing, token, cipher);

    socket.Client.ReceiveTimeout = 2000;

    for (var attempt = 1; attempt <= 3; attempt++)
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

        var timeout = true;
        var deadline = DateTime.UtcNow.AddSeconds(2);
        while (DateTime.UtcNow < deadline)
        {
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

            if (Frame.TryDecodePong(resp, resp.Length, cipher, token.Length, out var pongToken, out var tcpFlag)
                && pongToken.AsSpan().SequenceEqual(token))
            {
                sw.Stop();
                Console.WriteLine($"[диагностика] OK: сервер {proxyServer} ответил на PING за {sw.ElapsedMilliseconds} мс.");
                Console.WriteLine($"[диагностика] TCP-проксирование на сервере: {(tcpFlag ? "включено" : "выключено")}.");
                return (true, tcpFlag);
            }

            Console.WriteLine("[диагностика] Получен несоответствующий PONG — жду дальше.");
        }

        if (timeout)
            Console.WriteLine($"[диагностика] Попытка {attempt}/3: сервер не ответил за 2 с.");
    }

    Console.WriteLine("[!] Связь с прокси-сервером не установлена. Проверьте:");
    Console.WriteLine("[!]   1) прокси-сервер запущен и слушает UDP-порт (по умолчанию 27015);");
    Console.WriteLine("[!]   2) файрвол машины A пропускает UDP-трафик на порт туннеля;");
    Console.WriteLine("[!]   3) ключ шифрования совпадает у сервера и клиента.");
    Console.WriteLine("[!] Прокси-клиент продолжит работу и выведет [диагностика], как только получит первый кадр.");
    return (false, false);
}

static async Task RunAsync(
    IPEndPoint proxyServer,
    IPAddress gameIp,
    ushort gamePort,
    UdpClient tunnel,
    bool captureReplies,
    bool loopbackAliases,
    ServerTcpStatus serverTcp,
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
    var firstServerFrame = 0;

    var aliases = new LoopbackAliasManager(loopbackAliases);
    using var injector = new RawInjector(gameIp, gamePort);
    using var tcpRelay = new TcpRelay(gameIp, gamePort, tunnel, proxyServer, cipher, stats, serverTcp);
    using var statsTimer = new Timer(_ => stats.Print("прокси-клиент"), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));

    ReplySniffer? sniffer = null;
    var tasks = new List<Task>
    {
        Task.Run(() => ReceiveLoop(tunnel, aliases, injector, knownClients, activeIps, cipher, stats,
            () => Interlocked.Exchange(ref firstServerFrame, 1) == 0, cts.Token, tcpRelay, serverTcp)),
        Task.Run(() => HeartbeatLoop(tunnel, proxyServer, cipher, cts.Token))
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

/// Сердцебиение: раз в 10 секунд отправляет прокси-серверу PING с туннельного
/// сокета. Сервер по нему определяет/обновляет адрес туннеля — связь восстанавливается
/// сама после перезапуска сервера, смены порта после NAT или неудачного стартового PING.
static async Task HeartbeatLoop(UdpClient tunnel, IPEndPoint proxyServer, TunnelCipher? cipher, CancellationToken ct)
{
    var ping = Frame.EncodeControl(Frame.TypePing, Guid.NewGuid().ToByteArray(), cipher);

    while (!ct.IsCancellationRequested)
    {
        try
        {
            await tunnel.SendAsync(ping, ping.Length, proxyServer);
        }
        catch (SocketException)
        {
            // сервер временно недоступен — повторим через интервал
        }
        catch (ObjectDisposedException)
        {
            break;
        }

        try
        {
            await Task.Delay(TimeSpan.FromSeconds(10), ct);
        }
        catch (OperationCanceledException)
        {
            break;
        }
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
    CancellationToken ct,
    TcpRelay tcpRelay,
    ServerTcpStatus serverTcp)
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

        var frameType = Frame.PeekFrameType(result.Buffer, result.Buffer.Length);
        if (frameType is Frame.TypeTcpOpen or Frame.TypeTcpData or Frame.TypeTcpClose)
        {
            tcpRelay.OnFrame(result.Buffer, result.Buffer.Length);
            continue;
        }

        if (frameType == Frame.TypePong)
        {
            // Сервер каждым PONG сообщает, включено ли у него TCP-проксирование.
            if (Frame.TryDecodePong(result.Buffer, result.Buffer.Length, cipher, 16, out _, out var tcpFlag))
                serverTcp.Set(tcpFlag);
            continue;
        }
        if (frameType == Frame.TypePing)
        {
            // служебные кадры (в т.ч. ответы на сердцебиение) — не трафик
            continue;
        }

        if (frameType == Frame.TypeData && cipher != null)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен незашифрованный кадр, но шифрование включено. Проверьте ключ у прокси-сервера.");
            Interlocked.Increment(ref stats.BadFrames);
            continue;
        }

        if (!Frame.TryDecodeData(result.Buffer, result.Buffer.Length, cipher, out var clientIp, out var clientPort, out var payload))
        {
            Interlocked.Increment(ref stats.BadFrames);
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать кадр ({result.Buffer.Length} байт).");
            continue;
        }

        Interlocked.Increment(ref stats.PacketsIn);
        if (reportFirstFrame())
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Получен первый кадр туннеля от прокси-сервера — канал работает.");

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
    var idleTimeout = TimeSpan.FromMinutes(10);

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
