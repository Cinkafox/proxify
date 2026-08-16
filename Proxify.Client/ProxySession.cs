using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using Proxify.Common;

namespace Proxify.Client;

/// <summary>
/// Текущее состояние сессии проксирования на прокси-клиенте (машина B).
///
/// Владеет конфигурацией, туннельным сокетом, очередью инжекции и всеми
/// текущими данными сессии: известные клиенты игры, активные IP (для
/// loopback-алиасов), признак TCP-проксирования на сервере. Здесь же —
/// рукопожатие (PING/PONG), циклы приёма/сердцебиения и очистка.
/// </summary>
public sealed class ProxySession : IDisposable
{
    public IPEndPoint ProxyServer { get; }
    public IPAddress GameIp { get; }
    public ushort GamePort { get; }
    public int TunnelPort { get; }
    public bool CaptureReplies { get; }
    public bool LoopbackAliases { get; }
    public TunnelCipher Cipher { get; }

    public TunnelStats Stats { get; } = new();
    public UdpClient Tunnel { get; }
    public ServerTcpStatus ServerTcp { get; } = new();
    public LoopbackAliasManager Aliases { get; }

    /// <summary>Параллельная инжекция пакетов в игровой сервер.</summary>
    public AsyncWorkQueue InjectWork { get; }

    /// <summary>Клиенты игры (IP:порт), от которых проксируются пакеты.</summary>
    public ConcurrentDictionary<IPEndPoint, DateTime> KnownClients { get; } = new();

    /// <summary>Активные IP игроков (для loopback-алиасов и очистки по таймауту).</summary>
    public ConcurrentDictionary<IPAddress, DateTime> ActiveIps { get; } = new();

    public ProxySession(
        IPEndPoint proxyServer,
        IPAddress gameIp,
        ushort gamePort,
        int tunnelPort,
        bool captureReplies,
        bool loopbackAliases,
        TunnelCipher cipher)
    {
        ProxyServer = proxyServer;
        GameIp = gameIp;
        GamePort = gamePort;
        TunnelPort = tunnelPort;
        CaptureReplies = captureReplies;
        LoopbackAliases = loopbackAliases;
        Cipher = cipher;

        Tunnel = new UdpClient();
        Aliases = new LoopbackAliasManager(loopbackAliases);
        InjectWork = new AsyncWorkQueue(Math.Clamp(Environment.ProcessorCount, 2, 8));
    }

    public void PrintBanner()
    {
        Console.WriteLine("=== Прокси-клиент (RealIP) ===");
        Console.WriteLine($"Прокси-сервер (машина A) : {ProxyServer} (порт туннеля)");
        Console.WriteLine($"Игровой сервер (локально): {GameIp}:{GamePort}");
        Console.WriteLine($"Порт туннеля            : {TunnelPort} (порт туннеля сервера)");
        Console.WriteLine($"Перехват ответов       : {(CaptureReplies ? "вкл" : "выкл")}");
        Console.WriteLine($"Loopback-алиасы        : {(LoopbackAliases ? "вкл" : "выкл")}");
        Console.WriteLine("Шифрование туннеля      : вкл (AES-256-GCM)");
        Console.WriteLine();
    }

    /// <summary>
    /// Проверка связи с прокси-сервером: отправляет PING (3 попытки по 2 с) и ждёт PONG.
    /// PING уходит с туннельного сокета — сервер по нему определяет адрес туннеля.
    /// Работает даже при несовпадении ключа — сервер ответит «не разобранным» PING,
    /// и клиент это увидит в логе сервера. При неудаче клиент всё равно продолжает работу.
    /// Возвращает результат связи и флаг TCP-проксирования, который сервер передаёт в PONG.
    /// </summary>
    public async Task<(bool Ok, bool TcpEnabled)> HandshakeAsync()
    {
        Console.WriteLine("[диагностика] Проверка связи с прокси-сервером (PING/PONG)...");

        var token = Guid.NewGuid().ToByteArray();
        var ping = Frame.EncodeControl(Frame.TypePing, token, Cipher);

        Tunnel.Client.ReceiveTimeout = 2000;

        for (var attempt = 1; attempt <= 3; attempt++)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                await Tunnel.SendAsync(ping, ping.Length, ProxyServer);
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
                    resp = Tunnel.Receive(ref remote);
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

                if (Frame.TryDecodePong(resp, resp.Length, Cipher, token.Length, out var pongToken, out var tcpFlag)
                    && pongToken.AsSpan().SequenceEqual(token))
                {
                    sw.Stop();
                    Console.WriteLine($"[диагностика] OK: сервер {ProxyServer} ответил на PING за {sw.ElapsedMilliseconds} мс.");
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

    public async Task RunAsync()
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        var firstServerFrame = 0;

        using var injector = new RawInjector(GameIp, GamePort);
        using var tcpRelay = new TcpRelay(GameIp, GamePort, Tunnel, ProxyServer, Cipher, Stats, ServerTcp);
        using var statsTimer = new Timer(_ => Stats.Print("прокси-клиент"), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));

        ReplySniffer? sniffer = null;
        var tasks = new List<Task>
        {
            Task.Run(() => ReceiveLoop(cts.Token, injector, tcpRelay, () => Interlocked.Exchange(ref firstServerFrame, 1) == 0)),
            Task.Run(() => HeartbeatLoop(cts.Token))
        };

        if (CaptureReplies)
        {
            sniffer = new ReplySniffer(IPAddress.Loopback, GamePort, KnownClients, Tunnel, ProxyServer, Cipher, Stats, cts.Token);
            tasks.Add(Task.Run(sniffer.Run));
        }

        tasks.Add(Task.Run(() => CleanupLoop(cts.Token)));

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
            Stats.Print("прокси-клиент");
            // Дожидаемся обработки оставшихся в очереди пакетов перед закрытием сокетов.
            await InjectWork.WaitForDrainAsync();
            sniffer?.Dispose();
            Console.WriteLine("Прокси-клиент остановлен.");
        }
    }

    private async Task ReceiveLoop(
        CancellationToken ct,
        RawInjector injector,
        TcpRelay tcpRelay,
        Func<bool> reportFirstFrame)
    {
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult result;
            try
            {
                result = await Tunnel.ReceiveAsync(ct);
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
                if (Frame.TryDecodePong(result.Buffer, result.Buffer.Length, Cipher, 16, out _, out var tcpFlag))
                    ServerTcp.Set(tcpFlag);
                continue;
            }
            if (frameType == Frame.TypePing)
            {
                // служебные кадры (в т.ч. ответы на сердцебиение) — не трафик
                continue;
            }

            if (frameType == Frame.TypeData && Cipher != null)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен незашифрованный кадр, но шифрование включено. Проверьте ключ у прокси-сервера.");
                Interlocked.Increment(ref Stats.BadFrames);
                continue;
            }

            if (!Frame.TryDecodeData(result.Buffer, result.Buffer.Length, Cipher, out var clientIp, out var clientPort, out var payload))
            {
                Interlocked.Increment(ref Stats.BadFrames);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать кадр ({result.Buffer.Length} байт).");
                continue;
            }

            Interlocked.Increment(ref Stats.PacketsIn);

            // Инжекция и обновление словарей выполняются воркером параллельно,
            // чтобы цикл приёма не ждал отправки «сырых» пакетов.
            try
            {
                await InjectWork.EnqueueAsync(() =>
                {
                    if (reportFirstFrame())
                        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Получен первый кадр туннеля от прокси-сервера — канал работает.");

                    Aliases.Add(clientIp);
                    KnownClients[new IPEndPoint(clientIp, clientPort)] = DateTime.UtcNow;
                    ActiveIps[clientIp] = DateTime.UtcNow;

                    injector.Inject(clientIp, clientPort, payload);
                    Interlocked.Increment(ref Stats.Injected);
                    return Task.CompletedTask;
                });
            }
            catch (ChannelClosedException)
            {
                break;
            }
        }
    }

    /// <summary>
    /// Сердцебиение: раз в 10 секунд отправляет прокси-серверу PING с туннельного
    /// сокета. Сервер по нему определяет/обновляет адрес туннеля — связь восстанавливается
    /// сама после перезапуска сервера, смены порта после NAT или неудачного стартового PING.
    /// </summary>
    private async Task HeartbeatLoop(CancellationToken ct)
    {
        var ping = Frame.EncodeControl(Frame.TypePing, Guid.NewGuid().ToByteArray(), Cipher);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Tunnel.SendAsync(ping, ping.Length, ProxyServer);
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

    private void CleanupLoop(CancellationToken ct)
    {
        var idleTimeout = TimeSpan.FromMinutes(10);

        while (!ct.IsCancellationRequested)
        {
            if (ct.WaitHandle.WaitOne(TimeSpan.FromSeconds(60)))
                break;

            var now = DateTime.UtcNow;

            foreach (var entry in KnownClients)
            {
                if (now - entry.Value > idleTimeout)
                    KnownClients.TryRemove(entry.Key, out _);
            }

            foreach (var entry in ActiveIps)
            {
                if (now - entry.Value > idleTimeout && ActiveIps.TryRemove(entry.Key, out _))
                    Aliases.Remove(entry.Key);
            }
        }
    }

    public void Dispose()
    {
        InjectWork.Dispose();
        Aliases.Dispose();
        Tunnel.Dispose();
    }
}
