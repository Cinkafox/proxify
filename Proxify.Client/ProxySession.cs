using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Channels;
using Proxify.Common;

namespace Proxify.Client;

/// <summary>
/// Прокси-клиент (машина B).
///
/// Клиент знает только адрес прокси-сервера и свой закрытый ключ (PEM, PKCS#8).
/// Параметры туннеля (игровой сервер, флаги capture/aliases/tcp) приходят от
/// сервера в кадре AuthAck. Сессионный ключ выводится из ECDH при рукопожатии
/// и обновляется при повторной авторизации (если сервер долго не отвечает).
/// </summary>
public sealed class ProxySession : IDisposable
{
    private static readonly TimeSpan AuthAttemptTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan ReauthTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(10);

    private readonly ECDsa _identityKey;
    private readonly object _authLock = new();

    private ECDiffieHellman? _ephemeral;
    private byte[]? _pendingNonce;
    private TaskCompletionSource<bool>? _authTcs;
    private long _lastPongTicks;
    private LoopbackAliasManager? _aliases;
    private RawInjector? _injector;
    private TcpRelay? _tcpRelay;
    private ReplySniffer? _sniffer;

    public IPEndPoint ProxyServer { get; }
    public TunnelCipher? Cipher { get; private set; }
    public ClientConfig? Config { get; private set; }

    public TunnelStats Stats { get; } = new();
    public UdpClient Tunnel { get; }
    public ServerTcpStatus ServerTcp { get; } = new();

    /// <summary>Параллельная инжекция пакетов в игровой сервер.</summary>
    public AsyncWorkQueue InjectWork { get; }

    /// <summary>Клиенты игры (IP:порт), от которых проксируются пакеты.</summary>
    public ConcurrentDictionary<IPEndPoint, DateTime> KnownClients { get; } = new();

    /// <summary>Активные IP игроков (для loopback-алиасов и очистки по таймауту).</summary>
    public ConcurrentDictionary<IPAddress, DateTime> ActiveIps { get; } = new();

    public ProxySession(IPEndPoint proxyServer, ECDsa identityKey)
    {
        ProxyServer = proxyServer;
        _identityKey = identityKey;
        Tunnel = new UdpClient();
        Tunnel.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        InjectWork = new AsyncWorkQueue(Math.Clamp(Environment.ProcessorCount, 2, 8));
    }

    public void PrintBanner()
    {
        var config = Config;
        Console.WriteLine("=== Прокси-клиент (RealIP) ===");
        Console.WriteLine($"Прокси-сервер (машина A) : {ProxyServer}");
        Console.WriteLine($"Игровой сервер (локально): {config!.GameIp}:{config.GamePort}");
        Console.WriteLine($"Перехват ответов          : {(config.CaptureReplies ? "вкл" : "выкл")}");
        Console.WriteLine($"Loopback-алиасы           : {(config.LoopbackAliases ? "вкл" : "выкл")}");
        Console.WriteLine($"TCP-проксирование         : {(config.TcpEnabled ? "вкл" : "выкл")}");
        Console.WriteLine("Шифрование туннеля        : ECDSA P-256 + ECDH P-256 + AES-256-GCM (сессионный ключ)");
        Console.WriteLine();
    }

    public async Task RunAsync()
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        // Циклы запускаются сразу: приём обрабатывает AuthAck рукопожатия, а сердцебиение
        // начнёт слать PING только после появления сессионного ключа (Cipher != null).
        var tasks = new List<Task>
        {
            Task.Run(() => ReceiveLoop(cts.Token)),
            Task.Run(() => HeartbeatLoop(cts.Token)),
            Task.Run(() => CleanupLoop(cts.Token)),
        };

        // 1. Авторизация: получаем сессионный ключ и конфиг от сервера.
        Console.WriteLine("[auth] Авторизация на прокси-сервере...");
        var authOk = await AuthenticateAsync(cts.Token);
        if (!authOk)
        {
            Console.WriteLine("[!] Не удалось авторизоваться на прокси-сервере. Проверьте:");
            Console.WriteLine("[!]   1) сервер запущен и слушает порт туннеля;");
            Console.WriteLine("[!]   2) публичный ключ клиента (client-public.pem) зарегистрирован в конфиге сервера;");
            Console.WriteLine("[!]   3) файрвол машины A пропускает UDP-трафик на порт туннеля.");
            cts.Cancel();
            try
            {
                await Task.WhenAll(tasks);
            }
            catch
            {
                // плановое завершение циклов
            }
            return;
        }
        PrintBanner();

        var config = Config!;

        // 2. Компоненты с известным конфигом (нужны адрес и порт игрового сервера).
        var aliases = new LoopbackAliasManager(config.LoopbackAliases);
        _aliases = aliases;
        _injector = new RawInjector(config.GameIp, config.GamePort);
        _tcpRelay = new TcpRelay(config.GameIp, config.GamePort, Tunnel, ProxyServer, () => Cipher, Stats, ServerTcp);

        if (config.CaptureReplies)
        {
            _sniffer = new ReplySniffer(IPAddress.Loopback, config.GamePort, KnownClients, Tunnel, ProxyServer, () => Cipher, Stats, cts.Token);
            tasks.Add(Task.Run(_sniffer.Run));
        }

        using var statsTimer = new Timer(_ => Stats.Print("прокси-клиент"), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));

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
            _sniffer?.Dispose();
            _injector?.Dispose();
            _tcpRelay?.Dispose();
            aliases.Dispose();
            Console.WriteLine("Прокси-клиент остановлен.");
        }
    }

    /// <summary>
    /// Отправляет кадр Auth и ждёт AuthAck (несколько попыток). Результат приходит
    /// из цикла приёма через <see cref="_authTcs"/>. При успехе заполняются
    /// <see cref="Cipher"/> и <see cref="Config"/>.
    /// </summary>
    private async Task<bool> AuthenticateAsync(CancellationToken ct)
    {
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            var sw = Stopwatch.StartNew();
            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            lock (_authLock)
            {
                _authTcs = tcs;
                _pendingNonce = RandomNumberGenerator.GetBytes(TunnelKeys.NonceSize);
                _ephemeral?.Dispose();
                _ephemeral = TunnelKeys.CreateEphemeral();
                SendAuth();
            }

            Task completed;
            try
            {
                completed = await Task.WhenAny(tcs.Task, Task.Delay(AuthAttemptTimeout, ct));
            }
            catch (OperationCanceledException)
            {
                return false;
            }

            if (ct.IsCancellationRequested)
                return false;

            if (completed == tcs.Task)
            {
                sw.Stop();
                Console.WriteLine($"[auth] OK: авторизация за {sw.ElapsedMilliseconds} мс.");
                return true;
            }

            Console.WriteLine($"[auth] Попытка {attempt}/3: сервер не ответил AuthAck за 3 с.");
        }

        lock (_authLock)
        {
            _authTcs = null;
            _pendingNonce = null;
        }
        return false;
    }

    /// <summary>
    /// Отправляет кадр Auth с текущим эфемерным ключом и nonce.
    /// </summary>
    private void SendAuth()
    {
        if (_ephemeral == null || _pendingNonce == null)
            return;

        var (ephX, ephY) = TunnelKeys.ExportPoint(_ephemeral);
        var payload = TunnelKeys.BuildAuthPayload(ephX, ephY, _pendingNonce);
        var signature = TunnelKeys.Sign(_identityKey, payload);
        var frame = Frame.EncodeAuth(TunnelKeys.AuthVersion, ephX, ephY, _pendingNonce, signature);

        try
        {
            Tunnel.Send(frame, ProxyServer);
        }
        catch (SocketException ex)
        {
            Console.WriteLine($"[auth] Ошибка отправки Auth: {ex.Message}");
        }
        catch (ObjectDisposedException)
        {
            // сокет закрыт — выходим из рукопожатия
        }
    }

    /// <summary>
    /// Обработка кадра AuthAck: выводит сессионный ключ из ECDH, расшифровывает
    /// «доказательство», проверяет echo nonce и сохраняет конфиг.
    /// </summary>
    private void HandleAuthAck(byte[] buffer, int length)
    {
        if (!Frame.TryDecodeAuthAck(buffer, length, out var sX, out var sY, out var wrappedProof))
        {
            Interlocked.Increment(ref Stats.BadFrames);
            return;
        }

        byte[]? nonce;
        ECDiffieHellman? ephemeral;
        TaskCompletionSource<bool>? tcs;
        lock (_authLock)
        {
            nonce = _pendingNonce;
            ephemeral = _ephemeral;
            tcs = _authTcs;
        }

        if (nonce == null || ephemeral == null || tcs == null)
            return; // не ожидаем AuthAck в данный момент

        TunnelCipher? cipher = null;
        ClientConfig? config;
        try
        {
            var sessionKey = TunnelKeys.DeriveSessionKey(ephemeral, sX, sY);
            try
            {
                cipher = new TunnelCipher(sessionKey);
                if (!ClientConfig.TryDecodeProof(nonce, cipher, wrappedProof, out config))
                {
                    Interlocked.Increment(ref Stats.BadFrames);
                    Console.WriteLine("[auth] [!] AuthAck не прошёл проверку (неверный echo nonce или ключ).");
                    return;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sessionKey);
            }
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref Stats.BadFrames);
            Console.WriteLine($"[auth] [!] Не удалось установить сессию: {ex.Message}");
            return;
        }

        Cipher = cipher;
        Config = config;
        Interlocked.Exchange(ref _lastPongTicks, DateTime.UtcNow.Ticks);
        ServerTcp.Set(config.TcpEnabled);

        lock (_authLock)
        {
            _authTcs = null;
            _pendingNonce = null;
            _ephemeral?.Dispose();
            _ephemeral = null;
        }

        tcs.TrySetResult(true);
        Console.WriteLine($"[auth] Получена конфигурация от сервера: игра {config.GameIp}:{config.GamePort}, " +
                          $"capture={(config.CaptureReplies ? "вкл" : "выкл")}, aliases={(config.LoopbackAliases ? "вкл" : "выкл")}, " +
                          $"tcp={(config.TcpEnabled ? "вкл" : "выкл")}.");
    }

    private async Task ReceiveLoop(CancellationToken ct)
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
            if (frameType is Frame.TypeTcpOpen or Frame.TypeTcpData or Frame.TypeTcpClose or Frame.TypeTcpAck)
            {
                _tcpRelay?.OnFrame(result.Buffer, result.Buffer.Length);
                continue;
            }

            if (frameType == Frame.TypeAuthAck)
            {
                HandleAuthAck(result.Buffer, result.Buffer.Length);
                continue;
            }

            var cipher = Cipher;
            if (cipher == null)
                continue;

            if (frameType == Frame.TypePong)
            {
                // Сервер каждым PONG сообщает, включено ли у него TCP-проксирование.
                if (Frame.TryDecodePong(result.Buffer, result.Buffer.Length, cipher, 16, out _, out var tcpFlag))
                {
                    Interlocked.Exchange(ref _lastPongTicks, DateTime.UtcNow.Ticks);
                    ServerTcp.Set(tcpFlag);
                }
                continue;
            }
            if (frameType == Frame.TypePing)
            {
                // служебные кадры (в т.ч. ответы на сердцебиение) — не трафик
                continue;
            }

            if (frameType == Frame.TypeData && Cipher != null)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен незашифрованный кадр, но шифрование включено. Проверьте конфиг у прокси-сервера.");
                Interlocked.Increment(ref Stats.BadFrames);
                continue;
            }

            if (!Frame.TryDecodeData(result.Buffer, result.Buffer.Length, cipher, out var clientIp, out var clientPort, out var payload))
            {
                Interlocked.Increment(ref Stats.BadFrames);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать кадр ({result.Buffer.Length} байт).");
                continue;
            }

            Interlocked.Increment(ref Stats.PacketsIn);

            var injector = _injector;
            if (injector == null)
                continue;

            // Инжекция и обновление словарей выполняются воркером параллельно,
            // чтобы цикл приёма не ждал отправки «сырых» пакетов.
            try
            {
                await InjectWork.EnqueueAsync(() =>
                {
                    _aliases?.Add(clientIp);
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
    /// Сердцебиение: раз в 10 секунд отправляет прокси-серверу PING. Сервер по нему
    /// держит сессию живой. Если PONG давно не было (30 с) — сессия протухла:
    /// выполняем повторную авторизацию (новый Auth/AuthAck и сессионный ключ).
    /// </summary>
    private async Task HeartbeatLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var cipher = Cipher;
                if (cipher != null)
                {
                    var ping = Frame.EncodeControl(Frame.TypePing, Guid.NewGuid().ToByteArray(), cipher);
                    await Tunnel.SendAsync(ping, ping.Length, ProxyServer);
                }
            }
            catch (SocketException)
            {
                // сервер временно недоступен — повторим через интервал
            }
            catch (ObjectDisposedException)
            {
                break;
            }

            var lastPong = Interlocked.Read(ref _lastPongTicks);
            if (Cipher != null && DateTime.UtcNow.Ticks - lastPong > ReauthTimeout.Ticks)
            {
                Console.WriteLine("[auth] Сессия протухла (нет ответа сервера) — повторная авторизация...");
                if (await AuthenticateAsync(ct))
                    Console.WriteLine("[auth] Сессия восстановлена.");
            }

            try
            {
                await Task.Delay(HeartbeatInterval, ct);
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
                    _aliases?.Remove(entry.Key);
            }
        }
    }

    public void Dispose()
    {
        InjectWork.Dispose();
        _aliases?.Dispose();
        Tunnel.Dispose();
        _identityKey.Dispose();
    }
}
