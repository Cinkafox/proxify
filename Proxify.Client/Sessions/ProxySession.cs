using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Proxify.Client.Tcp;
using Proxify.Common.Config;
using Proxify.Common.Crypto;
using Proxify.Common.Metrics;
using Proxify.Common.Protocol;
using Proxify.Common.Quic;
using Proxify.Common.Sessions;

namespace Proxify.Client.Sessions;

/// <summary>
/// Прокси-клиент (машина B).
///
/// Клиент знает только адрес прокси-сервера и свой закрытый ключ (PEM, PKCS#8).
/// Параметры туннеля (игровой сервер, флаги capture/aliases/tcp) приходят от
/// сервера в кадре AuthAck — поэтому конкретный протокол (UDP или TCP) изначально
/// неизвестен и сессия создаётся фабрикой <see cref="CreateAsync"/>: сначала
/// выполняется прямое рукопожатие, затем возвращается <see cref="UdpProxySession"/>
/// или <see cref="TcpProxySession"/>. Сессионный ключ выводится из ECDH при
/// рукопожатии и обновляется при повторной авторизации (если сервер долго молчит).
///
/// Общее для обеих реализаций: приём кадров, сердцебиение (PING/PONG) и повторная
/// авторизация собраны здесь; протокольные части делегируются абстрактным хук-методам.
/// Ещё более общее с серверной сессией лежит в <see cref="SharedProxySession"/>.
/// </summary>
public abstract class ProxySession : SharedProxySession
{
    private static readonly TimeSpan AuthAttemptTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan ReauthTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan HeartbeatMinInterval = TimeSpan.FromSeconds(7);
    private static readonly TimeSpan HeartbeatMaxInterval = TimeSpan.FromSeconds(15);

    private readonly ECDsa _identityKey;
    private readonly object _authLock = new();

    private ECDiffieHellman? _ephemeral;
    private byte[]? _pendingNonce;
    private TaskCompletionSource<bool>? _authTcs;
    private long _lastPongTicks;
    private long _lastMaskingLogTicks;
    private byte[] _lastPingToken = Array.Empty<byte>();

    private readonly TunnelMetrics _processMetrics;

    public IPEndPoint ProxyServer { get; }
    public override TunnelCipher? Cipher { get; protected set; }
    public override ClientConfig? Config { get; protected set; }

    /// <summary>
    /// Реестр метрик процесса: его отдаёт наружу экспортёр (--metrics-port).
    /// </summary>
    public TunnelMetrics ProcessMetrics => _processMetrics;

    /// <summary>
    /// Число игроков (UDP-правило) или активных соединений с игровым сервером
    /// (TCP-правило) — источник гаужа <c>proxify_tunnel_players</c>.
    /// </summary>
    public abstract int PlayersCount { get; }

    /// <summary>
    /// Признак включённого TCP-проксирования на прокси-сервере.
    /// Заполняется из AuthAck/PONG и обновляется при повторной авторизации.
    /// </summary>
    public ServerTcpStatus ServerTcp { get; } = new();

    protected ECDsa IdentityKey => _identityKey;

    /// <param name="tunnel">Локальный UDP-сокет туннеля (владеется этой сессией).</param>
    /// <param name="work">Очередь фоновой обработки исходящих пакетов/кадров.</param>
    protected ProxySession(
        IPEndPoint proxyServer,
        ECDsa identityKey,
        UdpClient tunnel,
        WireObfuscator? wire,
        TunnelMetricsHandle metrics,
        AsyncWorkQueue work,
        TunnelCipher cipher,
        ClientConfig config,
        TunnelMetrics processMetrics)
        : base(tunnel, metrics, work, wire)
    {
        ProxyServer = proxyServer;
        _identityKey = identityKey;
        _processMetrics = processMetrics;
        Cipher = cipher;
        Config = config;
        ServerTcp.Set(config.Protocol == TunnelProtocol.Tcp);
        // Сессия создаётся только после успешного Auth, поэтому она авторизована.
        Metrics.SetAuthorized(true);
        _processMetrics.AddRefreshCallback(RefreshMetrics);
        Interlocked.Exchange(ref _lastPongTicks, DateTime.UtcNow.Ticks);
    }

    /// <summary>
    /// Обновляет «живые» гаужи метрик: число игроков, глубину очереди обработки и
    /// признак авторизации. Вызывается по таймеру, только если метрики включены.
    /// </summary>
    private void RefreshMetrics()
    {
        Metrics.SetPlayers(PlayersCount);
        Metrics.SetQueueDepth(Work.PendingCount);
        Metrics.SetAuthorized(Cipher != null);
    }

    /// <summary>
    /// Точка входа клиента: выполняет рукопожатие Auth/AuthAck напрямую (без
    /// запущенного цикла приёма), затем создаёт и возвращает сессию нужного
    /// протокола (UDP или TCP — из конфига сервера в AuthAck). При неудаче
    /// печатает подсказки, освобождает ресурсы и возвращает null.
    /// Владелец вызывает у результата <see cref="RunAsync"/> и <see cref="Dispose"/>.
    /// </summary>
    public static async Task<ProxySession?> CreateAsync(
        IPEndPoint proxyServer,
        ECDsa identityKey,
        int? localPort = null,
        WireObfuscationMode wireMode = WireObfuscationMode.Off,
        string? quicServerName = null,
        TunnelMetrics? metrics = null)
    {
        metrics ??= new TunnelMetrics(MetricsRole.Client, perClientLabels: false);
        var tunnel = new UdpClient();
        try
        {
            tunnel.Client.Bind(new IPEndPoint(IPAddress.Any, localPort ?? 0));
        }
        catch (Exception ex)
        {
            tunnel.Dispose();
            identityKey.Dispose();
            Console.WriteLine($"[ошибка конфигурации] Не удалось открыть локальный UDP-сокет: {ex.Message}");
            return null;
        }

        var wire = wireMode == WireObfuscationMode.Off
            ? null
            : WireObfuscator.Create(identityKey, weAreClient: true, wireMode, quicServerName ?? QuicConnection.DefaultServerName);

        if (wire != null)
            Console.WriteLine($"[tunnel] Режим маскировки: {DescribeMode(wireMode)}");

        // До рукопожатия конфиг правила ещё неизвестен, поэтому плохие кадры
        // рукопожатия считаем на уровне процесса.
        var authMetrics = metrics.Process;
        var work = new AsyncWorkQueue(Math.Clamp(Environment.ProcessorCount, 2, 8));

        Console.WriteLine("[auth] Авторизация на прокси-сервере...");
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            var sw = Stopwatch.StartNew();
            byte[] nonce;
            ECDiffieHellman ephemeral;
            byte[] authFrame;
            using (ephemeral = TunnelKeys.CreateEphemeral())
            {
                nonce = RandomNumberGenerator.GetBytes(TunnelKeys.NonceSize);
                authFrame = BuildAuth(identityKey, ephemeral, nonce);
                try
                {
                    // В режиме quic рукопожатие уходит первым обменом QUIC (Initial с
                    // ClientHello + Handshake с кадром Auth одной даграммой).
                    tunnel.Send(wire?.Wrap(authFrame, WireFrameRole.Handshake) ?? authFrame, proxyServer);
                }
                catch (SocketException ex)
                {
                    Console.WriteLine($"[auth] Ошибка отправки Auth: {ex.Message}");
                    ephemeral.Dispose();
                    break;
                }
                catch (ObjectDisposedException)
                {
                    ephemeral.Dispose();
                    break;
                }

                var deadline = DateTime.UtcNow + AuthAttemptTimeout;
                while (true)
                {
                    var remaining = deadline - DateTime.UtcNow;
                    if (remaining <= TimeSpan.Zero)
                        break;

                    var received = await ReceiveAuthAckAsync(tunnel, remaining);
                    if (received == null)
                        break; // таймаут ожидания

                    var data = received.Value.Data;
                    if (wire != null)
                    {
                        // Пакет без кадра туннеля (ACK, PING) пропускаем: ждём AuthAck.
                        if (wire.Unwrap(data, data.Length, out var inner) != WireOutcome.Tunnel)
                        {
                            authMetrics.CountBadFrame();
                            continue;
                        }

                        data = inner;
                    }

                    if (Frame.PeekFrameType(data, data.Length) != Frame.TypeAuthAck)
                        continue;

                    if (TryParseAuthAck(data, data.Length, nonce, ephemeral, out var cipher, out var config))
                    {
                        sw.Stop();
                        Console.WriteLine($"[auth] OK: авторизация за {sw.ElapsedMilliseconds} мс.");

                        tunnel.Client.ReceiveTimeout = 0;
                        Console.WriteLine($"[auth] Получена конфигурация от сервера: игра {config!.GameIp}:{config.GamePort}, " +
                                          $"capture={(config.CaptureReplies ? "вкл" : "выкл")}, aliases={(config.LoopbackAliases ? "вкл" : "выкл")}, " +
                                          $"protocol={config.Protocol}.");

                        // Ключи пакетов 1-RTT выводятся из того же сессионного ключа,
                        // что и внутренний шифр: с этого момента кадры идут в потоке.
                        wire?.AttachSessionKey(cipher!.ExportSessionKey());

                        var sessionMetrics = metrics.ForClient($"{config!.GameIp}:{config.GamePort}");
                        return config.Protocol == TunnelProtocol.Tcp
                            ? new TcpProxySession(proxyServer, identityKey, tunnel, wire, sessionMetrics, work, cipher!, config, metrics)
                            : new UdpProxySession(proxyServer, identityKey, tunnel, wire, sessionMetrics, work, cipher!, config, metrics)!;
                    }

                    authMetrics.CountBadFrame();
                    Console.WriteLine("[auth] [!] AuthAck не прошёл проверку (неверный echo nonce или ключ).");
                }
            }

            Console.WriteLine($"[auth] Попытка {attempt}/3: сервер не ответил AuthAck за 3 с.");
        }

        Console.WriteLine("[!] Не удалось авторизоваться на прокси-сервере. Проверьте:");
        Console.WriteLine("[!]   1) сервер запущен и слушает порт туннеля;");
        Console.WriteLine("[!]   2) публичный ключ клиента (client-public.pem) зарегистрирован в конфиге сервера;");
        Console.WriteLine("[!]   3) файрвол машины A пропускает UDP-трафик на порт туннеля.");

        identityKey.Dispose();
        work.Dispose();
        tunnel.Dispose();
        return null;
    }

    /// <summary>
    /// Соединяется с игровым сервером и проксирует через туннель.
    /// </summary>
    /// <param name="externalToken">
    /// Внешний токен отмены: консольный клиент не передаёт его (используется Ctrl+C),
    /// GUI-клиент передаёт токен кнопки «Остановить».
    /// </param>
    public async Task RunAsync(CancellationToken externalToken = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        // Циклы запускаются сразу: приём обрабатывает AuthAck повторной авторизации,
        // а сердцебиение начинает слать PING только после появления сессионного ключа.
        var tasks = new List<Task>
        {
            Task.Run(() => ReceiveLoop(cts.Token)),
            Task.Run(() => HeartbeatLoop(cts.Token)),
        };
        tasks.AddRange(CreateProtocolTasks(cts.Token));

        PrintBanner();
        CreateComponents(cts.Token);

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
            // Дожидаемся обработки оставшихся в очереди пакетов перед закрытием сокетов.
            await Work.WaitForDrainAsync();
            DisposeComponents();
            Console.WriteLine("Прокси-клиент остановлен.");
        }
    }

    /// <summary>Создаёт компоненты протокола (инжектор/алиасы/сниффер или TCP-релей).</summary>
    protected abstract void CreateComponents(CancellationToken ct);

    /// <summary>Дополнительные фоновые циклы протокола (например, очистка словарей).</summary>
    protected abstract IEnumerable<Task> CreateProtocolTasks(CancellationToken ct);

    /// <summary>Обработка протокольного кадра туннеля (данные UDP или TCP-кадры).</summary>
    protected abstract Task HandleProtocolFrameAsync(byte? frameType, byte[] data, int length);

    /// <summary>Освобождение компонентов протокола (идемпотентно).</summary>
    protected abstract void DisposeComponents();

    /// <summary>Строки баннера, зависящие от протокола правила.</summary>
    protected abstract void PrintProtocolBanner(ClientConfig config);

    private void PrintBanner()
    {
        var config = Config!;
        Console.WriteLine("=== Прокси-клиент (RealIP) ===");
        Console.WriteLine($"Прокси-сервер (машина A) : {ProxyServer}");
        PrintProtocolBanner(config);
        Console.WriteLine("Шифрование туннеля        : ECDSA P-256 + ECDH P-256 + AES-256-GCM (сессионный ключ)");
        Console.WriteLine($"Метрики Prometheus         : {(_processMetrics.Enabled ? $"вкл — {_processMetrics.ExpositionUrl}" : "выкл (задайте --metrics-port, чтобы включить)")}");
        Console.WriteLine($"Маскировка датаграмм      : {(Wire != null
            ? "внешний AEAD-слой от ключа клиента (на проводе только случайные байты)"
            : "ВЫКЛЮЧЕНА (кадры видны в внутреннем формате; должна совпадать с сервером)")}");
        Console.WriteLine();
    }

    /// <summary>
    /// Повторная авторизация (после протухания сессии): результата ждём из цикла
    /// приёма через <see cref="_authTcs"/>, как и при стартовом рукопожатии.
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

    /// <summary>Человекочитаемое имя режима маскировки для журнала запуска.</summary>
    private static string DescribeMode(WireObfuscationMode mode) => mode switch
    {
        WireObfuscationMode.Random => "шифрование датаграммы (AES-256-GCM)",
        WireObfuscationMode.Quic => "пакеты QUIC v1 поверх HTTP/3",
        _ => "выключена"
    };

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
            // Рукопожатие уходит в той же маскирующей оболочке, что и все кадры.
            Tunnel.Send(SealFrame(frame, WireFrameRole.Handshake), ProxyServer);
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
    /// Обработка кадра AuthAck (повторная авторизация): выводит сессионный ключ из
    /// ECDH, расшифровывает «доказательство», проверяет echo nonce и сохраняет конфиг.
    /// </summary>
    private void HandleAuthAck(byte[] buffer, int length)
    {
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

        TunnelCipher? cipher;
        ClientConfig? config;
        if (!TryParseAuthAck(buffer, length, nonce, ephemeral, out cipher, out config))
        {
            Metrics.CountBadFrame();
            Console.WriteLine("[auth] [!] AuthAck не прошёл проверку (неверный echo nonce или ключ).");
            return;
        }

        Cipher = cipher;
        Config = config;
        Metrics.SetAuthorized(true);
        ServerTcp.Set(config!.Protocol == TunnelProtocol.Tcp);
        Interlocked.Exchange(ref _lastPongTicks, DateTime.UtcNow.Ticks);

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
                          $"protocol={config.Protocol}.");
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

            // Внешний слой маскировки (если включен): без верного wire-ключа
            // датаграмма не читается. Расхождение настроек сторон даёт понятные
            // подсказки в логе.
            byte[] data;
            if (Wire != null)
            {
                var outcome = Wire.Unwrap(result.Buffer, result.Buffer.Length, out data!);
                if (outcome == WireOutcome.Unknown)
                {
                    LogMaskingMismatch(result.Buffer, result.Buffer.Length, "на сервере выключена обфускация (obfuscation=false) или старая версия ПО");
                    Metrics.CountBadFrame();
                    continue;
                }

                if (outcome == WireOutcome.Closed)
                    continue;

                if (outcome == WireOutcome.Handshake)
                {
                    // Наш служебный пакет без кадра туннеля: подтверждения, PING,
                    // CRYPTO. Это не ошибка и не трафик игры.
                    continue;
                }
            }
            else
            {
                data = result.Buffer;
                if (Frame.PeekFrameType(data, data.Length) == null)
                {
                    LogMaskingMismatch(data, data.Length, "на сервере включена обфускация, а у клиента она отключена (--wire-obfuscation off)");
                    Metrics.CountBadFrame();
                    continue;
                }
            }

            var frameType = Frame.PeekFrameType(data, data.Length);
            if (frameType == Frame.TypeAuthAck)
            {
                HandleAuthAck(data, data.Length);
                continue;
            }

            var cipher = Cipher;
            if (cipher == null)
                continue;

            if (frameType == Frame.TypePong)
            {
                // Сервер каждым PONG сообщает, включено ли у него TCP-проксирование.
                if (Frame.TryDecodePong(data, data.Length, cipher, _lastPingToken.Length, out _, out var tcpFlag))
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

            await HandleProtocolFrameAsync(frameType, data, data.Length);
        }
    }

    /// <summary>
    /// Раз в несколько секунд объясняет, из-за чего датаграмма не читается. Если по
    /// заголовку видно, что это пакет QUIC, — сразу называем вероятную причину:
    /// режимы маскировки на клиенте и сервере разошлись.
    /// </summary>
    private void LogMaskingMismatch(byte[] datagram, int length, string reason)
    {
        var nowTicks = DateTime.UtcNow.Ticks;
        var prev = Interlocked.Read(ref _lastMaskingLogTicks);
        if (nowTicks - prev < TimeSpan.FromSeconds(5).Ticks)
            return;
        if (Interlocked.CompareExchange(ref _lastMaskingLogTicks, nowTicks, prev) != prev)
            return;

        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Датаграмма не прочитана — {reason}." +
                          (WireObfuscator.LooksLikeQuic(datagram, length)
                              ? " Похоже на пакет QUIC: проверьте, что --wire-obfuscation и --quic-sni у клиента и сервера совпадают."
                              : string.Empty));
    }

    /// <summary>
    /// Сердцебиение: отправляет прокси-серверу PING через случайный интервал
    /// (7–15 с) с маркером случайной длины. Нерегулярные интервалы и размер
    /// делают служебный трафик неотличимым от данных. Если PONG давно не было
    /// (30 с) — сессия протухла: выполняем повторную авторизацию
    /// (новый Auth/AuthAck и сессионный ключ).
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
                    var token = new byte[16 + Random.Shared.Next(49)];
                    Random.Shared.NextBytes(token);
                    _lastPingToken = token;

                    var ping = Frame.EncodeControl(Frame.TypePing, token, cipher);
                    await Tunnel.SendAsync(SealFrame(ping), ProxyServer);
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
                var delay = HeartbeatMinInterval.TotalMilliseconds +
                            Random.Shared.NextDouble() * (HeartbeatMaxInterval - HeartbeatMinInterval).TotalMilliseconds;
                await Task.Delay(TimeSpan.FromMilliseconds(delay), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>
    /// Собирает кадр Auth из произвольных nonce и эфемерного ключа (общая часть
    /// стартового рукопожатия и повторной авторизации).
    /// </summary>
    private static byte[] BuildAuth(ECDsa identityKey, ECDiffieHellman ephemeral, byte[] nonce)
    {
        var (ephX, ephY) = TunnelKeys.ExportPoint(ephemeral);
        var payload = TunnelKeys.BuildAuthPayload(ephX, ephY, nonce);
        var signature = TunnelKeys.Sign(identityKey, payload);
        return Frame.EncodeAuth(TunnelKeys.AuthVersion, ephX, ephY, nonce, signature);
    }

    /// <summary>
    /// Разбирает AuthAck: выводит сессионный ключ из ECDH, расшифровывает
    /// «доказательство» и проверяет echo nonce. Общее для стартового прямого
    /// рукопожатия (фабрика) и повторной авторизации через цикл приёма.
    /// </summary>
    private static bool TryParseAuthAck(
        byte[] buffer,
        int length,
        byte[] nonce,
        ECDiffieHellman ephemeral,
        out TunnelCipher? cipher,
        out ClientConfig? config)
    {
        cipher = null;
        config = null;
        if (!Frame.TryDecodeAuthAck(buffer, length, out var sX, out var sY, out var wrappedProof))
            return false;

        try
        {
            var sessionKey = TunnelKeys.DeriveSessionKey(ephemeral, sX, sY);
            try
            {
                cipher = new TunnelCipher(sessionKey);
                return ClientConfig.TryDecodeProof(nonce, cipher, wrappedProof, out config);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sessionKey);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[auth] [!] Не удалось установить сессию: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Ожидает одну датаграмму с ограничением по времени (без запуска параллельного
    /// приёма — используется ТОЛЬКО до старта цикла приёма). Возвращает null по таймауту.
    /// </summary>
    private static async Task<(byte[] Data, IPEndPoint From)?> ReceiveAuthAckAsync(UdpClient tunnel, TimeSpan timeout)
    {
        return await Task.Run<(byte[], IPEndPoint)?>(() =>
        {
            var ep = new IPEndPoint(IPAddress.Any, 0);
            try
            {
                tunnel.Client.ReceiveTimeout = (int)Math.Min(Math.Max(timeout.TotalMilliseconds, 1), int.MaxValue);
                var data = tunnel.Receive(ref ep);
                return (data, ep);
            }
            catch (SocketException)
            {
                return null;
            }
            catch (ObjectDisposedException)
            {
                return null;
            }
        });
    }

    public override void Dispose()
    {
        DisposeComponents();
        Work.Dispose();
        Tunnel.Dispose();
        _identityKey.Dispose();
    }
}