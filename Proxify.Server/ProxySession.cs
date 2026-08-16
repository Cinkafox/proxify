using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using Proxify.Common;

namespace Proxify.Server;

/// <summary>
/// Текущее состояние сессии проксирования на прокси-сервере (машина A).
///
/// Владеет конфигурацией, сокетами, очередями воркеров и всеми текущими
/// данными сессии: адрес прокси-клиента (машина B), известные игроки,
/// TCP-соединения реальных клиентов. Здесь же — вся обработка пакетов
/// игроков и кадров туннеля.
/// </summary>
public sealed class ProxySession : IDisposable
{
    private readonly object _endpointLock = new();
    private IPEndPoint? _proxyClient;
    private long _lastNoClientLogTicks;
    private long _lastRejectedLogTicks;
    private long _nextTcpConnId;

    public int ListenPort { get; }
    public int TunnelPort { get; }
    public bool TcpEnabled { get; }
    public TunnelCipher Cipher { get; }

    /// <summary>
    /// Разрешённый адрес прокси-клиента (машина B). Если задан, сервер принимает
    /// кадры туннеля только с этого IP. Если не задан — сервер принимает первого
    /// аутентифицированного клиента и дальше фиксирует его IP (сменить IP может
    /// только явный --client-ip / перезапуск сервера).
    /// </summary>
    public IPAddress? AllowedClientIp { get; }

    public TunnelStats Stats { get; } = new();
    public UdpClient Udp { get; }
    public UdpClient Tunnel { get; }
    public TcpListener? TcpListener { get; }

    /// <summary>Параллельная обработка пакетов: игроки -> прокси-клиент.</summary>
    public AsyncWorkQueue PlayerWork { get; }

    /// <summary>Параллельная обработка кадров: прокси-клиент -> игроки.</summary>
    public AsyncWorkQueue TunnelWork { get; }

    /// <summary>Игроки, уже контактировавшие с сервером (для однократного [диагностика]).</summary>
    public ConcurrentDictionary<IPEndPoint, byte> SeenClients { get; } = new();

    /// <summary>TCP-соединения реальных клиентов: connId -> сокет.</summary>
    public ConcurrentDictionary<uint, TcpClient> TcpClients { get; } = new();

    /// <summary>Сериализация записи в конкретное TCP-соединение (connId -> семафор).</summary>
    public ConcurrentDictionary<uint, SemaphoreSlim> TcpWriteLocks { get; } = new();

    public ProxySession(int listenPort, int tunnelPort, bool tcpEnabled, IPAddress? allowedClientIp, TunnelCipher cipher)
    {
        ListenPort = listenPort;
        TunnelPort = tunnelPort;
        TcpEnabled = tcpEnabled;
        AllowedClientIp = allowedClientIp;
        Cipher = cipher;

        Udp = new UdpClient(new IPEndPoint(IPAddress.Any, listenPort));
        Tunnel = new UdpClient(new IPEndPoint(IPAddress.Any, tunnelPort));
        TcpListener = tcpEnabled ? new TcpListener(IPAddress.Any, listenPort) : null;

        var workerCount = Math.Clamp(Environment.ProcessorCount, 2, 8);
        PlayerWork = new AsyncWorkQueue(workerCount);
        TunnelWork = new AsyncWorkQueue(workerCount);
    }

    public void PrintBanner()
    {
        Console.WriteLine("=== Прокси-сервер (RealIP) ===");
        Console.WriteLine($"Порт для клиентов игры    : {ListenPort}");
        Console.WriteLine($"Порт туннеля              : {TunnelPort}");
        Console.WriteLine($"TCP-проксирование        : {(TcpEnabled ? $"вкл (порт {ListenPort})" : "выкл")}");
        Console.WriteLine($"Разрешённый прокси-клиент: {AllowedClientIp?.ToString() ?? "первый (автообучение)"}");
        Console.WriteLine("Шифрование туннеля        : вкл (AES-256-GCM)");
        Console.WriteLine();
        Console.WriteLine("Открытые порты нужны только у машины A: игроки идут на --port,");
        Console.WriteLine("а прокси-клиент (машина B) сам устанавливает исходящее соединение");
        Console.WriteLine("на --tunnel-port. На машине B открывать порты не требуется.");
        Console.WriteLine();
        if (AllowedClientIp == null)
        {
            Console.WriteLine("Адрес прокси-клиента определяется автоматически по первому кадру туннеля");
            Console.WriteLine("(PING или данные) и фиксируется: только этот IP может выступать прокси-клиентом.");
        }
        else
        {
            Console.WriteLine($"Прокси-клиентом может быть только {AllowedClientIp} — кадры с других адресов отвергаются.");
        }
        Console.WriteLine("Сервер принимает только кадры, аутентифицированные ключом, поэтому подменить");
        Console.WriteLine("адрес туннеля другой машиной нельзя.");
        Console.WriteLine();
        Console.WriteLine("Ожидание пакетов от клиентов игры и кадров туннеля...");
        Console.WriteLine("При запуске прокси-клиент отправит PING на порт туннеля — сервер ответит PONG");
        Console.WriteLine("и выведет диагностику первого контакта.");
        Console.WriteLine();
    }

    public async Task RunAsync()
    {
        var loops = new List<Task> { Task.Run(PlayerLoop), Task.Run(TunnelLoop) };
        if (TcpEnabled)
            loops.Add(Task.Run(TcpLoop));
        await Task.WhenAll(loops);
    }

    private async Task TcpLoop()
    {
        TcpListener!.Start();
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Слушаем TCP-порт игроков: {ListenPort}");

        while (true)
        {
            TcpClient client;
            try
            {
                client = await TcpListener.AcceptTcpClientAsync();
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [warn] Ошибка приёма TCP-подключения: {ex.Message}");
                continue;
            }
            catch (ObjectDisposedException)
            {
                break;
            }

            // Ждём, пока известен адрес прокси-клиента, чтобы кадры TcpOpen/TcpData не потерялись.
            IPEndPoint? proxy;
            while ((proxy = CurrentProxyClient()) == null)
            {
                try
                {
                    await Task.Delay(200);
                }
                catch (ObjectDisposedException)
                {
                    client.Close();
                    return;
                }
            }

            var connId = NextTcpConnId();
            client.NoDelay = true;
            TcpClients[connId] = client;

            var remote = (IPEndPoint)client.Client.RemoteEndPoint!;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Новый TCP-клиент {remote} (connId {connId}).");

            var open = Frame.EncodeTcpOpen(remote.Address, (ushort)remote.Port, connId, Cipher);
            await Tunnel.SendAsync(open, proxy!);

            _ = Task.Run(() => HandleTcpClientAsync(client, connId));
        }
    }

    private async Task HandleTcpClientAsync(TcpClient client, uint connId)
    {
        try
        {
            var stream = client.GetStream();
            var buffer = new byte[16384];
            while (true)
            {
                int read;
                try
                {
                    read = await stream.ReadAsync(buffer);
                }
                catch (IOException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }

                if (read <= 0)
                    break;

                var proxy = CurrentProxyClient();
                if (proxy == null)
                    continue;

                Interlocked.Increment(ref Stats.PacketsIn);
                Interlocked.Increment(ref Stats.PacketsOut);
                var frame = Frame.EncodeTcpData(connId, buffer.AsSpan(0, read), Cipher);
                await Tunnel.SendAsync(frame, proxy);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] TCP-клиент (connId {connId}): {ex.Message}");
        }
        finally
        {
            await CloseTcpWithRemoteAsync(connId);
        }
    }

    private void CloseTcpLocally(uint connId)
    {
        if (TcpClients.TryRemove(connId, out var client))
        {
            try
            {
                client.Close();
            }
            catch
            {
                // уже закрыт
            }
        }

        if (TcpWriteLocks.TryRemove(connId, out var writeLock))
            writeLock.Dispose();
    }

    private async Task CloseTcpWithRemoteAsync(uint connId)
    {
        CloseTcpLocally(connId);

        var proxy = CurrentProxyClient();
        if (proxy == null)
            return;

        try
        {
            await Tunnel.SendAsync(Frame.EncodeTcpClose(connId, Cipher), proxy);
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Соединение {connId} закрыто, прокси-клиент уведомлён.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] Отправка TcpClose (connId {connId}): {ex.Message}");
        }
    }

    private void LearnProxyClient(IPEndPoint from)
    {
        bool changed;
        lock (_endpointLock)
        {
            changed = _proxyClient == null || !_proxyClient.Equals(from);
            if (changed)
                _proxyClient = from;
        }

        if (changed)
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Прокси-клиент (машина B) определён: {from}.");
    }

    private IPEndPoint? CurrentProxyClient()
    {
        lock (_endpointLock)
        {
            return _proxyClient;
        }
    }

    /// <summary>
    /// Проверка, что кадр пришёл от разрешённого прокси-клиента.
    /// Либо адрес задан явно (--client-ip), либо сервер фиксирует IP первого
    /// аутентифицированного клиента и не даёт другой машине перехватить сессию
    /// (смена порта того же клиента после NAT допустима).
    /// </summary>
    private bool IsAllowedClient(IPEndPoint from)
    {
        if (AllowedClientIp != null)
            return from.Address.Equals(AllowedClientIp);

        var current = CurrentProxyClient();
        return current == null || current.Address.Equals(from.Address);
    }

    /// <summary>
    /// Логирование отвергнутых кадров от посторонних клиентов (не чаще раза в 5 секунд).
    /// </summary>
    private void LogRejectedClient(IPEndPoint from)
    {
        var nowTicks = DateTime.UtcNow.Ticks;
        var prev = Interlocked.Read(ref _lastRejectedLogTicks);
        if (nowTicks - prev < TimeSpan.FromSeconds(5).Ticks)
            return;
        if (Interlocked.CompareExchange(ref _lastRejectedLogTicks, nowTicks, prev) != prev)
            return;

        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Отвергнут кадр от постороннего адреса {from} — другой клиент не может подключиться.");
    }

    private uint NextTcpConnId() => (uint)Interlocked.Increment(ref _nextTcpConnId);

    private async Task PlayerLoop()
    {
        while (true)
        {
            UdpReceiveResult result;
            try
            {
                result = await Udp.ReceiveAsync();
            }
            catch (SocketException ex)
            {
                // Windows может вернуть WSAECONNRESET (10054) на UDP-сокете после ICMP
                // "порт недоступен" (например, если прокси-клиент ещё не запущен).
                // Такие ошибки преходящи — продолжаем принимать дальше.
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [warn] Ошибка приёма (игроки): {ex.Message}");
                continue;
            }
            catch (ObjectDisposedException)
            {
                break;
            }

            // Пакет обрабатывается воркером параллельно с другими пакетами.
            try
            {
                await PlayerWork.EnqueueAsync(() => HandlePlayerPacket(result.RemoteEndPoint, result.Buffer));
            }
            catch (ChannelClosedException)
            {
                break;
            }
        }
    }

    private async Task TunnelLoop()
    {
        while (true)
        {
            UdpReceiveResult result;
            try
            {
                result = await Tunnel.ReceiveAsync();
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [warn] Ошибка приёма (туннель): {ex.Message}");
                continue;
            }
            catch (ObjectDisposedException)
            {
                break;
            }

            // Кадр обрабатывается воркером параллельно с другими кадрами.
            try
            {
                await TunnelWork.EnqueueAsync(() => HandleTunnelFrame(result.RemoteEndPoint, result.Buffer));
            }
            catch (ChannelClosedException)
            {
                break;
            }
        }
    }

    private async Task HandlePlayerPacket(IPEndPoint from, byte[] data)
    {
        try
        {
            // Пакет от реального клиента игры -> завернуть в кадр и отправить прокси-клиенту
            var proxyClientEndpoint = CurrentProxyClient();
            if (proxyClientEndpoint == null)
            {
                var nowTicks = DateTime.UtcNow.Ticks;
                var prev = Interlocked.Read(ref _lastNoClientLogTicks);
                if (nowTicks - prev >= TimeSpan.FromSeconds(5).Ticks)
                {
                    Interlocked.CompareExchange(ref _lastNoClientLogTicks, nowTicks, prev);
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Прокси-клиент ещё не установил связь — пакеты от игроков отбрасываются.");
                }
                return;
            }

            if (SeenClients.TryAdd(from, 0))
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Новый игрок подключился: {from}.");
            Interlocked.Increment(ref Stats.PacketsIn);
            Interlocked.Increment(ref Stats.PacketsOut);
            var frame = Frame.EncodeData(from.Address, (ushort)from.Port, data, Cipher);
            await Tunnel.SendAsync(frame, proxyClientEndpoint);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] {ex.Message}");
        }
    }

    private async Task HandleTunnelFrame(IPEndPoint from, byte[] data)
    {
        try
        {
            // Дополнительная проверка источника: только разрешённый прокси-клиент
            // (--client-ip либо зафиксированный IP первого клиента) может слать кадры.
            if (!IsAllowedClient(from))
            {
                Interlocked.Increment(ref Stats.BadFrames);
                LogRejectedClient(from);
                return;
            }

            var frameType = Frame.PeekFrameType(data, data.Length);

            // --- Служебные кадры диагностики (PING/PONG) ---
            if (frameType == Frame.TypePing)
            {
                if (Frame.TryDecodeControl(data, data.Length, Frame.TypePing, Cipher, out var token))
                {
                    LearnProxyClient(from);
                    await Tunnel.SendAsync(Frame.EncodePong(token, TcpEnabled, Cipher), from);
                }
                else
                {
                    Interlocked.Increment(ref Stats.BadFrames);
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] PING от {from} не разобран (возможно, несовпадение ключа).");
                }
                return;
            }
            if (frameType == Frame.TypePong)
            {
                return;
            }

            // --- TCP-кадры прокси-клиента (ответы игрового сервера по TCP) ---
            if (frameType == Frame.TypeTcpData)
            {
                if (Frame.TryDecodeTcpData(data, data.Length, Cipher, out var connId, out var payload))
                {
                    LearnProxyClient(from);
                    if (TcpClients.TryGetValue(connId, out var tcpClient))
                    {
                        var writeLock = TcpWriteLocks.GetOrAdd(connId, _ => new SemaphoreSlim(1, 1));
                        try
                        {
                            await writeLock.WaitAsync();
                            try
                            {
                                await tcpClient.GetStream().WriteAsync(payload);
                                Interlocked.Increment(ref Stats.RepliesRelayed);
                            }
                            finally
                            {
                                writeLock.Release();
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] Запись TCP-клиенту (connId {connId}): {ex.Message}");
                            CloseTcpLocally(connId);
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] TcpData для неизвестного connId {connId}.");
                    }
                }
                else
                {
                    Interlocked.Increment(ref Stats.BadFrames);
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать TcpData от {from}.");
                }
                return;
            }

            if (frameType == Frame.TypeTcpClose)
            {
                if (Frame.TryDecodeTcpClose(data, data.Length, Cipher, out var connId))
                {
                    LearnProxyClient(from);
                    CloseTcpLocally(connId);
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Закрыто прокси-клиентом: connId {connId}.");
                }
                else
                {
                    Interlocked.Increment(ref Stats.BadFrames);
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать TcpClose от {from}.");
                }
                return;
            }

            if (frameType == Frame.TypeTcpOpen)
            {
                // Прокси-клиент не инициирует TCP-соединения; валидный кадр лишь обновляет адрес туннеля.
                LearnProxyClient(from);
                return;
            }

            // --- Кадры данных от прокси-клиента (ответы игрового сервера) ---
            if (frameType is Frame.TypeData or Frame.TypeDataEncrypted)
            {
                if (frameType == Frame.TypeData)
                {
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен незашифрованный кадр, но сервер работает только с шифрованием. Проверьте ключ у прокси-клиента.");
                    Interlocked.Increment(ref Stats.BadFrames);
                    return;
                }

                if (Frame.TryDecodeData(data, data.Length, Cipher, out var clientIp, out var clientPort, out var payload))
                {
                    LearnProxyClient(from);
                    var target = new IPEndPoint(clientIp, clientPort);
                    Interlocked.Increment(ref Stats.PacketsIn);
                    Interlocked.Increment(ref Stats.RepliesRelayed);
                    await Udp.SendAsync(payload, target);
                }
                else
                {
                    Interlocked.Increment(ref Stats.BadFrames);
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать кадр от {from}.");
                }
                return;
            }

            // Посторонний пакет на порт туннеля
            Interlocked.Increment(ref Stats.BadFrames);
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен посторонний пакет на порт туннеля от {from} (не кадр туннеля).");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] {ex.Message}");
        }
    }

    public void Dispose()
    {
        PlayerWork.Dispose();
        TunnelWork.Dispose();
        TcpListener?.Stop();
        Tunnel.Dispose();
        Udp.Dispose();
    }
}
