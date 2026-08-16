using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Channels;
using Proxify.Common;

namespace Proxify.Server;

/// <summary>
/// Состояние одного зарегистрированного прокси-клиента на прокси-сервере (машина A).
///
/// Владеет UDP-сокетом игроков (порт <see cref="ClientConfig.Port"/>), опциональным
/// TCP-прослушивателем, зарегистрированным публичным ключом и текущей сессией
/// (адрес туннеля клиента + сессионный ключ). Сессия устанавливается кадром Auth,
/// а ключ шифрования выводится из ECDH и меняется при каждой авторизации.
/// </summary>
public sealed class ClientRuntime : IDisposable
{
    private TunnelCipher? _cipher;
    private IPEndPoint? _tunnelEndpoint;
    private long _lastActivityTicks;

    public ClientConfig Config { get; }
    public ECDsa RegisteredKey { get; }
    public UdpClient Udp { get; }
    public TcpListener? TcpListener { get; }

    /// <summary>TCP-соединения реальных клиентов: connId -> сокет.</summary>
    public ConcurrentDictionary<uint, TcpClient> TcpClients { get; } = new();

    /// <summary>Сериализация записи в конкретное TCP-соединение (connId -> семафор).</summary>
    public ConcurrentDictionary<uint, SemaphoreSlim> TcpWriteLocks { get; } = new();

    /// <summary>Игроки, уже контактировавшие с сервером (для однократного [диагностика]).</summary>
    public ConcurrentDictionary<IPEndPoint, byte> SeenClients { get; } = new();

    public TunnelCipher? Cipher => Volatile.Read(ref _cipher);
    public IPEndPoint? TunnelEndpoint => Volatile.Read(ref _tunnelEndpoint);
    public long LastActivityTicks => Interlocked.Read(ref _lastActivityTicks);

    public ClientRuntime(ClientConfig config)
    {
        Config = config;
        RegisteredKey = TunnelKeys.ImportPublicPem(config.PublicKeyPem);
        Udp = new UdpClient(new IPEndPoint(IPAddress.Any, config.Port));
        if (config.TcpEnabled)
            TcpListener = new TcpListener(IPAddress.Any, config.TcpPort);
    }

    /// <summary>
    /// Устанавливает новую сессию: адрес туннеля клиента и ключ шифрования.
    /// Вызывается при успешной авторизации (кадр Auth).
    /// </summary>
    public void SetSession(IPEndPoint endpoint, TunnelCipher cipher)
    {
        Interlocked.Exchange(ref _tunnelEndpoint, endpoint);
        Volatile.Write(ref _cipher, cipher);
        Interlocked.Exchange(ref _lastActivityTicks, DateTime.UtcNow.Ticks);
    }

    public void TouchActivity() => Interlocked.Exchange(ref _lastActivityTicks, DateTime.UtcNow.Ticks);

    public string DisplayName => string.IsNullOrWhiteSpace(Config.Name) ? "(без имени)" : Config.Name;

    public void Dispose()
    {
        RegisteredKey.Dispose();
        Udp.Dispose();
        TcpListener?.Stop();
        foreach (var client in TcpClients.Values)
            client.Close();
        foreach (var writeLock in TcpWriteLocks.Values)
            writeLock.Dispose();
        TcpClients.Clear();
        TcpWriteLocks.Clear();
    }
}

/// <summary>
/// Прокси-сервер (машина A): обслуживает несколько прокси-клиентов одновременно.
///
/// У каждого клиента свой UDP-порт для игроков и свой зарегистрированный ключ.
/// Туннельный UDP-сокет общий: клиент опознаётся по подписи кадра Auth, после
/// чего сессия привязывается к адресу туннеля клиента, а все кадры от этого
/// адреса расшифровываются ключом данной сессии.
/// </summary>
public sealed class ProxySession : IDisposable
{
    private readonly ConcurrentDictionary<IPEndPoint, ClientRuntime> _sessions = new();
    private long _nextTcpConnId;
    private long _lastUnknownLogTicks;

    public int TunnelPort { get; }
    public List<ClientRuntime> Clients { get; } = new();
    public UdpClient Tunnel { get; }
    public TunnelStats Stats { get; } = new();
    public AsyncWorkQueue TunnelWork { get; }

    public ProxySession(List<ClientConfig> configs, int tunnelPort)
    {
        TunnelPort = tunnelPort;
        Tunnel = new UdpClient(new IPEndPoint(IPAddress.Any, tunnelPort));
        TunnelWork = new AsyncWorkQueue(Math.Clamp(Environment.ProcessorCount, 2, 8));

        foreach (var config in configs)
            Clients.Add(new ClientRuntime(config));
    }

    public void PrintBanner()
    {
        Console.WriteLine("=== Прокси-сервер (RealIP) ===");
        Console.WriteLine($"Порт туннеля                : {TunnelPort}");
        foreach (var c in Clients)
        {
            Console.WriteLine($"  Клиент '{c.DisplayName}':");
            Console.WriteLine($"    игроки (UDP) : {c.Config.Port}");
            Console.WriteLine($"    игровой сервер: {c.Config.GameIp}:{c.Config.GamePort} (на машине B)");
            Console.WriteLine($"    TCP-проксирование: {(c.Config.TcpEnabled ? $"вкл (порт {c.Config.TcpPort})" : "выкл")}");
            Console.WriteLine($"    публичный ключ: {DescribeKey(c.Config.PublicKeyPem)}");
            Console.WriteLine($"    статус        : {(c.Cipher == null ? "ждёт авторизации" : "сессия активна")}");
        }
        Console.WriteLine();
        Console.WriteLine("Шифрование: ECDSA P-256 (аутентификация) + ECDH P-256 + HKDF-SHA256 + AES-256-GCM");
        Console.WriteLine();
        Console.WriteLine("Открытые порты нужны только у машины A: игроки идут на свой UDP-порт клиента,");
        Console.WriteLine("а прокси-клиенты (машины B) сами устанавливают исходящее соединение на --tunnel-port.");
        Console.WriteLine("На машине B открывать порты не требуется.");
        Console.WriteLine();
        Console.WriteLine("Сервер принимает только авторизованных клиентов: подпись кадра Auth проверяется");
        Console.WriteLine("зарегистрированным публичным ключом. Каждый клиент получает свою сессию.");
        Console.WriteLine();
        Console.WriteLine("Ожидание кадров от прокси-клиентов...");
        Console.WriteLine();
    }

    public async Task RunAsync()
    {
        var loops = new List<Task> { Task.Run(TunnelLoop) };
        foreach (var client in Clients)
        {
            loops.Add(Task.Run(() => PlayerLoop(client)));
            if (client.TcpListener != null)
                loops.Add(Task.Run(() => TcpLoop(client)));
        }
        await Task.WhenAll(loops);
    }

    private async Task TcpLoop(ClientRuntime client)
    {
        client.TcpListener!.Start();
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Клиент '{client.DisplayName}': слушаем TCP-порт игроков {client.Config.TcpPort}.");

        while (true)
        {
            TcpClient tcpClient;
            try
            {
                tcpClient = await client.TcpListener.AcceptTcpClientAsync();
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

            // Ждём, пока клиент авторизуется, чтобы кадры TcpOpen/TcpData не потерялись.
            IPEndPoint? proxy;
            TunnelCipher? cipher;
            while ((proxy = client.TunnelEndpoint) == null || (cipher = client.Cipher) == null)
            {
                try
                {
                    await Task.Delay(200);
                }
                catch (ObjectDisposedException)
                {
                    tcpClient.Close();
                    return;
                }
            }

            var connId = NextTcpConnId();
            tcpClient.NoDelay = true;
            client.TcpClients[connId] = tcpClient;

            var remote = (IPEndPoint)tcpClient.Client.RemoteEndPoint!;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Клиент '{client.DisplayName}': новый TCP-клиент {remote} (connId {connId}).");

            var open = Frame.EncodeTcpOpen(remote.Address, (ushort)remote.Port, connId, cipher);
            await Tunnel.SendAsync(open, proxy);

            _ = Task.Run(() => HandleTcpClientAsync(client, tcpClient, connId));
        }
    }

    private async Task HandleTcpClientAsync(ClientRuntime client, TcpClient tcpClient, uint connId)
    {
        try
        {
            var stream = tcpClient.GetStream();
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

                var proxy = client.TunnelEndpoint;
                var cipher = client.Cipher;
                if (proxy == null || cipher == null)
                    continue;

                Interlocked.Increment(ref Stats.PacketsIn);
                Interlocked.Increment(ref Stats.PacketsOut);
                var frame = Frame.EncodeTcpData(connId, buffer.AsSpan(0, read), cipher);
                await Tunnel.SendAsync(frame, proxy);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] TCP-клиент (connId {connId}): {ex.Message}");
        }
        finally
        {
            await CloseTcpWithRemoteAsync(client, connId);
        }
    }

    private void CloseTcpLocally(ClientRuntime client, uint connId)
    {
        if (client.TcpClients.TryRemove(connId, out var tcpClient))
        {
            try
            {
                tcpClient.Close();
            }
            catch
            {
                // уже закрыт
            }
        }

        if (client.TcpWriteLocks.TryRemove(connId, out var writeLock))
            writeLock.Dispose();
    }

    private async Task CloseTcpWithRemoteAsync(ClientRuntime client, uint connId)
    {
        CloseTcpLocally(client, connId);

        var proxy = client.TunnelEndpoint;
        var cipher = client.Cipher;
        if (proxy == null || cipher == null)
            return;

        try
        {
            await Tunnel.SendAsync(Frame.EncodeTcpClose(connId, cipher), proxy);
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Соединение {connId} закрыто, прокси-клиент уведомлён.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] Отправка TcpClose (connId {connId}): {ex.Message}");
        }
    }

    private uint NextTcpConnId() => (uint)Interlocked.Increment(ref _nextTcpConnId);

    private async Task PlayerLoop(ClientRuntime client)
    {
        while (true)
        {
            UdpReceiveResult result;
            try
            {
                result = await client.Udp.ReceiveAsync();
            }
            catch (SocketException ex)
            {
                // Windows может вернуть WSAECONNRESET (10054) на UDP-сокете после ICMP
                // "порт недоступен". Такие ошибки преходящи — продолжаем принимать дальше.
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [warn] Ошибка приёма (игроки, клиент '{client.DisplayName}'): {ex.Message}");
                continue;
            }
            catch (ObjectDisposedException)
            {
                break;
            }

            try
            {
                await TunnelWork.EnqueueAsync(() => HandlePlayerPacket(client, result.RemoteEndPoint, result.Buffer));
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

    private async Task HandlePlayerPacket(ClientRuntime client, IPEndPoint from, byte[] data)
    {
        try
        {
            var cipher = client.Cipher;
            var proxyEndpoint = client.TunnelEndpoint;
            if (cipher == null || proxyEndpoint == null)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Клиент '{client.DisplayName}' ещё не авторизовался — пакет от игрока {from} отброшен.");
                return;
            }

            if (client.SeenClients.TryAdd(from, 0))
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Клиент '{client.DisplayName}': новый игрок подключился: {from}.");

            Interlocked.Increment(ref Stats.PacketsIn);
            Interlocked.Increment(ref Stats.PacketsOut);
            var frame = Frame.EncodeData(from.Address, (ushort)from.Port, data, cipher);
            await Tunnel.SendAsync(frame, proxyEndpoint);
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
            var frameType = Frame.PeekFrameType(data, data.Length);

            // --- Рукопожатие: кадр Auth (всегда plaintext) ---
            if (frameType == Frame.TypeAuth)
            {
                HandleAuth(from, data);
                return;
            }

            // --- Остальные кадры принимаются только от авторизованной сессии ---
            if (!_sessions.TryGetValue(from, out var client) || client.Cipher == null)
            {
                Interlocked.Increment(ref Stats.BadFrames);
                LogUnknownFrame(from);
                return;
            }

            var cipher = client.Cipher;

            // --- Служебные кадры диагностики (PING/PONG) ---
            if (frameType == Frame.TypePing)
            {
                if (Frame.TryDecodeControl(data, data.Length, Frame.TypePing, cipher, out var token))
                {
                    client.TouchActivity();
                    await Tunnel.SendAsync(Frame.EncodePong(token, client.Config.TcpEnabled, cipher), from);
                }
                else
                {
                    Interlocked.Increment(ref Stats.BadFrames);
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] PING от {from} не разобран (возможно, сессия устарела).");
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
                if (Frame.TryDecodeTcpData(data, data.Length, cipher, out var connId, out var payload))
                {
                    client.TouchActivity();
                    await HandleTcpDataAsync(client, connId, payload);
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
                if (Frame.TryDecodeTcpClose(data, data.Length, cipher, out var connId))
                {
                    client.TouchActivity();
                    CloseTcpLocally(client, connId);
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
                // Прокси-клиент не инициирует TCP-соединения; кадр лишь обновляет активность.
                client.TouchActivity();
                return;
            }

            // --- Кадры данных от прокси-клиента (ответы игрового сервера) ---
            if (frameType is Frame.TypeData or Frame.TypeDataEncrypted)
            {
                if (frameType == Frame.TypeData)
                {
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен незашифрованный кадр, но сервер работает только с шифрованием. Проверьте конфиг у прокси-клиента.");
                    Interlocked.Increment(ref Stats.BadFrames);
                    return;
                }

                if (Frame.TryDecodeData(data, data.Length, cipher, out var clientIp, out var clientPort, out var payload))
                {
                    client.TouchActivity();
                    var target = new IPEndPoint(clientIp, clientPort);
                    Interlocked.Increment(ref Stats.PacketsIn);
                    Interlocked.Increment(ref Stats.RepliesRelayed);
                    await client.Udp.SendAsync(payload, target);
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

    /// <summary>
    /// Обрабатывает кадр Auth: проверяет подпись по всем зарегистрированным ключам,
    /// устанавливает сессию (ECDH + сессионный ключ) и отвечает AuthAck.
    /// </summary>
    private void HandleAuth(IPEndPoint from, byte[] data)
    {
        if (!Frame.TryDecodeAuth(data, data.Length, out var version, out var ephX, out var ephY, out var nonce, out var signature))
        {
            Interlocked.Increment(ref Stats.BadFrames);
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать кадр Auth от {from}.");
            return;
        }

        if (version != TunnelKeys.AuthVersion)
        {
            Interlocked.Increment(ref Stats.BadFrames);
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Auth от {from} с неизвестной версией {version}.");
            return;
        }

        // Ищем клиента по подписи: подписать кадр может только владелец закрытого ключа.
        ClientRuntime? found = null;
        var payload = TunnelKeys.BuildAuthPayload(ephX, ephY, nonce);
        foreach (var candidate in Clients)
        {
            if (TunnelKeys.Verify(candidate.RegisteredKey, payload, signature))
            {
                found = candidate;
                break;
            }
        }

        if (found == null)
        {
            Interlocked.Increment(ref Stats.BadFrames);
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Auth от {from}: подпись не соответствует ни одному зарегистрированному ключу.");
            return;
        }

        byte[] sessionKey;
        byte[] sX;
        byte[] sY;
        using (var ephemeral = TunnelKeys.CreateEphemeral())
        {
            (sX, sY) = TunnelKeys.ExportPoint(ephemeral);
            sessionKey = TunnelKeys.DeriveSessionKey(ephemeral, ephX, ephY);
        }

        TunnelCipher cipher;
        try
        {
            cipher = new TunnelCipher(sessionKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sessionKey);
        }

        found.SetSession(from, cipher);
        _sessions[from] = found;
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [auth] Клиент '{found.DisplayName}' авторизован: {from}.");

        var proof = found.Config.EncodeProof(nonce, cipher);
        var ack = Frame.EncodeAuthAck(sX, sY, proof);
        try
        {
            Tunnel.Send(ack, from);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] Отправка AuthAck клиенту '{found.DisplayName}': {ex.Message}");
        }
    }

    private async Task HandleTcpDataAsync(ClientRuntime client, uint connId, byte[] payload)
    {
        if (client.TcpClients.TryGetValue(connId, out var tcpClient))
        {
            var writeLock = client.TcpWriteLocks.GetOrAdd(connId, _ => new SemaphoreSlim(1, 1));
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
                CloseTcpLocally(client, connId);
            }
        }
        else
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] TcpData для неизвестного connId {connId}.");
        }
    }

    private void LogUnknownFrame(IPEndPoint from)
    {
        var nowTicks = DateTime.UtcNow.Ticks;
        var prev = Interlocked.Read(ref _lastUnknownLogTicks);
        if (nowTicks - prev < TimeSpan.FromSeconds(5).Ticks)
            return;
        if (Interlocked.CompareExchange(ref _lastUnknownLogTicks, nowTicks, prev) != prev)
            return;

        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Кадр от неавторизованного адреса {from} — клиент должен сначала выполнить Auth.");
    }

    private static string DescribeKey(string pem)
    {
        var text = pem.Trim();
        if (text.Length > 60)
            return text[..40] + "..." + text[^10..];
        return text;
    }

    public void Dispose()
    {
        TunnelWork.Dispose();
        foreach (var client in Clients)
            client.Dispose();
        Tunnel.Dispose();
    }
}
