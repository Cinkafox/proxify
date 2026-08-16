using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Channels;
using Proxify.Common;

namespace Proxify.Server;

/// <summary>
/// Обработчик кадров и пакетов одного прокси-клиента (машина B).
///
/// Привязан к данным <see cref="ClientSession"/>: принимает пакеты игроков
/// (UDP-порт игроков и TCP-подключения этого клиента) и обрабатывает кадры
/// туннеля от этого клиента (PING/PONG, TCP, данные). Туннельный UDP-сокет
/// общий для всех клиентов и владеет им <see cref="ProxyServer"/> — сюда он
/// передаётся ссылкой вместе с общей очередью обработки.
/// </summary>
public sealed class ProxySession : IDisposable
{
    private readonly ClientSession _client;
    private readonly UdpClient _tunnel;
    private readonly AsyncWorkQueue _tunnelWork;
    private readonly TunnelStats _stats;
    private long _nextTcpConnId;

    public ClientSession Client => _client;

    public ProxySession(ClientSession client, UdpClient tunnel, AsyncWorkQueue tunnelWork, TunnelStats stats)
    {
        _client = client;
        _tunnel = tunnel;
        _tunnelWork = tunnelWork;
        _stats = stats;
    }

    /// <summary>
    /// Пытается авторизовать этого клиента: проверяет подпись кадра Auth своим
    /// зарегистрированным публичным ключом. При успехе устанавливает сессию
    /// (ECDH + сессионный ключ) и отвечает AuthAck. Диспетчер уже разобрал
    /// кадр Auth и проверил версию — сюда передаются проверяемые части.
    /// </summary>
    public bool TryAuthenticate(IPEndPoint from, byte[] payload, byte[] signature, byte[] ephX, byte[] ephY, byte[] nonce)
    {
        if (!TunnelKeys.Verify(_client.RegisteredKey, payload, signature))
            return false;

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

        _client.SetSession(from, cipher);
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [auth] Клиент '{_client.DisplayName}' авторизован: {from}.");

        var proof = _client.Config.EncodeProof(nonce, cipher);
        var ack = Frame.EncodeAuthAck(sX, sY, proof);
        try
        {
            _tunnel.Send(ack, from);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] Отправка AuthAck клиенту '{_client.DisplayName}': {ex.Message}");
        }
        return true;
    }

    /// <summary>
    /// Обрабатывает кадр туннеля от этого клиента: служебные (PING/PONG),
    /// TCP-кадры (TcpData/TcpClose/TcpOpen) и кадры данных с ответами игрового
    /// сервера. Вызывается диспетчером только для авторизованной сессии.
    /// </summary>
    public async Task HandleFrameAsync(IPEndPoint from, byte[] data)
    {
        var frameType = Frame.PeekFrameType(data, data.Length);
        var cipher = _client.Cipher!;

        if (frameType == Frame.TypePing)
        {
            if (Frame.TryDecodeControl(data, data.Length, Frame.TypePing, cipher, out var token))
            {
                _client.TouchActivity();
                await _tunnel.SendAsync(Frame.EncodePong(token, _client.Config.TcpEnabled, cipher), from);
            }
            else
            {
                Interlocked.Increment(ref _stats.BadFrames);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] PING от {from} не разобран (возможно, сессия устарела).");
            }
            return;
        }

        if (frameType == Frame.TypePong)
            return;

        if (frameType == Frame.TypeTcpData)
        {
            if (Frame.TryDecodeTcpData(data, data.Length, cipher, out var connId, out var seq, out var payload))
            {
                _client.TouchActivity();
                if (_client.TcpReceivers.TryGetValue(connId, out var receiver))
                {
                    receiver.Receive(payload, seq);
                }
                else
                {
                    Interlocked.Increment(ref _stats.BadFrames);
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] TcpData для неизвестного connId {connId}.");
                }
            }
            else
            {
                Interlocked.Increment(ref _stats.BadFrames);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать TcpData от {from}.");
            }
            return;
        }

        if (frameType == Frame.TypeTcpAck)
        {
            if (Frame.TryDecodeTcpAck(data, data.Length, cipher, out var connId, out var ackSeq))
            {
                _client.TouchActivity();
                if (_client.TcpSenders.TryGetValue(connId, out var sender))
                {
                    sender.OnAck(ackSeq);
                }
                else
                {
                    Interlocked.Increment(ref _stats.BadFrames);
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] TcpAck для неизвестного connId {connId}.");
                }
            }
            else
            {
                Interlocked.Increment(ref _stats.BadFrames);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать TcpAck от {from}.");
            }
            return;
        }

        if (frameType == Frame.TypeTcpClose)
        {
            if (Frame.TryDecodeTcpClose(data, data.Length, cipher, out var connId))
            {
                _client.TouchActivity();
                CloseTcpLocally(connId);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Закрыто прокси-клиентом: connId {connId}.");
            }
            else
            {
                Interlocked.Increment(ref _stats.BadFrames);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать TcpClose от {from}.");
            }
            return;
        }

        if (frameType == Frame.TypeTcpOpen)
        {
            // Прокси-клиент не инициирует TCP-соединения; кадр лишь обновляет активность.
            _client.TouchActivity();
            return;
        }

        if (frameType is Frame.TypeData or Frame.TypeDataEncrypted)
        {
            if (frameType == Frame.TypeData)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен незашифрованный кадр, но сервер работает только с шифрованием. Проверьте конфиг у прокси-клиента.");
                Interlocked.Increment(ref _stats.BadFrames);
                return;
            }

            if (Frame.TryDecodeData(data, data.Length, cipher, out var clientIp, out var clientPort, out var payload))
            {
                _client.TouchActivity();
                var target = new IPEndPoint(clientIp, clientPort);
                Interlocked.Increment(ref _stats.PacketsIn);
                Interlocked.Increment(ref _stats.RepliesRelayed);
                await _client.Udp.SendAsync(payload, target);
            }
            else
            {
                Interlocked.Increment(ref _stats.BadFrames);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать кадр от {from}.");
            }
            return;
        }

        Interlocked.Increment(ref _stats.BadFrames);
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен посторонний пакет на порт туннеля от {from} (не кадр туннеля).");
    }

    /// <summary>
    /// Цикл приёма пакетов игроков (UDP-порт игроков этого клиента).
    /// </summary>
    public async Task PlayerLoopAsync()
    {
        while (true)
        {
            UdpReceiveResult result;
            try
            {
                result = await _client.Udp.ReceiveAsync();
            }
            catch (SocketException ex)
            {
                // Windows может вернуть WSAECONNRESET (10054) на UDP-сокете после ICMP
                // "порт недоступен". Такие ошибки преходящи — продолжаем принимать дальше.
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [warn] Ошибка приёма (игроки, клиент '{_client.DisplayName}'): {ex.Message}");
                continue;
            }
            catch (ObjectDisposedException)
            {
                break;
            }

            try
            {
                await _tunnelWork.EnqueueAsync(() => HandlePlayerPacketAsync(result.RemoteEndPoint, result.Buffer));
            }
            catch (ChannelClosedException)
            {
                break;
            }
        }
    }

    /// <summary>
    /// Обрабатывает пакет игрока: заворачивает в зашифрованный кадр данных
    /// и отправляет прокси-клиенту.
    /// </summary>
    public async Task HandlePlayerPacketAsync(IPEndPoint from, byte[] data)
    {
        try
        {
            var cipher = _client.Cipher;
            var proxyEndpoint = _client.TunnelEndpoint;
            if (cipher == null || proxyEndpoint == null)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Клиент '{_client.DisplayName}' ещё не авторизовался — пакет от игрока {from} отброшен.");
                return;
            }

            if (_client.SeenClients.TryAdd(from, 0))
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Клиент '{_client.DisplayName}': новый игрок подключился: {from}.");

            Interlocked.Increment(ref _stats.PacketsIn);
            Interlocked.Increment(ref _stats.PacketsOut);
            var frame = Frame.EncodeData(from.Address, (ushort)from.Port, data, cipher);
            await _tunnel.SendAsync(frame, proxyEndpoint);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] {ex.Message}");
        }
    }

    /// <summary>
    /// Цикл приёма TCP-подключений игроков (если включено в конфиге клиента).
    /// </summary>
    public async Task TcpLoopAsync()
    {
        _client.TcpListener!.Start();
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Клиент '{_client.DisplayName}': слушаем TCP-порт игроков {_client.Config.TcpPort}.");

        while (true)
        {
            TcpClient tcpClient;
            try
            {
                tcpClient = await _client.TcpListener.AcceptTcpClientAsync();
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
            while ((proxy = _client.TunnelEndpoint) == null || (cipher = _client.Cipher) == null)
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
            _client.TcpClients[connId] = tcpClient;

            var sender = new TcpReliableSender(connId, SendTcpDataFrame);
            var receiver = new TcpReliableReceiver(connId, payload => WriteToBrowser(connId, payload), SendTcpAck);
            _client.TcpSenders[connId] = sender;
            _client.TcpReceivers[connId] = receiver;

            var remote = (IPEndPoint)tcpClient.Client.RemoteEndPoint!;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Клиент '{_client.DisplayName}': новый TCP-клиент {remote} (connId {connId}).");

            var open = Frame.EncodeTcpOpen(remote.Address, (ushort)remote.Port, connId, cipher);
            await _tunnel.SendAsync(open, proxy);

            _ = Task.Run(() => HandleTcpClientAsync(tcpClient, connId, sender));
        }
    }

    private async Task HandleTcpClientAsync(TcpClient tcpClient, uint connId, TcpReliableSender sender)
    {
        try
        {
            var stream = tcpClient.GetStream();
            using var batcher = new TcpFrameBatcher(sender.Send);

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

                batcher.Append(buffer.AsSpan(0, read));
            }
            batcher.Complete();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] TCP-клиент (connId {connId}): {ex.Message}");
        }
        finally
        {
            // Аналогично клиенту: закрытие (TcpClose) отправляется только после полного
            // подтверждения всех отправленных кадров, чтобы последние байты запроса/ответа
            // не потерялись на реальной сети с потерями.
            sender.WaitDrained(TimeSpan.FromSeconds(10));
            await CloseTcpWithRemoteAsync(connId);
        }
    }

    private void CloseTcpLocally(uint connId)
    {
        if (_client.TcpClients.TryRemove(connId, out var tcpClient))
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

        if (_client.TcpSenders.TryRemove(connId, out var sender))
            sender.Dispose();

        if (_client.TcpReceivers.TryRemove(connId, out var receiver))
            receiver.Dispose();
    }

    private async Task CloseTcpWithRemoteAsync(uint connId)
    {
        CloseTcpLocally(connId);

        var proxy = _client.TunnelEndpoint;
        var cipher = _client.Cipher;
        if (proxy == null || cipher == null)
            return;

        try
        {
            // TcpClose — управляющий кадр без подтверждения: дублируем, чтобы потеря
            // единственной датаграммы не оставила висящее соединение (повторы идемпотентны).
            var frame = Frame.EncodeTcpClose(connId, cipher);
            for (var i = 0; i < 3; i++)
            {
                await _tunnel.SendAsync(frame, proxy);
                if (i < 2)
                    await Task.Delay(30);
            }
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Соединение {connId} закрыто, прокси-клиент уведомлён.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] Отправка TcpClose (connId {connId}): {ex.Message}");
        }
    }

    private uint NextTcpConnId() => (uint)Interlocked.Increment(ref _nextTcpConnId);

    /// <summary>
    /// Отправка кадра TcpData прокси-клиенту (вызывается отправителем, в том числе
    /// при повторной передаче — каждый раз с актуальным сессионным ключом).
    /// </summary>
    private void SendTcpDataFrame(byte[] payload, uint connId, long seq)
    {
        var proxy = _client.TunnelEndpoint;
        var cipher = _client.Cipher;
        if (proxy == null || cipher == null)
            return;

        Interlocked.Increment(ref _stats.PacketsOut);
        _tunnel.Send(Frame.EncodeTcpData(connId, seq, payload, cipher), proxy);
    }

    /// <summary>
    /// Отправка кадра TcpAck прокси-клиенту.
    /// </summary>
    private void SendTcpAck(uint connId, long ackSeq)
    {
        var proxy = _client.TunnelEndpoint;
        var cipher = _client.Cipher;
        if (proxy == null || cipher == null)
            return;

        _tunnel.Send(Frame.EncodeTcpAck(connId, ackSeq, cipher), proxy);
    }

    /// <summary>
    /// Запись упорядоченных данных реальному TCP-клиенту (доставка от приёмника).
    /// </summary>
    private void WriteToBrowser(uint connId, byte[] payload)
    {
        if (!_client.TcpClients.TryGetValue(connId, out var tcpClient))
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] TcpData для неизвестного connId {connId}.");
            return;
        }

        tcpClient.GetStream().Write(payload, 0, payload.Length);
        Interlocked.Increment(ref _stats.RepliesRelayed);
    }

    public void Dispose() => _client.Dispose();
}
