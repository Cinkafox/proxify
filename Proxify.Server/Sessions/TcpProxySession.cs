using System.Net;
using System.Net.Sockets;
using Proxify.Common.Crypto;
using Proxify.Common.Metrics;
using Proxify.Common.Protocol;
using Proxify.Common.Sessions;
using Proxify.Common.Tcp;

namespace Proxify.Server.Sessions;

/// <summary>
/// Обработчик TCP-правила: принимает TCP-подключения реальных клиентов на
/// <see cref="ClientSession.TcpListener"/> (порт игроков) и проксирует их через
/// туннель кадрами TcpOpen/TcpData/TcpClose/TcpAck. Каждое подключение получает
/// connId; надёжность обеспечивают TcpReliableSender/TcpReliableReceiver.
/// </summary>
public sealed class TcpProxySession : ProxySession
{
    private long _nextTcpConnId;

    public TcpProxySession(ClientSession client, UdpClient tunnel, AsyncWorkQueue tunnelWork, TunnelMetricsHandle metrics)
        : base(client, tunnel, tunnelWork, metrics)
    {
    }

    /// <summary>Активные TCP-соединения игроков, ожидающие закрытия или данных.</summary>
    public override int PlayersCount => Client.TcpClients.Count;

    /// <summary>
    /// Цикл приёма TCP-подключений игроков (только для TCP-правил конфига).
    /// </summary>
    public override async Task ProtocolLoopAsync()
    {
        Client.TcpListener!.Start();
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Клиент '{Client.DisplayName}': слушаем TCP-порт игроков {Client.Config.Port}.");

        while (true)
        {
            TcpClient tcpClient;
            try
            {
                tcpClient = await Client.TcpListener.AcceptTcpClientAsync();
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
            while ((proxy = Client.TunnelEndpoint) == null || (cipher = Client.Cipher) == null)
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
            Client.TcpClients[connId] = tcpClient;

            var sender = new TcpReliableSender(connId, SendTcpDataFrame);
            var receiver = new TcpReliableReceiver(connId, payload => WriteToBrowser(connId, payload), SendTcpAck);
            Client.TcpSenders[connId] = sender;
            Client.TcpReceivers[connId] = receiver;

            var remote = (IPEndPoint)tcpClient.Client.RemoteEndPoint!;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Клиент '{Client.DisplayName}': новый TCP-клиент {remote} (connId {connId}).");

            var open = Frame.EncodeTcpOpen(remote.Address, (ushort)remote.Port, connId, cipher);
            await Tunnel.SendAsync(SealFrame(open), proxy);

            _ = Task.Run(() => HandleTcpClientAsync(tcpClient, connId, sender));
        }
    }

    protected override Task HandlePayloadFrameAsync(IPEndPoint from, byte[] data, byte? frameType)
    {
        var cipher = Client.Cipher!;

        switch (frameType)
        {
            case Frame.TypeTcpData:
                if (Frame.TryDecodeTcpData(data, data.Length, cipher, out var connId, out var seq, out var payload))
                {
                    Client.TouchActivity();
                    if (Client.TcpReceivers.TryGetValue(connId, out var receiver))
                    {
                        receiver.Receive(payload, seq);
                    }
                    else
                    {
                        Metrics.CountBadFrame();
                        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] TcpData для неизвестного connId {connId}.");
                    }
                }
                else
                {
                    Metrics.CountBadFrame();
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать TcpData от {from}.");
                }
                break;

            case Frame.TypeTcpAck:
                if (Frame.TryDecodeTcpAck(data, data.Length, cipher, out var ackConnId, out var ackSeq))
                {
                    Client.TouchActivity();
                    if (Client.TcpSenders.TryGetValue(ackConnId, out var sender))
                    {
                        sender.OnAck(ackSeq);
                    }
                    else
                    {
                        Metrics.CountBadFrame();
                        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] TcpAck для неизвестного connId {ackConnId}.");
                    }
                }
                else
                {
                    Metrics.CountBadFrame();
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать TcpAck от {from}.");
                }
                break;

            case Frame.TypeTcpClose:
                if (Frame.TryDecodeTcpClose(data, data.Length, cipher, out var closeConnId))
                {
                    Client.TouchActivity();
                    CloseTcpLocally(closeConnId);
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Закрыто прокси-клиентом: connId {closeConnId}.");
                }
                else
                {
                    Metrics.CountBadFrame();
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать TcpClose от {from}.");
                }
                break;

            case Frame.TypeTcpOpen:
                // Прокси-клиент не инициирует TCP-соединения; кадр лишь обновляет активность.
                Client.TouchActivity();
                break;

            default:
                Metrics.CountBadFrame();
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен посторонний кадр от {from} (кадр данных вне TCP-правила).");
                break;
        }

        return Task.CompletedTask;
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
        if (Client.TcpClients.TryRemove(connId, out var tcpClient))
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

        if (Client.TcpSenders.TryRemove(connId, out var sender))
            sender.Dispose();

        if (Client.TcpReceivers.TryRemove(connId, out var receiver))
            receiver.Dispose();
    }

    private async Task CloseTcpWithRemoteAsync(uint connId)
    {
        CloseTcpLocally(connId);

        var proxy = Client.TunnelEndpoint;
        var cipher = Client.Cipher;
        if (proxy == null || cipher == null)
            return;

        try
        {
            // TcpClose — управляющий кадр без подтверждения: дублируем, чтобы потеря
            // единственной датаграммы не оставила висящее соединение (повторы
            // идемпотентны). Шифруем один раз — все копии идентичны.
            var frame = SealFrame(Frame.EncodeTcpClose(connId, cipher));
            for (var i = 0; i < 3; i++)
            {
                await Tunnel.SendAsync(frame, proxy);
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
        var proxy = Client.TunnelEndpoint;
        var cipher = Client.Cipher;
        if (proxy == null || cipher == null)
            return;

        var sealedFrame = SealFrame(Frame.EncodeTcpData(connId, seq, payload, cipher));
        Metrics.CountPacketsOut(sealedFrame.Length);
        Tunnel.Send(sealedFrame, proxy);
    }

    /// <summary>
    /// Отправка кадра TcpAck прокси-клиенту.
    /// </summary>
    private void SendTcpAck(uint connId, long ackSeq)
    {
        var proxy = Client.TunnelEndpoint;
        var cipher = Client.Cipher;
        if (proxy == null || cipher == null)
            return;

        Tunnel.Send(SealFrame(Frame.EncodeTcpAck(connId, ackSeq, cipher)), proxy);
    }

    /// <summary>
    /// Запись упорядоченных данных реальному TCP-клиенту (доставка от приёмника).
    /// </summary>
    private void WriteToBrowser(uint connId, byte[] payload)
    {
        if (!Client.TcpClients.TryGetValue(connId, out var tcpClient))
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] TcpData для неизвестного connId {connId}.");
            return;
        }

        tcpClient.GetStream().Write(payload, 0, payload.Length);
        Metrics.CountRepliesRelayed();
    }
}