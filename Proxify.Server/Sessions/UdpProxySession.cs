using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using Proxify.Common.Metrics;
using Proxify.Common.Protocol;
using Proxify.Common.Sessions;

namespace Proxify.Server.Sessions;

/// <summary>
/// Обработчик UDP-правила: принимает UDP-пакеты игроков на <see cref="ClientSession.Udp"/>
/// (порт игроков) и передаёт их прокси-клиенту, а кадры данных из туннеля (ответы
/// игрового сервера) отправляет игрокам. Ответы заворачивает в <see cref="UdpClient"/>
/// с исходным адресом игрока, маскируя реальный IP машины B.
/// </summary>
public sealed class UdpProxySession : ProxySession
{
    public UdpProxySession(ClientSession client, UdpClient tunnel, AsyncWorkQueue tunnelWork, TunnelMetricsHandle metrics)
        : base(client, tunnel, tunnelWork, metrics)
    {
    }

    /// <summary>Игроки, уже приславшие пакеты этому правилу.</summary>
    public override int PlayersCount => Client.SeenClients.Count;

    /// <summary>
    /// Цикл приёма пакетов игроков (UDP-порт игроков этого клиента).
    /// </summary>
    public override async Task ProtocolLoopAsync()
    {
        while (true)
        {
            UdpReceiveResult result;
            try
            {
                result = await Client.Udp!.ReceiveAsync();
            }
            catch (SocketException ex)
            {
                // Windows может вернуть WSAECONNRESET (10054) на UDP-сокете после ICMP
                // "порт недоступен". Такие ошибки преходящи — продолжаем принимать дальше.
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [warn] Ошибка приёма (игроки, клиент '{Client.DisplayName}'): {ex.Message}");
                continue;
            }
            catch (ObjectDisposedException)
            {
                break;
            }

            try
            {
                await Work.EnqueueAsync(() => HandlePlayerPacketAsync(result.RemoteEndPoint, result.Buffer));
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
            var cipher = Client.Cipher;
            var proxyEndpoint = Client.TunnelEndpoint;
            if (cipher == null || proxyEndpoint == null)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Клиент '{Client.DisplayName}' ещё не авторизовался — пакет от игрока {from} отброшен.");
                return;
            }

            if (Client.SeenClients.TryAdd(from, 0))
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Клиент '{Client.DisplayName}': новый игрок подключился: {from}.");

            Metrics.CountPacketsIn(data.Length);
            var frame = Frame.EncodeData(from.Address, (ushort)from.Port, data, cipher);
            var sealedFrame = SealFrame(frame);
            Metrics.CountPacketsOut(sealedFrame.Length);
            await Tunnel.SendAsync(sealedFrame, proxyEndpoint);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] {ex.Message}");
        }
    }

    protected override async Task HandlePayloadFrameAsync(IPEndPoint from, byte[] data, byte? frameType)
    {
        var cipher = Client.Cipher!;

        if (frameType is Frame.TypeData or Frame.TypeDataEncrypted)
        {
            if (frameType == Frame.TypeData)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен незашифрованный кадр, но сервер работает только с шифрованием. Проверьте конфиг у прокси-клиента.");
                Metrics.CountBadFrame();
                return;
            }

            if (Frame.TryDecodeData(data, data.Length, cipher, out var clientIp, out var clientPort, out var payload))
            {
                Client.TouchActivity();
                var target = new IPEndPoint(clientIp, clientPort);
                Metrics.CountPacketsIn(payload.Length);
                Metrics.CountRepliesRelayed();
                await Client.Udp!.SendAsync(payload, target);
            }
            else
            {
                Metrics.CountBadFrame();
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать кадр от {from}.");
            }
            return;
        }

        Metrics.CountBadFrame();
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен посторонний кадр от {from} (TCP-кадр в UDP-правило?).");
    }
}