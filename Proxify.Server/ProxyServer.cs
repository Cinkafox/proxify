using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using Proxify.Common;

namespace Proxify.Server;

/// <summary>
/// Прокси-сервер (машина A): обслуживает несколько прокси-клиентов одновременно.
///
/// Владеет общим туннельным UDP-сокетом, создаёт по одному <see cref="ProxySession"/>
/// на каждого зарегистрированного клиента и распределяет кадры туннеля по сессиям.
/// Кадр Auth (всегда plaintext) разбирается здесь и направляется сессиям, которые
/// проверяют подпись своим ключом; после успешной авторизации адрес туннеля
/// привязывается к сессии, и все дальнейшие кадры от этого адреса передаются ей.
/// </summary>
public sealed class ProxyServer : IDisposable
{
    private readonly ConcurrentDictionary<IPEndPoint, ProxySession> _active = new();
    private long _lastUnknownLogTicks;

    public int TunnelPort { get; }
    public List<ProxySession> Sessions { get; } = new();
    public UdpClient Tunnel { get; }
    public TunnelStats Stats { get; } = new();
    public AsyncWorkQueue TunnelWork { get; }

    public ProxyServer(List<ClientConfig> configs, int tunnelPort)
    {
        TunnelPort = tunnelPort;
        Tunnel = new UdpClient(new IPEndPoint(IPAddress.Any, tunnelPort));
        TunnelWork = new AsyncWorkQueue(Math.Clamp(Environment.ProcessorCount, 2, 8));

        foreach (var config in configs)
            Sessions.Add(new ProxySession(new ClientSession(config), Tunnel, TunnelWork, Stats));
    }

    public void PrintBanner()
    {
        Console.WriteLine("=== Прокси-сервер (RealIP) ===");
        Console.WriteLine($"Порт туннеля                : {TunnelPort}");
        foreach (var session in Sessions)
        {
            var client = session.Client;
            Console.WriteLine($"  Клиент '{client.DisplayName}':");
            Console.WriteLine($"    игроки (UDP) : {client.Config.Port}");
            Console.WriteLine($"    игровой сервер: {client.Config.GameIp}:{client.Config.GamePort} (на машине B)");
            Console.WriteLine($"    TCP-проксирование: {(client.Config.TcpEnabled ? $"вкл (порт {client.Config.TcpPort})" : "выкл")}");
            Console.WriteLine($"    публичный ключ: {DescribeKey(client.Config.PublicKeyPem)}");
            Console.WriteLine($"    статус        : {(client.Cipher == null ? "ждёт авторизации" : "сессия активна")}");
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
        foreach (var session in Sessions)
        {
            loops.Add(Task.Run(session.PlayerLoopAsync));
            if (session.Client.TcpListener != null)
                loops.Add(Task.Run(session.TcpLoopAsync));
        }
        await Task.WhenAll(loops);
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
                await TunnelWork.EnqueueAsync(() => HandleTunnelFrameAsync(result.RemoteEndPoint, result.Buffer));
            }
            catch (ChannelClosedException)
            {
                break;
            }
        }
    }

    private async Task HandleTunnelFrameAsync(IPEndPoint from, byte[] data)
    {
        try
        {
            var frameType = Frame.PeekFrameType(data, data.Length);

            // --- Рукопожатие: кадр Auth (всегда plaintext) ---
            if (frameType == Frame.TypeAuth)
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
                var payload = TunnelKeys.BuildAuthPayload(ephX, ephY, nonce);
                foreach (var candidate in Sessions)
                {
                    if (candidate.TryAuthenticate(from, payload, signature, ephX, ephY, nonce))
                    {
                        _active[from] = candidate;
                        return;
                    }
                }

                Interlocked.Increment(ref Stats.BadFrames);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Auth от {from}: подпись не соответствует ни одному зарегистрированному ключу.");
                return;
            }

            // --- Остальные кадры принимаются только от авторизованной сессии ---
            if (!_active.TryGetValue(from, out var session) || session.Client.Cipher == null)
            {
                Interlocked.Increment(ref Stats.BadFrames);
                LogUnknownFrame(from);
                return;
            }

            await session.HandleFrameAsync(from, data);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] {ex.Message}");
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
        foreach (var session in Sessions)
            session.Dispose();
        Tunnel.Dispose();
    }
}
