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
/// Все датаграммы приходят во внешней маскирующей оболочке (WireObfuscator): ключ
/// выводится из зарегистрированного публичного ключа клиента, поэтому расшифровать
/// кадр может только владелец соответствующего закрытого ключа. Расшифровка и
/// служит опознанием клиента.
///
/// Клиент опознаётся по своей криптографической личности (wire-ключу / подписи
/// кадра Auth), а не по исходному IP-адресу. Это позволяет обслуживать несколько
/// клиентов за одним адресом или NAT и не сбрасывает сессию при смене исходного
/// порта (повторное подключение): для каждого кадра сервер подбирает сессию,
/// чей wire-ключ успешно расшифровал датаграмму.
/// </summary>
public sealed class ProxyServer : IDisposable
{
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
            Console.WriteLine($"    маскировка туннеля: {(client.Config.WireObfuscation ? "вкл" : "выкл")}");
            Console.WriteLine($"    публичный ключ: {DescribeKey(client.Config.PublicKeyPem)}");
            Console.WriteLine($"    статус        : {(client.Cipher == null ? "ждёт авторизации" : "сессия активна")}");
        }
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
            foreach (var candidate in Sessions)
            {
                byte[] inner;
                var isKnownEndpoint = candidate.Client.TunnelEndpoint?.Equals(from) == true;

                if (candidate.Client.Wire != null)
                {
                    if (!candidate.Client.Wire.TryUnwrap(data, data.Length, out inner))
                        continue;
                }
                else
                {
                    if (!isKnownEndpoint &&
                        Frame.PeekFrameType(data, data.Length) != Frame.TypeAuth)
                    {
                        continue;
                    }
                    inner = data;
                }

                var frameType = Frame.PeekFrameType(inner, inner.Length);
                if (frameType != Frame.TypeAuth)
                {
                    if (candidate.Client.Cipher != null)
                    {
                        await candidate.HandleFrameAsync(from, inner);
                        return;
                    }

                    Interlocked.Increment(ref Stats.BadFrames);
                    LogUnknownFrame(from);
                    return;
                }

                HandleAuthFrame(candidate, from, inner);
                return;
            }

            Interlocked.Increment(ref Stats.BadFrames);
            LogUnknownFrame(from);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] {ex.Message}");
        }
    }

    /// <summary>
    /// Разбирает и проверяет кадр Auth, расшифрованный wire-ключом кандидата.
    /// Подпись ECDSA подтверждает владение закрытым ключом; при успехе сессия
    /// активируется и запоминает текущий адрес отправителя для обратной отправки.
    /// </summary>
    private void HandleAuthFrame(ProxySession candidate, IPEndPoint from, byte[] inner)
    {
        if (!Frame.TryDecodeAuth(inner, inner.Length, out var version, out var ephX, out var ephY, out var nonce, out var signature))
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

        var payload = TunnelKeys.BuildAuthPayload(ephX, ephY, nonce);
        if (!candidate.TryAuthenticate(from, payload, signature, ephX, ephY, nonce))
        {
            Interlocked.Increment(ref Stats.BadFrames);
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Auth от {from}: подпись не соответствует зарегистрированному ключу клиента '{candidate.Client.DisplayName}'.");
            return;
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
