using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using Proxify.Common.Config;
using Proxify.Common.Crypto;
using Proxify.Common.Metrics;
using Proxify.Common.Protocol;
using Proxify.Common.Sessions;
using Proxify.Server.Sessions;

namespace Proxify.Server.Core;

/// <summary>
/// Прокси-сервер (машина A): обслуживает несколько прокси-клиентов одновременно.
///
/// Владеет общим туннельным UDP-сокетом, создаёт по одному <see cref="ProxySession"/>
/// (UDP- или TCP-правило) на каждого зарегистрированного клиента и распределяет
/// кадры туннеля по сессиям.
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
    public TunnelMetrics Metrics { get; }
    public AsyncWorkQueue TunnelWork { get; }

    public ProxyServer(List<ClientConfig> configs, int tunnelPort, TunnelMetrics metrics)
    {
        TunnelPort = tunnelPort;
        Metrics = metrics;
        metrics.TunnelPort.Set(tunnelPort);
        Tunnel = new UdpClient(new IPEndPoint(IPAddress.Any, tunnelPort));
        TunnelWork = new AsyncWorkQueue(Math.Clamp(Environment.ProcessorCount, 2, 8));

        foreach (var config in configs)
        {
            var session = new ClientSession(config);
            if (config.Protocol == TunnelProtocol.Tcp)
                Sessions.Add(new TcpProxySession(session, Tunnel, TunnelWork, metrics.ForClient(session.DisplayName)));
            else
                Sessions.Add(new UdpProxySession(session, Tunnel, TunnelWork, metrics.ForClient(session.DisplayName)));
        }

        metrics.AddRefreshCallback(RefreshMetrics);
    }

    /// <summary>
    /// Обновляет «живые» гаужи метрик: число игроков/соединений и глубину очереди
    /// обработки. Вызывается по таймеру, только если метрики включены
    /// (<c>--metrics-port</c>), иначе значения остаются нулевыми.
    /// </summary>
    private void RefreshMetrics()
    {
        Metrics.TunnelPort.Set(TunnelPort);

        // Очередь обработки на сервере одна на всех клиентов, поэтому глубина
        // отдаётся как метрика процесса, а не каждого правила.
        Metrics.Process.SetQueueDepth(TunnelWork.PendingCount);

        foreach (var session in Sessions)
        {
            session.Metrics.SetPlayers(session.PlayersCount);
            session.Metrics.SetAuthorized(session.Client.Cipher != null);
        }
    }

    public void PrintBanner()
    {
        Console.WriteLine("=== Прокси-сервер (RealIP) ===");
        Console.WriteLine($"Порт туннеля                : {TunnelPort}");
        Console.WriteLine($"Метрики Prometheus          : {(Metrics.Enabled ? $"вкл — {Metrics.ExpositionUrl}" : "выкл (задайте --metrics-port, чтобы включить)")}");
        foreach (var session in Sessions)
        {
            var client = session.Client;
var protocol = client.Config.Protocol == TunnelProtocol.Tcp
            ? $"TCP (порт {client.Config.Port} -> игра {client.Config.GameIp}:{client.Config.GamePort})"
            : $"UDP (порт {client.Config.Port} -> игра {client.Config.GameIp}:{client.Config.GamePort})";
            Console.WriteLine($"  Клиент '{client.DisplayName}':");
            Console.WriteLine($"    правило: {protocol}");
            Console.WriteLine($"    маскировка туннеля: {DescribeMode(client.Config.ObfuscationMode)}");
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
            loops.Add(Task.Run(session.ProtocolLoopAsync));
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
                    var outcome = candidate.Client.Wire.Unwrap(data, data.Length, out inner);

                    // Датаграмма не наша: ключ чужой или режим не совпадает. В режиме
                    // quic служебный пакет (ACK, PING, CRYPTO) тоже не даёт кадра,
                    // но это уже наш трафик — перебор кандидатов продолжать нельзя.
                    if (outcome == WireOutcome.Unknown)
                        continue;

                    if (outcome == WireOutcome.Handshake || outcome == WireOutcome.Closed)
                        return;
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

                    continue;
                }

                if (HandleAuthFrame(candidate, from, inner))
                    return;
            }

            Metrics.UnauthorizedFrames.Inc();
            LogUnknownFrame(from, data);
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
    /// Возвращает true, если кадр успешно принят этим кандидатом; false — кандидат
    /// не совпал (подпись не его), и перебор стоит продолжить.
    /// </summary>
    private bool HandleAuthFrame(ProxySession candidate, IPEndPoint from, byte[] inner)
    {
        if (!Frame.TryDecodeAuth(inner, inner.Length, out var version, out var ephX, out var ephY, out var nonce, out var signature))
        {
            candidate.Metrics.CountBadFrame();
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать кадр Auth от {from}.");
            return false;
        }

        if (version != TunnelKeys.AuthVersion)
        {
            candidate.Metrics.CountBadFrame();
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Auth от {from} с неизвестной версией {version}.");
            return false;
        }

        var payload = TunnelKeys.BuildAuthPayload(ephX, ephY, nonce);
        if (!candidate.TryAuthenticate(from, payload, signature, ephX, ephY, nonce))
        {
            candidate.Metrics.CountBadFrame();
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Auth от {from}: подпись не соответствует зарегистрированному ключу клиента '{candidate.Client.DisplayName}'.");
            return false;
        }

        return true;
    }

    private void LogUnknownFrame(IPEndPoint from, byte[] datagram)
    {
        var nowTicks = DateTime.UtcNow.Ticks;
        var prev = Interlocked.Read(ref _lastUnknownLogTicks);
        if (nowTicks - prev < TimeSpan.FromSeconds(5).Ticks)
            return;
        if (Interlocked.CompareExchange(ref _lastUnknownLogTicks, nowTicks, prev) != prev)
            return;

        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Кадр от неавторизованного адреса {from} — клиент должен сначала выполнить Auth." +
                          (WireObfuscator.LooksLikeQuic(datagram, datagram.Length)
                              ? " Датаграмма выглядит как пакет QUIC: проверерьте, что режим маскировки у клиента и сервера одинаков."
                              : string.Empty));
    }

    /// <summary>Человекочитаемое имя режима маскировки для журнала запуска.</summary>
    private static string DescribeMode(WireObfuscationMode mode) => mode switch
    {
        WireObfuscationMode.Random => "шифрование датаграммы (AES-256-GCM)",
        WireObfuscationMode.Quic => "пакеты QUIC v1 поверх HTTP/3",
        _ => "выключена"
    };

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
