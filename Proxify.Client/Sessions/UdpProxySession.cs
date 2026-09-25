using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Channels;
using Proxify.Client.Injection;
using Proxify.Common.Config;
using Proxify.Common.Crypto;
using Proxify.Common.Metrics;
using Proxify.Common.Networking;
using Proxify.Common.Protocol;
using Proxify.Common.Sessions;

namespace Proxify.Client.Sessions;

/// <summary>
/// Прокси-клиент UDP-правила: принимает зашифрованные кадры данных из туннеля
/// (пакеты игроков от прокси-сервера) и отправляет их игровому серверу через
/// <see cref="RawInjector"/> с подменой исходного IP на реальный IP игрока.
/// Ответы перехватываются <see cref="ReplySniffer"/> (если включено) и уходят
/// обратно в туннель; словари известных игроков поддерживает CleanupLoop.
/// </summary>
public sealed class UdpProxySession : ProxySession
{
    private LoopbackAliasManager? _aliases;
    private RawInjector? _injector;
    private ReplySniffer? _sniffer;
    private Task? _snifferTask;

    /// <summary>Клиенты игры (IP:порт), от которых проксируются пакеты.</summary>
    public ConcurrentDictionary<IPEndPoint, DateTime> KnownClients { get; } = new();

    /// <summary>Активные IP игроков (для loopback-алиасов и очистки по таймауту).</summary>
    public ConcurrentDictionary<IPAddress, DateTime> ActiveIps { get; } = new();

    internal UdpProxySession(
        IPEndPoint proxyServer,
        ECDsa identityKey,
        UdpClient tunnel,
        WireObfuscator? wire,
        TunnelMetricsHandle metrics,
        AsyncWorkQueue work,
        TunnelCipher cipher,
        ClientConfig config,
        TunnelMetrics processMetrics)
        : base(proxyServer, identityKey, tunnel, wire, metrics, work, cipher, config, processMetrics)
    {
    }

    /// <summary>Игроки, чьи пакеты уже переданы игровому серверу.</summary>
    public override int PlayersCount => KnownClients.Count;

    protected override void PrintProtocolBanner(ClientConfig config)
    {
        Console.WriteLine($"Игровой сервер (локально): {config.GameIp}:{config.GamePort}");
        Console.WriteLine($"Перехват ответов          : {(config.CaptureReplies ? "вкл" : "выкл")}");
        Console.WriteLine($"Loopback-алиасы           : {(config.LoopbackAliases ? "вкл" : "выкл")}");
        Console.WriteLine($"TCP-проксирование         : выкл (UDP-правило)");
    }

    protected override void CreateComponents(CancellationToken ct)
    {
        var config = Config!;
        _aliases = new LoopbackAliasManager(config.LoopbackAliases);
        _injector = new RawInjector(config.GameIp, config.GamePort);

        if (config.CaptureReplies)
        {
            _sniffer = new ReplySniffer(IPAddress.Loopback, config.GamePort, KnownClients, Tunnel, ProxyServer, () => Cipher, Metrics, ct, Wire);
            _snifferTask = Task.Run(_sniffer.Run);
        }
    }

    protected override IEnumerable<Task> CreateProtocolTasks(CancellationToken ct)
    {
        var tasks = new List<Task> { Task.Run(() => CleanupLoop(ct)) };
        if (_snifferTask != null)
            tasks.Add(_snifferTask);
        return tasks;
    }

    protected override async Task HandleProtocolFrameAsync(byte? frameType, byte[] data, int length)
    {
        if (frameType == Frame.TypeData)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен незашифрованный кадр, но шифрование включено. Проверьте конфиг у прокси-сервера.");
            Metrics.CountBadFrame();
            return;
        }

        if (frameType != Frame.TypeDataEncrypted)
        {
            Metrics.CountBadFrame();
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен посторонний кадр у UDP-правила (TCP-кадр?).");
            return;
        }

        var cipher = Cipher;
        if (cipher == null)
            return;

        if (!Frame.TryDecodeData(data, length, cipher, out var clientIp, out var clientPort, out var payload))
        {
            Metrics.CountBadFrame();
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать кадр ({length} байт).");
            return;
        }

        Metrics.CountPacketsIn(payload.Length);

        var injector = _injector;
        if (injector == null)
            return;

        // Инжекция и обновление словарей выполняются воркером параллельно,
        // чтобы цикл приёма не ждал отправки «сырых» пакетов.
        try
        {
            await Work.EnqueueAsync(() =>
            {
                _aliases?.Add(clientIp);
                KnownClients[new IPEndPoint(clientIp, clientPort)] = DateTime.UtcNow;
                ActiveIps[clientIp] = DateTime.UtcNow;

                injector.Inject(clientIp, clientPort, payload);
                Metrics.CountInjected();
                return Task.CompletedTask;
            });
        }
        catch (ChannelClosedException)
        {
            // сессия завершается
        }
    }

    protected override void DisposeComponents()
    {
        _sniffer?.Dispose();
        _sniffer = null;
        _injector?.Dispose();
        _injector = null;
        _aliases?.Dispose();
        _aliases = null;
    }

    /// <summary>
    /// Периодическая очистка словарей игроков и loopback-алиасов по таймауту,
    /// чтобы NAT-записи не копились вечно.
    /// </summary>
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
}