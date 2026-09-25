using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Proxify.Client.Tcp;
using Proxify.Common.Config;
using Proxify.Common.Crypto;
using Proxify.Common.Protocol;
using Proxify.Common.Sessions;

namespace Proxify.Client.Sessions;

/// <summary>
/// Прокси-клиент TCP-правила: принимает TCP-кадры из туннеля (TcpOpen/TcpData/
/// TcpClose/TcpAck) и передаёт их <see cref="TcpRelay"/>, который соединяется
/// с игровым сервером и обеспечивает надёжную доставку в обе стороны. UDP-компоненты
/// (инжектор, алиасы, перехват ответов) для TCP-правила не создаются.
/// </summary>
public sealed class TcpProxySession : ProxySession
{
    private TcpRelay? _tcpRelay;

    internal TcpProxySession(
        IPEndPoint proxyServer,
        ECDsa identityKey,
        UdpClient tunnel,
        WireObfuscator? wire,
        TunnelStats stats,
        AsyncWorkQueue work,
        TunnelCipher cipher,
        ClientConfig config)
        : base(proxyServer, identityKey, tunnel, wire, stats, work, cipher, config)
    {
    }

    protected override void PrintProtocolBanner(ClientConfig config)
    {
        Console.WriteLine($"TCP-проксирование         : вкл (игровой сервер {config.GameIp}:{config.GamePort})");
        Console.WriteLine("Перехват ответов/UDP       : не используются (TCP-правило)");
    }

    protected override void CreateComponents(CancellationToken ct)
    {
        var config = Config!;
        _tcpRelay = new TcpRelay(config.GameIp, config.GamePort, Tunnel, ProxyServer, () => Cipher, Stats, ServerTcp, Wire);
    }

    protected override IEnumerable<Task> CreateProtocolTasks(CancellationToken ct) => Array.Empty<Task>();

    protected override Task HandleProtocolFrameAsync(byte? frameType, byte[] data, int length)
    {
        if (frameType is Frame.TypeTcpOpen or Frame.TypeTcpData or Frame.TypeTcpClose or Frame.TypeTcpAck)
        {
            _tcpRelay?.OnFrame(data, length);
            return Task.CompletedTask;
        }

        Interlocked.Increment(ref Stats.BadFrames);
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен посторонний кадр у TCP-правила (кадр данных?).");
        return Task.CompletedTask;
    }

    protected override void DisposeComponents()
    {
        _tcpRelay?.Dispose();
        _tcpRelay = null;
    }
}