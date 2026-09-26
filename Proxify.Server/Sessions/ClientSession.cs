using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Proxify.Common.Config;
using Proxify.Common.Crypto;
using Proxify.Common.Quic;
using Proxify.Common.Tcp;

namespace Proxify.Server.Sessions;

/// <summary>
/// Данные одного зарегистрированного прокси-клиента на прокси-сервере (машина A).
///
/// Хранит только состояние: конфиг из server.yml, зарегистрированный публичный
/// ключ, сокет игроков (UDP — порт <see cref="ClientConfig.Port"/> для UDP-правила,
/// либо TCP-прослушиватель для TCP-правила) и активную сессию туннеля (адрес
/// клиента + сессионный ключ). Обработкой кадров и пакетов занимается
/// <see cref="ProxySession"/>.
///
/// TCP и UDP разделены конфигом: клиент — либо UDP-правило (с подменой реального
/// IP), либо TCP-правило. Для UDP-клиента создаётся <see cref="Udp"/>, для
/// TCP-клиента — <see cref="TcpListener"/> на том же <see cref="ClientConfig.Port"/>.
/// </summary>
public sealed class ClientSession : IDisposable
{
    private TunnelCipher? _cipher;
    private IPEndPoint? _tunnelEndpoint;
    private long _lastActivityTicks;

    public ClientConfig Config { get; }
    public ECDsa RegisteredKey { get; }

    /// <summary>
    /// Внешний слой маскировки датаграмм туннеля для этого клиента.
    /// Ключи выводятся из зарегистрированного публичного ключа, поэтому
    /// доступны сразу — ещё до рукопожатия (кадр Auth тоже приходит в оболочке).
    /// </summary>
    public WireObfuscator? Wire { get; }

    /// <summary>UDP-сокет игроков (только для UDP-правила; у TCP-клиента null).</summary>
    public UdpClient? Udp { get; }

    /// <summary>TCP-прослушиватель игроков (только для TCP-правила; у UDP-клиента null).</summary>
    public TcpListener? TcpListener { get; }

    /// <summary>TCP-соединения реальных клиентов: connId -> сокет.</summary>
    public ConcurrentDictionary<uint, TcpClient> TcpClients { get; } = new();

    /// <summary>Надёжная отправка TCP-данных прокси-клиенту (connId -> отправитель).</summary>
    public ConcurrentDictionary<uint, TcpReliableSender> TcpSenders { get; } = new();

    /// <summary>Надёжный приём TCP-данных от прокси-клиента (connId -> приёмник).</summary>
    public ConcurrentDictionary<uint, TcpReliableReceiver> TcpReceivers { get; } = new();

    /// <summary>Игроки, уже контактировавшие с сервером (для однократного [диагностика]).</summary>
    public ConcurrentDictionary<IPEndPoint, byte> SeenClients { get; } = new();

    public TunnelCipher? Cipher => Volatile.Read(ref _cipher);
    public IPEndPoint? TunnelEndpoint => Volatile.Read(ref _tunnelEndpoint);
    public long LastActivityTicks => Interlocked.Read(ref _lastActivityTicks);

    public ClientSession(ClientConfig config)
    {
        Config = config;
        RegisteredKey = TunnelKeys.ImportPublicPem(config.PublicKeyPem);
        Wire = config.ObfuscationEnabled
            ? WireObfuscator.Create(RegisteredKey, weAreClient: false, config.ObfuscationMode, QuicConnection.DefaultServerName)
            : null;
        if (config.Protocol == TunnelProtocol.Tcp)
            TcpListener = new TcpListener(IPAddress.Any, config.Port);
        else
            Udp = new UdpClient(new IPEndPoint(IPAddress.Any, config.Port));
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

        // Ключи пакетов 1-RTT выводятся из того же сессионного ключа, что и
        // внутренний шифр: после рукопожатия кадры идут в потоке 1-RTT.
        Wire?.AttachSessionKey(cipher.ExportSessionKey());
    }

    public void TouchActivity() => Interlocked.Exchange(ref _lastActivityTicks, DateTime.UtcNow.Ticks);

    public string DisplayName => string.IsNullOrWhiteSpace(Config.Name) ? "(без имени)" : Config.Name;

    public void Dispose()
    {
        RegisteredKey.Dispose();
        Udp?.Dispose();
        TcpListener?.Stop();
        foreach (var client in TcpClients.Values)
            client.Close();
        foreach (var sender in TcpSenders.Values)
            sender.Dispose();
        foreach (var receiver in TcpReceivers.Values)
            receiver.Dispose();
        TcpClients.Clear();
        TcpSenders.Clear();
        TcpReceivers.Clear();
    }
}
