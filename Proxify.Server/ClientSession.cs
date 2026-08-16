using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Proxify.Common;

namespace Proxify.Server;

/// <summary>
/// Данные одного зарегистрированного прокси-клиента на прокси-сервере (машина A).
///
/// Хранит только состояние: конфиг из server.json, зарегистрированный публичный
/// ключ, UDP-сокет игроков (порт <see cref="ClientConfig.Port"/>), опциональный
/// TCP-прослушиватель и активную сессию туннеля (адрес клиента + сессионный ключ).
/// Обработкой кадров и пакетов занимается <see cref="ProxySession"/>.
/// </summary>
public sealed class ClientSession : IDisposable
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
        foreach (var sender in TcpSenders.Values)
            sender.Dispose();
        foreach (var receiver in TcpReceivers.Values)
            receiver.Dispose();
        TcpClients.Clear();
        TcpSenders.Clear();
        TcpReceivers.Clear();
    }
}
