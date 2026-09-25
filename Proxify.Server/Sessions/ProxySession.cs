using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Proxify.Common.Config;
using Proxify.Common.Crypto;
using Proxify.Common.Protocol;
using Proxify.Common.Sessions;

namespace Proxify.Server.Sessions;

/// <summary>
/// Базовый обработчик одного прокси-клиента (машина B) на прокси-сервере.
///
/// Общее для UDP- и TCP-правил: авторизация (Auth/AuthAck), ответ на сердцебиение
/// (PING/PONG), привязка к состоянию <see cref="ClientSession"/> и разбор общих
/// служебных кадров. Циклы и кадры конкретного протокола реализуют наследники:
/// <see cref="UdpProxySession"/> (UDP-пакеты игроков) и <see cref="TcpProxySession"/>
/// (TCP-проксирование).
/// </summary>
public abstract class ProxySession : SharedProxySession
{
    private readonly ClientSession _client;

    protected ProxySession(ClientSession client, UdpClient tunnel, AsyncWorkQueue tunnelWork, TunnelStats stats)
        : base(tunnel, stats, tunnelWork, client.Wire)
    {
        _client = client;
    }

    public ClientSession Client => _client;

    public override TunnelCipher? Cipher => _client.Cipher;
    public override ClientConfig? Config => _client.Config;

    /// <summary>
    /// Цикл обработки трафика игроков этого правила (UDP-пакетов или TCP-подключений).
    /// </summary>
    public abstract Task ProtocolLoopAsync();

    /// <summary>
    /// Обработка протокольного кадра туннеля (данные UDP или TCP) от этого клиента.
    /// Диспетчер уже разобрал служебные кадры (PING/PONG) и вызывает этот метод
    /// только для остальных типов.
    /// </summary>
    protected abstract Task HandlePayloadFrameAsync(IPEndPoint from, byte[] data, byte? frameType);

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
            Tunnel.Send(SealFrame(ack), from);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] Отправка AuthAck клиенту '{_client.DisplayName}': {ex.Message}");
        }
        return true;
    }

    /// <summary>
    /// Обрабатывает кадр туннеля от этого клиента: общие служебные (PING/PONG)
    /// обслуживаются здесь, остальные перенаправляются в реализацию протокола
    /// наследника. Вызывается диспетчером только для авторизованной сессии.
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
                await Tunnel.SendAsync(SealFrame(Frame.EncodePong(token, _client.Config.Protocol == TunnelProtocol.Tcp, cipher)), from);
            }
            else
            {
                Interlocked.Increment(ref Stats.BadFrames);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] PING от {from} не разобран (возможно, сессия устарела).");
            }
            return;
        }

        if (frameType == Frame.TypePong)
            return;

        await HandlePayloadFrameAsync(from, data, frameType);
    }

    public sealed override void Dispose() => _client.Dispose();
}