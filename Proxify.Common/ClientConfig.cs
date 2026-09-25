using System.Net;

namespace Proxify.Common;

/// <summary>
/// Конфигурация одного прокси-клиента (машина B).
///
/// Полная конфигурация задаётся в YAML-конфиге прокси-сервера (машина A): каждый
/// блок конфига — отдельный клиент, ключ правила задаёт протокол и порты
/// (<see cref="Port"/>, <see cref="GamePort"/>, <see cref="TcpEnabled"/>). Сервер
/// слушает на порту <see cref="Port"/> пакеты игроков (UDP) или TCP-подключения
/// (<see cref="TcpEnabled"/>), знает адрес игрового сервера машины B и пересылает
/// клиенту нужные параметры кадром AuthAck. Клиент хранит только адрес сервера
/// и свой закрытый ключ.
///
/// По туннелю (в «доказательстве» AuthAck) передаётся только та часть, которая
/// нужна клиенту: gameIp, gamePort, флаги capture/aliases/tcp. Не передаются
/// <see cref="Port"/> (это порт сервера) и публичный ключ.
/// </summary>
public sealed class ClientConfig
{
    public const byte FlagCapture = 0x01;
    public const byte FlagAliases = 0x02;
    public const byte FlagTcp = 0x04;

    /// <summary>Имя клиента (только для диагностики; по туннелю не передаётся).</summary>
    public string? Name { get; set; }

    /// <summary>Публичный ключ клиента (SPKI PEM); только на сервере.</summary>
    public string PublicKeyPem { get; set; } = "";

    /// <summary>Порт на машине A, на который подключаются игроки этого клиента (UDP или TCP).</summary>
    public int Port { get; set; }

    /// <summary>IP игрового сервера на машине B (видимый прокси-клиенту).</summary>
    public IPAddress GameIp { get; set; } = IPAddress.Any;

    /// <summary>UDP- или TCP-порт игрового сервера на машине B.</summary>
    public ushort GamePort { get; set; }

    /// <summary>Перехватывать ответы игрового сервера (raw-сниффер) на машине B.</summary>
    public bool CaptureReplies { get; set; } = true;

    /// <summary>Добавлять IP игроков в loopback-алиасы на машине B.</summary>
    public bool LoopbackAliases { get; set; } = true;

    /// <summary>
    /// Протокол правила: <c>true</c> — TCP-проксирование (публичный порт
    /// <see cref="Port"/> на машине A открывается по TCP, игровой <see cref="GamePort"/>
    /// тоже TCP); <c>false</c> — UDP-проксирование с подменой реального IP.
    /// TCP и UDP разделены: каждое правило конфига — отдельный клиент.
    /// </summary>
    public bool TcpEnabled { get; set; }

    /// <summary>
    /// Внешняя маскировка туннеля (WireObfuscator): каждая датаграмма шифруется
    /// wire-ключом до внутреннего протокола. По умолчанию выключена; настройка
    /// задаётся только в конфиге сервера и должна совпадать с параметром
    /// --wire-obfuscation клиента; по туннелю не передаётся.
    /// </summary>
    public bool WireObfuscation { get; set; }

    /// <summary>
    /// Шифрует «доказательство» для AuthAck сессионным ключом.
    /// Открытый текст: [16] nonce клиента [1] флаги [4] gameIp [2] gamePort.
    /// Для TCP-клиента (флаг 0x04) gameIp/gamePort — адрес TCP-игрового сервера.
    /// </summary>
    public byte[] EncodeProof(byte[] clientNonce, TunnelCipher cipher)
    {
        var flags = (byte)((CaptureReplies ? FlagCapture : 0) |
                           (LoopbackAliases ? FlagAliases : 0) |
                           (TcpEnabled ? FlagTcp : 0));

        var ip = GameIp.GetAddressBytes();
        var plain = new byte[16 + 1 + 4 + 2];
        clientNonce.CopyTo(plain, 0);
        plain[16] = flags;
        Array.Copy(ip, 0, plain, 17, 4);
        plain[21] = (byte)(GamePort >> 8);
        plain[22] = (byte)GamePort;
        return cipher.Wrap(plain);
    }

    /// <summary>
    /// Расшифровывает «доказательство» из AuthAck и проверяет echo nonce.
    /// Заполняет только поля, передаваемые по туннелю.
    /// </summary>
    public static bool TryDecodeProof(byte[] clientNonce, TunnelCipher cipher, ReadOnlySpan<byte> wrappedProof, out ClientConfig config)
    {
        config = new ClientConfig();

        if (!cipher.TryUnwrap(wrappedProof, out var plain))
            return false;
        if (plain.Length != 16 + 1 + 4 + 2)
            return false;
        if (!plain.AsSpan(0, 16).SequenceEqual(clientNonce))
            return false;

        config.CaptureReplies = (plain[16] & FlagCapture) != 0;
        config.LoopbackAliases = (plain[16] & FlagAliases) != 0;
        config.TcpEnabled = (plain[16] & FlagTcp) != 0;
        config.GameIp = new IPAddress(plain.AsSpan(17, 4).ToArray());
        config.GamePort = (ushort)((plain[21] << 8) | plain[22]);
        return true;
    }
}
