using System.Security.Cryptography;
using Proxify.Common.Quic;

namespace Proxify.Common.Crypto;

/// <summary>Режим внешней маскировки датаграмм туннеля.</summary>
public enum WireObfuscationMode
{
    /// <summary>Без маскировки: на проводе внутренний формат кадров (обратная совместимость).</summary>
    Off,

    /// <summary>
    /// Датаграмма целиком шифруется AES-256-GCM: на проводе равномерно случайные
    /// байты без сигнатуры протокола.
    /// </summary>
    Random,

    /// <summary>
    /// Трафик выглядит как QUIC v1 поверх HTTP/3: настоящий ClientHello в пакете
    /// Initial, читаемый публичной солью версии, и рукопожатие/данные в пакетах
    /// Handshake и 1-RTT, ключи которых из трафика не выводятся.
    /// </summary>
    Quic,
}

/// <summary>Что оказалось в принятой датаграмме после снятия маскировки.</summary>
public enum WireOutcome
{
    /// <summary>Датаграмма не наша: чужой ключ, искажение или другой режим маскировки.</summary>
    Unknown,

    /// <summary>Датаграмма наша, но кадра туннеля в ней нет: ACK, PING, CRYPTO, PADDING.</summary>
    Handshake,

    /// <summary>Датаграмма наша и содержит кадр туннеля.</summary>
    Tunnel,

    /// <summary>Соединение закрыто собеседником (CONNECTION_CLOSE).</summary>
    Closed,
}

/// <summary>
/// Внешний слой маскировки туннеля: превращает внутренние кадры в датаграммы,
/// неотличимые от постороннего трафика, и обратно.
///
/// Режим <see cref="WireObfuscationMode.Random"/> шифрует кадр целиком:
///
///   датаграмма = [12]nonce [16]tag [N]AES-GCM(wireKey, внутренний кадр)
///
/// На проводе не остаётся ни одного постоянного байта: ни магии 0xC0DE, ни типов
/// кадров, ни открытого рукопожатия Auth/AuthAck — датаграммы выглядят как
/// равномерно случайные байты, без сигнатуры протокола и факта рукопожатия.
///
/// Режим <see cref="WireObfuscationMode.Quic"/> вместо этого собирает настоящие
/// пакеты QUIC v1 (см. <see cref="QuicConnection"/>): наблюдатель видит корректный
/// ClientHello и параметры транспорта, но не видит ни рукопожатия туннеля, ни его
/// данных — они лежат в пакетах Handshake и 1-RTT, ключи к которым выводятся из
/// зарегистрированной пары ключей клиента и сессионного ключа ECDH.
///
/// Wire-ключи выводятся из зарегистрированной пары ключей клиента
/// (HKDF-SHA256 от SPKI-байт публичного ключа, отдельный ключ на направление:
/// клиент→сервер и сервер→клиент). Публичный ключ нигде не передаётся по проводу,
/// поэтому вывести ключ из перехваченного трафика нельзя.
///
/// Граница угроз: слой защищает от классификации по сигнатурам и эвристикам
/// содержимого. Атакующий, которому известен client-public.pem (файл конфига),
/// может вычислить wire-ключи — конфиденциальность полезной нагрузки при этом
/// по-прежнему обеспечивает внутренний сессионный шифр (см. TunnelCipher).
/// </summary>
public sealed class WireObfuscator
{
    private readonly TunnelCipher? _send;
    private readonly TunnelCipher? _receive;
    private readonly QuicConnection? _quic;

    private WireObfuscator(TunnelCipher? send, TunnelCipher? receive, QuicConnection? quic)
    {
        _send = send;
        _receive = receive;
        _quic = quic;
    }

    /// <summary>Режим маскировки, которым создана эта оболочка.</summary>
    public WireObfuscationMode Mode { get; private init; }

    /// <param name="identityKey">Ключ зарегистрированной пары клиента:
    /// на машине B — загруженный закрытый ключ, на машине A — публичный ключ
    /// из конфига сервера.</param>
    /// <param name="weAreClient">true для прокси-клиента (машина B).</param>
    /// <param name="serverName">Имя сервера для SNI в ClientHello (режим Quic).</param>
    public static WireObfuscator Create(ECDsa identityKey, bool weAreClient, WireObfuscationMode mode, string serverName)
    {
        if (mode == WireObfuscationMode.Off)
            return new WireObfuscator(null, null, null) { Mode = mode };

        if (mode == WireObfuscationMode.Quic)
        {
            return new WireObfuscator(null, null, QuicConnection.Create(identityKey, weAreClient, serverName))
            {
                Mode = mode
            };
        }

        var spki = TunnelKeys.ExportSpkiDer(identityKey);
        var kC2s = TunnelKeys.DeriveWireKey(spki, TunnelKeys.WireInfoClientToServer);
        var kS2c = TunnelKeys.DeriveWireKey(spki, TunnelKeys.WireInfoServerToClient);

        return new WireObfuscator(
            weAreClient ? new TunnelCipher(kC2s) : new TunnelCipher(kS2c),
            weAreClient ? new TunnelCipher(kS2c) : new TunnelCipher(kC2s),
            null)
        {
            Mode = mode
        };
    }

    /// <summary>
    /// Устанавливает сессионный ключ для пакетов 1-RTT. Вызывается сразу после
    /// рукопожатия, когда ECDH уже дал общий ключ. В режиме Random не требуется:
    /// там ключ не меняется в течение туннеля.
    /// </summary>
    public void AttachSessionKey(byte[] sessionKey) => _quic?.AttachSessionKey(sessionKey);

    /// <summary>Готовит внутренний кадр к отправке по проводу.</summary>
    public byte[] Wrap(byte[] innerFrame, WireFrameRole role = WireFrameRole.Data)
    {
        if (_quic != null)
        {
            // Рукопожатие туннеля уходит первым обменом QUIC, а не в потоке 1-RTT:
            // на проводе это неотличимо от обычного начала соединения.
            if (role == WireFrameRole.Handshake)
                return _quic.IsClient
                    ? _quic.BuildClientHandshakeDatagram(innerFrame)
                    : _quic.BuildServerFlight(innerFrame);

            return _quic.Wrap(innerFrame, role);
        }

        // Режим off: оболочки нет, кадр уходит в внутреннем формате как есть.
        return _send != null ? _send.Wrap(innerFrame) : innerFrame;
    }

    /// <summary>
    /// Пытается разобрать принятую датаграмму. <see cref="WireOutcome.Unknown"/>
    /// означает, что датаграмма не наша (чужой ключ или искажение) — это заменяет
    /// прежнюю проверку magic. Исходный буфер не изменяется: его можно пробовать
    /// и другим кандидатам, пока не найдётся совпадение.
    /// </summary>
    public WireOutcome Unwrap(byte[] buffer, int length, out byte[] innerFrame)
    {
        if (length < 0 || length > buffer.Length)
        {
            innerFrame = Array.Empty<byte>();
            return WireOutcome.Unknown;
        }

        if (_quic != null)
        {
            var outcome = _quic.TryUnwrap(buffer, length, out innerFrame);
            return outcome switch
            {
                QuicPacketOutcome.Tunnel => WireOutcome.Tunnel,
                QuicPacketOutcome.Closed => WireOutcome.Closed,
                QuicPacketOutcome.Handshake => WireOutcome.Handshake,
                _ => WireOutcome.Unknown
            };
        }

        if (_receive == null)
        {
            innerFrame = buffer.AsSpan(0, length).ToArray();
            return WireOutcome.Tunnel;
        }

        return _receive.TryUnwrap(buffer.AsSpan(0, length), out innerFrame)
            ? WireOutcome.Tunnel
            : WireOutcome.Unknown;
    }

    /// <summary>
    /// Похоже ли содержимое датаграммы на внутренний кадр без снятия маскировки.
    /// Нужно, чтобы отличить «ключ не тот» от «на сервере маскировка выключена».
    /// </summary>
    public static bool LooksLikePlainFrame(byte[] buffer, int length) =>
        Protocol.Frame.PeekFrameType(buffer, length) != null;

    /// <summary>
    /// Похоже ли содержимое датаграммы на пакет QUIC с длинным заголовком — то есть
    /// на Initial или Handshake. Длинный заголовок и форсированный бит не скрыты
    /// защитой, поэтому такой пакет опознаётся однозначно: именно он приходит
    /// первым при несовпадении режимов. Пакеты 1-RTT опознать так нельзя: у них
    /// короткий заголовок, а признаки в нём замаскированы.
    /// </summary>
    public static bool LooksLikeQuic(byte[] buffer, int length) =>
        length >= 5 && (buffer[0] & QuicPacket.HeaderFormLong) != 0 &&
        (buffer[0] & QuicPacket.FixedBit) != 0 &&
        buffer[1] == 0 && buffer[2] == 0 && buffer[3] == 0 && buffer[4] == QuicPacket.Version1;
}
