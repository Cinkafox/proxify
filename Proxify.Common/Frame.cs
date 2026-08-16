using System.Net;

namespace Proxify.Common;

/// <summary>
/// Формат туннельного кадра между прокси-сервером и прокси-клиентом.
///
/// Внешняя оболочка (big endian):
///
///   [2 байта]  magic = 0xC0DE
///   [1 байт ]  тип кадра
///                0x01 = данные без шифрования  -> далее внутренний кадр данных
///                0x02 = данные с шифрованием   -> далее [12]nonce [16]tag [N]ciphertext
///                0x03 = PING (диагностика связи при запуске прокси-клиента)
///                0x04 = PONG (ответ прокси-сервера на PING; тело = маркер + [1] флаг TCP)
///                0x05 = TCP: открытие соединения (сервер -> клиент)
///                0x06 = TCP: данные соединения (в обе стороны)
///                0x07 = TCP: закрытие соединения (в обе стороны)
///                0x08 = AUTH (рукопожатие, без шифрования) — подпись ECDSA
///                0x09 = AUTH_ACK (рукопожатие, без шифрования) — эфемерный ключ
///                       сервера + зашифрованное «доказательство»
///                 для 0x03/0x04 тело = маркер (например, случайные байты),
///                 для PONG к маркеру добавляется байт признака TCP-проксирования;
///                 при заданном cipher тело шифруется как [12]nonce [16]tag [M]ciphertext
///
/// Внутренний кадр данных (расшифрованный текст для типа 0x02):
///
///   [2 байта]  magic = 0xC0DE
///   [1 байт ]  тип = 0x01
///   [4 байта]  IPv4-адрес реального клиента (big endian)
///   [2 байта]  UDP-порт реального клиента (big endian)
///   [2 байта]  длина полезной нагрузки (big endian)
///   [N байт ]  полезная нагрузка (исходная UDP-датаграмма)
///
/// Тело TCP-кадров (расшифрованный текст, все поля big endian):
///
///   TcpOpen (0x05): [4] IPv4 реального клиента [2] TCP-порт [4] connId
///   TcpData (0x06): [4] connId [N] данные
///   TcpClose(0x07): [4] connId
///
/// Кадр AUTH (0x08) передаётся БЕЗ шифрования (plaintext):
///
///   [1] версия = 1
///   [32] X эфемерного ключа ECDH клиента
///   [32] Y эфемерного ключа ECDH клиента
///   [16] nonce
///   [64] подпись ECDSA (IEEE P1363) по "proxify-auth-v1"||X||Y||nonce
///
/// Кадр AUTH_ACK (0x09) также БЕЗ шифрования оболочки:
///
///   [32] X эфемерного ключа ECDH сервера
///   [32] Y эфемерного ключа ECDH сервера
///   [N] «доказательство», зашифрованное сессионным ключом
///       (см. TunnelCipher.Wrap и ClientConfig.EncodeProof)
/// </summary>
public static class Frame
{
    public const ushort Magic = 0xC0DE;
    public const byte TypeData = 0x01;
    public const byte TypeDataEncrypted = 0x02;
    public const byte TypePing = 0x03;
    public const byte TypePong = 0x04;
    public const byte TypeTcpOpen = 0x05;
    public const byte TypeTcpData = 0x06;
    public const byte TypeTcpClose = 0x07;
    public const byte TypeAuth = 0x08;
    public const byte TypeAuthAck = 0x09;

    public const int HeaderLength = 3;
    public const int InnerHeaderLength = 11;
    public const int TcpHeaderLength = 4;

    /// <summary>Длина тела кадра AUTH: версия + X + Y + nonce + подпись.</summary>
    public const int AuthBodyLength = 1 + 32 + 32 + 16 + 64;

    /// <summary>
    /// Собирает туннельный кадр. Если передан cipher — кадр шифруется (тип 0x02),
    /// иначе формируется незашифрованный кадр (тип 0x01).
    /// </summary>
    public static byte[] EncodeData(
        IPAddress clientIp, ushort clientPort,
        ReadOnlySpan<byte> payload, TunnelCipher? cipher)
    {
        var inner = BuildDataFrame(clientIp, clientPort, payload);

        if (cipher == null)
        {
            return inner;
        }

        var encrypted = cipher.Wrap(inner);
        var frame = new byte[HeaderLength + encrypted.Length];
        var o = 0;
        WriteU16(frame, ref o, Magic);
        frame[o++] = TypeDataEncrypted;
        encrypted.CopyTo(frame.AsSpan(o));
        return frame;
    }

    /// <summary>
    /// Разбирает туннельный кадр. Для зашифрованного кадра требуется cipher.
    /// </summary>
    public static bool TryDecodeData(
        byte[] buffer, int length, TunnelCipher? cipher,
        out IPAddress clientIp, out ushort clientPort, out byte[] payload)
    {
        clientIp = IPAddress.Any;
        clientPort = 0;
        payload = Array.Empty<byte>();

        if (buffer == null || length < HeaderLength)
            return false;

        var o = 0;
        if (ReadU16(buffer, ref o) != Magic)
            return false;

        var type = buffer[o++];
        if (type == TypeData)
        {
            return TryDecodeDataFrame(buffer, length, out clientIp, out clientPort, out payload);
        }

        if (type == TypeDataEncrypted)
        {
            if (cipher == null)
                return false;

            if (!cipher.TryUnwrap(buffer.AsSpan(o, length - o), out var inner))
                return false;

            return TryDecodeDataFrame(inner, inner.Length, out clientIp, out clientPort, out payload);
        }

        return false;
    }

    /// <summary>
    /// Определяет тип кадра по внешней оболочке (для диагностики несовпадения шифрования).
    /// Возвращает null, если это не кадр нашего протокола.
    /// </summary>
    public static byte? PeekFrameType(byte[] buffer, int length)
    {
        if (buffer == null || length < HeaderLength)
            return null;

        var o = 0;
        if (ReadU16(buffer, ref o) != Magic)
            return null;

        return buffer[o];
    }

    /// <summary>
    /// Собирает служебный кадр (PING/PONG). Тело кадра при заданном cipher шифруется.
    /// </summary>
    public static byte[] EncodeControl(byte type, byte[] payload, TunnelCipher? cipher)
    {
        var body = cipher != null ? cipher.Wrap(payload) : payload;
        var frame = new byte[HeaderLength + body.Length];
        var o = 0;
        WriteU16(frame, ref o, Magic);
        frame[o++] = type;
        body.CopyTo(frame.AsSpan(o));
        return frame;
    }

    /// <summary>
    /// Разбирает служебный кадр (PING/PONG) и возвращает его тело (маркер).
    /// Возвращает false, если кадр не того типа, имеет неверный magic или
    /// не прошёл расшифровку (например, несовпадение ключа).
    /// </summary>
    public static bool TryDecodeControl(byte[] buffer, int length, byte expectedType, TunnelCipher? cipher, out byte[] payload)
    {
        payload = Array.Empty<byte>();

        if (buffer == null || length < HeaderLength)
            return false;

        var o = 0;
        if (ReadU16(buffer, ref o) != Magic)
            return false;

        if (buffer[o++] != expectedType)
            return false;

        var body = buffer.AsSpan(o, length - o);

        if (cipher == null)
        {
            payload = body.ToArray();
            return true;
        }

        return cipher.TryUnwrap(body, out payload);
    }

    /// <summary>
    /// Собирает PONG с состоянием TCP-проксирования на сервере.
    /// Тело: [M] токен из PING + [1] байт флага (1 = TCP-проксирование включено).
    /// </summary>
    public static byte[] EncodePong(byte[] token, bool tcpEnabled, TunnelCipher? cipher)
    {
        var body = new byte[token.Length + 1];
        token.CopyTo(body, 0);
        body[^1] = tcpEnabled ? (byte)1 : (byte)0;
        return EncodeControl(TypePong, body, cipher);
    }

    /// <summary>
    /// Разбирает PONG. Возвращает токен (должен совпадать с токеном PING) и флаг
    /// TCP-проксирования. Поддерживается и старый формат PONG без флага
    /// (тело = только токен) — тогда флаг считается выключенным.
    /// </summary>
    public static bool TryDecodePong(
        byte[] buffer, int length, TunnelCipher? cipher, int expectedTokenLength,
        out byte[] token, out bool tcpEnabled)
    {
        token = Array.Empty<byte>();
        tcpEnabled = false;

        if (!TryDecodeControl(buffer, length, TypePong, cipher, out var body))
            return false;

        if (body.Length == expectedTokenLength)
        {
            // старый формат PONG: тело = только маркер
            token = body;
            return true;
        }

        if (body.Length == expectedTokenLength + 1)
        {
            tcpEnabled = body[^1] == 1;
            token = body.AsSpan(0, expectedTokenLength).ToArray();
            return true;
        }

        return false;
    }

    /// <summary>
    /// Собирает TCP-кадр открытия соединения (сервер -> клиент).
    /// Тело: [4] IPv4 реального клиента [2] TCP-порт [4] connId.
    /// </summary>
    public static byte[] EncodeTcpOpen(IPAddress clientIp, ushort clientPort, uint connId, TunnelCipher? cipher)
    {
        var body = new byte[10];
        var o = 0;

        var ip = clientIp.GetAddressBytes();
        if (ip.Length != 4)
            throw new ArgumentException("Поддерживается только IPv4.", nameof(clientIp));
        Array.Copy(ip, 0, body, 0, 4);
        o += 4;

        WriteU16(body, ref o, clientPort);
        WriteU32(body, ref o, connId);
        return EncodeControl(TypeTcpOpen, body, cipher);
    }

    /// <summary>
    /// Разбирает TCP-кадр открытия соединения.
    /// </summary>
    public static bool TryDecodeTcpOpen(
        byte[] buffer, int length, TunnelCipher? cipher,
        out IPAddress clientIp, out ushort clientPort, out uint connId)
    {
        clientIp = IPAddress.Any;
        clientPort = 0;
        connId = 0;

        if (!TryDecodeControl(buffer, length, TypeTcpOpen, cipher, out var body) || body.Length != 10)
            return false;

        var o = 0;
        var ip = new byte[4];
        Array.Copy(body, o, ip, 0, 4);
        o += 4;
        clientIp = new IPAddress(ip);
        clientPort = ReadU16(body, ref o);
        connId = ReadU32(body, ref o);
        return true;
    }

    /// <summary>
    /// Собирает TCP-кадр данных. Тело: [4] connId [N] данные.
    /// </summary>
    public static byte[] EncodeTcpData(uint connId, ReadOnlySpan<byte> payload, TunnelCipher? cipher)
    {
        var body = new byte[TcpHeaderLength + payload.Length];
        var o = 0;
        WriteU32(body, ref o, connId);
        payload.CopyTo(body.AsSpan(o));
        return EncodeControl(TypeTcpData, body, cipher);
    }

    /// <summary>
    /// Разбирает TCP-кадр данных.
    /// </summary>
    public static bool TryDecodeTcpData(byte[] buffer, int length, TunnelCipher? cipher, out uint connId, out byte[] payload)
    {
        connId = 0;
        payload = Array.Empty<byte>();

        if (!TryDecodeControl(buffer, length, TypeTcpData, cipher, out var body) || body.Length < TcpHeaderLength)
            return false;

        var o = 0;
        connId = ReadU32(body, ref o);
        payload = new byte[body.Length - o];
        Array.Copy(body, o, payload, 0, payload.Length);
        return true;
    }

    /// <summary>
    /// Собирает TCP-кадр закрытия соединения. Тело: [4] connId.
    /// </summary>
    public static byte[] EncodeTcpClose(uint connId, TunnelCipher? cipher)
    {
        var body = new byte[TcpHeaderLength];
        var o = 0;
        WriteU32(body, ref o, connId);
        return EncodeControl(TypeTcpClose, body, cipher);
    }

    /// <summary>
    /// Разбирает TCP-кадр закрытия соединения.
    /// </summary>
    public static bool TryDecodeTcpClose(byte[] buffer, int length, TunnelCipher? cipher, out uint connId)
    {
        connId = 0;

        if (!TryDecodeControl(buffer, length, TypeTcpClose, cipher, out var body) || body.Length != TcpHeaderLength)
            return false;

        var o = 0;
        connId = ReadU32(body, ref o);
        return true;
    }

    /// <summary>
    /// Собирает кадр AUTH (рукопожатие, без шифрования оболочки).
    /// Тело: [1] версия [32] X [32] Y [16] nonce [64] подпись.
    /// </summary>
    public static byte[] EncodeAuth(
        byte version,
        ReadOnlySpan<byte> ephX,
        ReadOnlySpan<byte> ephY,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> signature)
    {
        if (ephX.Length != 32 || ephY.Length != 32 || nonce.Length != 16 || signature.Length != 64)
            throw new ArgumentException("Неверная длина полей кадра AUTH.");

        var frame = new byte[HeaderLength + AuthBodyLength];
        var o = 0;
        WriteU16(frame, ref o, Magic);
        frame[o++] = TypeAuth;
        frame[o++] = version;
        ephX.CopyTo(frame.AsSpan(o));
        o += ephX.Length;
        ephY.CopyTo(frame.AsSpan(o));
        o += ephY.Length;
        nonce.CopyTo(frame.AsSpan(o));
        o += nonce.Length;
        signature.CopyTo(frame.AsSpan(o));
        return frame;
    }

    /// <summary>
    /// Разбирает кадр AUTH.
    /// </summary>
    public static bool TryDecodeAuth(
        byte[] buffer, int length,
        out byte version,
        out byte[] ephX, out byte[] ephY, out byte[] nonce, out byte[] signature)
    {
        version = 0;
        ephX = ephY = nonce = signature = Array.Empty<byte>();

        if (buffer == null || length != HeaderLength + AuthBodyLength)
            return false;

        var o = 0;
        if (ReadU16(buffer, ref o) != Magic)
            return false;
        if (buffer[o++] != TypeAuth)
            return false;

        version = buffer[o++];
        ephX = Slice(buffer, ref o, 32);
        ephY = Slice(buffer, ref o, 32);
        nonce = Slice(buffer, ref o, 16);
        signature = Slice(buffer, ref o, 64);
        return true;
    }

    /// <summary>
    /// Собирает кадр AUTH_ACK (рукопожатие, без шифрования оболочки).
    /// Тело: [32] X [32] Y [N] зашифрованное «доказательство».
    /// </summary>
    public static byte[] EncodeAuthAck(ReadOnlySpan<byte> sX, ReadOnlySpan<byte> sY, ReadOnlySpan<byte> wrappedProof)
    {
        if (sX.Length != 32 || sY.Length != 32)
            throw new ArgumentException("Неверная длина полей кадра AUTH_ACK.");

        var frame = new byte[HeaderLength + 64 + wrappedProof.Length];
        var o = 0;
        WriteU16(frame, ref o, Magic);
        frame[o++] = TypeAuthAck;
        sX.CopyTo(frame.AsSpan(o));
        o += 32;
        sY.CopyTo(frame.AsSpan(o));
        o += 32;
        wrappedProof.CopyTo(frame.AsSpan(o));
        return frame;
    }

    /// <summary>
    /// Разбирает кадр AUTH_ACK.
    /// </summary>
    public static bool TryDecodeAuthAck(byte[] buffer, int length, out byte[] sX, out byte[] sY, out byte[] wrappedProof)
    {
        sX = sY = wrappedProof = Array.Empty<byte>();

        if (buffer == null || length <= HeaderLength + 64)
            return false;

        var o = 0;
        if (ReadU16(buffer, ref o) != Magic)
            return false;
        if (buffer[o++] != TypeAuthAck)
            return false;

        sX = Slice(buffer, ref o, 32);
        sY = Slice(buffer, ref o, 32);
        wrappedProof = new byte[length - o];
        Array.Copy(buffer, o, wrappedProof, 0, wrappedProof.Length);
        return true;
    }

    private static byte[] Slice(byte[] buffer, ref int offset, int count)
    {
        var result = new byte[count];
        Array.Copy(buffer, offset, result, 0, count);
        offset += count;
        return result;
    }

    private static byte[] BuildDataFrame(IPAddress clientIp, ushort clientPort, ReadOnlySpan<byte> payload)
    {
        if (clientIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new ArgumentException("Поддерживается только IPv4.", nameof(clientIp));

        var frame = new byte[InnerHeaderLength + payload.Length];
        var o = 0;

        WriteU16(frame, ref o, Magic);
        frame[o++] = TypeData;

        var ip = clientIp.GetAddressBytes();
        Array.Copy(ip, 0, frame, o, 4);
        o += 4;

        WriteU16(frame, ref o, clientPort);
        WriteU16(frame, ref o, (ushort)payload.Length);
        payload.CopyTo(frame.AsSpan(o));
        return frame;
    }

    private static bool TryDecodeDataFrame(byte[] buffer, int length, out IPAddress clientIp, out ushort clientPort, out byte[] payload)
    {
        clientIp = IPAddress.Any;
        clientPort = 0;
        payload = Array.Empty<byte>();

        if (buffer == null || length < InnerHeaderLength)
            return false;

        var o = 0;
        if (ReadU16(buffer, ref o) != Magic)
            return false;

        if (buffer[o++] != TypeData)
            return false;

        var ip = new byte[4];
        Array.Copy(buffer, o, ip, 0, 4);
        o += 4;
        clientIp = new IPAddress(ip);

        clientPort = ReadU16(buffer, ref o);

        int payloadLength = ReadU16(buffer, ref o);
        if (payloadLength > length - o)
            return false;

        payload = new byte[payloadLength];
        Array.Copy(buffer, o, payload, 0, payloadLength);
        return true;
    }

    private static ushort ReadU16(byte[] buffer, ref int offset)
    {
        var value = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
        offset += 2;
        return value;
    }

    private static uint ReadU32(byte[] buffer, ref int offset)
    {
        var value = ((uint)buffer[offset] << 24) | ((uint)buffer[offset + 1] << 16) |
                    ((uint)buffer[offset + 2] << 8) | buffer[offset + 3];
        offset += 4;
        return value;
    }

    private static void WriteU16(byte[] buffer, ref int offset, ushort value)
    {
        buffer[offset++] = (byte)(value >> 8);
        buffer[offset++] = (byte)value;
    }

    private static void WriteU32(byte[] buffer, ref int offset, uint value)
    {
        buffer[offset++] = (byte)(value >> 24);
        buffer[offset++] = (byte)(value >> 16);
        buffer[offset++] = (byte)(value >> 8);
        buffer[offset++] = (byte)value;
    }
}
