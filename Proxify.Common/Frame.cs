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
///                0x04 = PONG (ответ прокси-сервера на PING)
///                 для 0x03/0x04 тело = маркер (например, случайные байты);
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
/// </summary>
public static class Frame
{
    public const ushort Magic = 0xC0DE;
    public const byte TypeData = 0x01;
    public const byte TypeDataEncrypted = 0x02;
    public const byte TypePing = 0x03;
    public const byte TypePong = 0x04;

    public const int HeaderLength = 3;
    public const int InnerHeaderLength = 11;

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

    private static void WriteU16(byte[] buffer, ref int offset, ushort value)
    {
        buffer[offset++] = (byte)(value >> 8);
        buffer[offset++] = (byte)value;
    }
}
