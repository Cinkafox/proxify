using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Proxify.Common.Quic;

/// <summary>Тип пакета длинного заголовка (RFC 9000, таблица в разделе 17.2).</summary>
public enum QuicLongPacketType : byte
{
    Initial = 0,
    ZeroRtt = 1,
    Handshake = 2,
    Retry = 3,
}

/// <summary>Разобранный заголовок пакета длинного заголовка.</summary>
public readonly struct QuicLongHeader
{
    /// <summary>Пустой заголовок: все поля необязательны и заполняются инициализаторами.</summary>
    public QuicLongHeader()
    {
    }

    public QuicLongPacketType Type { get; init; }
    public uint Version { get; init; }

    /// <summary>Идентификатор соединения назначения (его выбирает сервер).</summary>
    public byte[] Dcid { get; init; } = Array.Empty<byte>();

    /// <summary>Идентификатор соединения источника (его выбирает клиент).</summary>
    public byte[] Scid { get; init; } = Array.Empty<byte>();

    /// <summary>Token из поля Initial (пустой у первого пакета клиента).</summary>
    public byte[] Token { get; init; } = Array.Empty<byte>();

    /// <summary>Значение поля Length: длина номера пакета, полезной нагрузки и метки.</summary>
    public ulong Length { get; init; }

    /// <summary>Смещение номера пакета от начала датаграммы.</summary>
    public int PacketNumberOffset { get; init; }

    /// <summary>Общая длина пакета в датаграмме (начало пакета + Length).</summary>
    public int PacketLength { get; init; }

    /// <summary>Смещение первого байта пакета в датаграмме.</summary>
    public int Offset { get; init; }
}

/// <summary>
/// Сборка и разбор пакетов QUIC: длинный заголовок (Initial/Handshake) и короткий
/// заголовок (1-RTT).
///
/// Заголовок длинного формата содержит версию, DCID, SCID, для Initial — token и
/// длину, поэтому границу пакета видно без расшифровки: в одну датаграмму можно
/// объединять несколько пакетов (coalescing), как это делает настоящий клиент.
/// У короткого заголовка длины нет — пакет всегда последний в датаграмме, а число
/// байт идентификатора соединения известно заранее (в маскировке фиксировано).
///
/// Сборка: номер пакета и кадры шифруются AES-128-GCM, в качестве
/// дополнительных данных берётся сам заголовок, затем накладывается защита
/// заголовка. Разбор — обратная операция с восстановлением полного номера пакета
/// из усечённого.
/// </summary>
public static class QuicPacket
{
    /// <summary>Версия QUIC v1.</summary>
    public const uint Version1 = 0x00000001;

    /// <summary>Версия, означающая Version Negotiation.</summary>
    public const uint VersionNegotiation = 0x00000000;

    public const byte HeaderFormLong = 0x80;
    public const byte FixedBit = 0x40;

    /// <summary>Смещение битов типа пакета в длинном заголовке.</summary>
    public const int LongPacketTypeShift = 4;

    /// <summary>Минимальная длина датаграммы с пакетом Initial (RFC 9000, раздел 14.1).</summary>
    public const int MinInitialDatagram = 1200;

    /// <summary>Предельная длина датаграммы маскировки (не нарушает MTU 1500).</summary>
    public const int MaxDatagram = 1452;

    /// <summary>
    /// Разбирает заголовок длинного формата, начиная с <paramref name="offset"/>.
    /// Возвращает false, если это не пакет длинного заголовка либо данные повреждены.
    /// </summary>
    public static bool TryParseLongHeader(byte[] datagram, int offset, int length, out QuicLongHeader header)
    {
        header = default;
        var end = offset + length;
        if (length < 7 || end > datagram.Length)
            return false;
        if ((datagram[offset] & HeaderFormLong) == 0)
            return false;

        var first = datagram[offset];
        var type = (QuicLongPacketType)((first >> LongPacketTypeShift) & 0x03);
        var pnLength = (first & 0x03) + 1;

        var o = offset + 1;
        if (o + 4 > end)
            return false;
        var version = BinaryPrimitives.ReadUInt32BigEndian(datagram.AsSpan(o));
        o += 4;

        if (o >= end)
            return false;
        var dcidLength = datagram[o++];
        if (o + dcidLength > end)
            return false;
        var dcid = Slice(datagram, o, dcidLength);
        o += dcidLength;

        if (o >= end)
            return false;
        var scidLength = datagram[o++];
        if (o + scidLength > end)
            return false;
        var scid = Slice(datagram, o, scidLength);
        o += scidLength;

        var token = Array.Empty<byte>();
        if (type == QuicLongPacketType.Initial)
        {
            if (!QuicVarInt.TryRead(datagram.AsSpan(o, end - o), out var tokenLength, out var tokenSize))
                return false;
            o += tokenSize;
            if (tokenLength > (ulong)(end - o))
                return false;
            token = Slice(datagram, o, (int)tokenLength);
            o += (int)tokenLength;
        }

        if (!QuicVarInt.TryRead(datagram.AsSpan(o, end - o), out var payloadLength, out var lengthSize))
            return false;
        o += lengthSize;

        // Length обязан покрывать номер пакета, полезную нагрузку и метку AEAD.
        if (payloadLength < (ulong)(1 + QuicPacketKeys.TagSize))
            return false;

        var packetLength = o + (int)payloadLength;
        if (packetLength > end)
            return false;

        header = new QuicLongHeader
        {
            Type = type,
            Version = version,
            Dcid = dcid,
            Scid = scid,
            Token = token,
            Length = payloadLength,
            PacketNumberOffset = o,
            PacketLength = packetLength,
            Offset = offset,
        };
        return true;
    }

    /// <summary>
    /// Проверяет, что по смещению <paramref name="offset"/> начинается пакет короткого
    /// заголовка, и возвращает смещение и длину номера пакета. dcidLength — длина
    /// идентификатора соединения, известная получателю заранее.
    /// </summary>
    public static bool TryParseShortHeader(byte[] datagram, int offset, int length, int dcidLength, out int packetNumberOffset)
    {
        packetNumberOffset = 0;

        if (length < 1)
            return false;
        if ((datagram[offset] & HeaderFormLong) != 0)
            return false;
        if ((datagram[offset] & FixedBit) == 0)
            return false;

        var pnOffset = offset + 1 + dcidLength;

        // Выборка для защиты заголовка — 16 байт с отступом 4 от начала номера
        // пакета. Она накладывается на шифротекст, поэтому метка AEAD отдельно не
        // проверяется: длину номера узнаём только после снятия защиты.
        if (pnOffset + 4 + 16 > offset + length)
            return false;

        packetNumberOffset = pnOffset;
        return true;
    }

    /// <summary>
    /// Собирает пакет длинного заголовка с одним или несколькими кадрами. Пакет
    /// занимает всю переданную датуграмму, поэтому дополнительный объём
    /// добавляется вызывающим кодом кадрами PADDING в <paramref name="frames"/>.
    /// </summary>
    public static byte[] BuildLong(
        QuicLongPacketType type,
        ReadOnlySpan<byte> dcid,
        ReadOnlySpan<byte> scid,
        ReadOnlySpan<byte> token,
        ulong packetNumber,
        int packetNumberLength,
        QuicPacketKeys keys,
        ReadOnlySpan<byte> frames)
    {
        var payloadLength = packetNumberLength + frames.Length + QuicPacketKeys.TagSize;
        var lengthFieldSize = QuicVarInt.SizeOf((ulong)payloadLength);
        var tokenFieldSize = type == QuicLongPacketType.Initial
            ? QuicVarInt.SizeOf((ulong)token.Length)
            : 0;

        var headerSize = 1 + 4 + 1 + dcid.Length + 1 + scid.Length + tokenFieldSize + lengthFieldSize;
        var packet = new byte[headerSize + payloadLength];
        var o = 0;

        // Форсированный бит, тип, длина номера пакета в младших битах
        // (замаскируется защитой заголовка).
        packet[o++] = (byte)(HeaderFormLong | FixedBit |
                            ((byte)type << LongPacketTypeShift) |
                            (packetNumberLength - 1));
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(o), Version1);
        o += 4;
        packet[o++] = (byte)dcid.Length;
        dcid.CopyTo(packet.AsSpan(o));
        o += dcid.Length;
        packet[o++] = (byte)scid.Length;
        scid.CopyTo(packet.AsSpan(o));
        o += scid.Length;

        if (type == QuicLongPacketType.Initial)
        {
            QuicVarInt.Write(packet.AsSpan(o), (ulong)token.Length);
            o += tokenFieldSize;
            token.CopyTo(packet.AsSpan(o));
            o += token.Length;
        }

        QuicVarInt.Write(packet.AsSpan(o), (ulong)payloadLength);
        o += lengthFieldSize;

        var packetNumberOffset = o;
        WritePacketNumber(packet.AsSpan(o), packetNumber, packetNumberLength);
        o += packetNumberLength;
        frames.CopyTo(packet.AsSpan(o));
        o += frames.Length;

        Seal(packet, o, 0, packetNumberOffset, packetNumberLength, isLongHeader: true, keys, packetNumber);
        return packet;
    }

    /// <summary>Собирает пакет короткого заголовка (1-RTT).</summary>
    public static byte[] BuildShort(
        ReadOnlySpan<byte> dcid,
        bool keyPhase,
        ulong packetNumber,
        int packetNumberLength,
        QuicPacketKeys keys,
        ReadOnlySpan<byte> frames)
    {
        var payloadLength = packetNumberLength + frames.Length + QuicPacketKeys.TagSize;
        var packet = new byte[1 + dcid.Length + payloadLength];

        packet[0] = (byte)(FixedBit | (keyPhase ? 0x04 : 0) | (packetNumberLength - 1));
        dcid.CopyTo(packet.AsSpan(1));

        var o = 1 + dcid.Length;
        var packetNumberOffset = o;
        WritePacketNumber(packet.AsSpan(o), packetNumber, packetNumberLength);
        o += packetNumberLength;
        frames.CopyTo(packet.AsSpan(o));
        o += frames.Length;

        Seal(packet, o, 0, packetNumberOffset, packetNumberLength, isLongHeader: false, keys, packetNumber);
        return packet;
    }

    /// <summary>
    /// Длина пакета длинного заголовка с заданным объёмом кадров — нужно, чтобы
    /// паддингом довести датаграмму ровно до требуемой длины.
    /// </summary>
    public static int LongPacketLength(
        QuicLongPacketType type,
        int dcidLength,
        int scidLength,
        int tokenLength,
        int packetNumberLength,
        int framesLength)
    {
        var payloadLength = packetNumberLength + framesLength + QuicPacketKeys.TagSize;
        var header = 1 + 4 + 1 + dcidLength + 1 + scidLength;
        if (type == QuicLongPacketType.Initial)
            header += QuicVarInt.SizeOf((ulong)tokenLength);
        header += QuicVarInt.SizeOf((ulong)payloadLength);
        return header + payloadLength;
    }

    /// <summary>Длина пакета короткого заголовка с заданным объёмом кадров.</summary>
    public static int ShortPacketLength(int dcidLength, int packetNumberLength, int framesLength) =>
        1 + dcidLength + packetNumberLength + framesLength + QuicPacketKeys.TagSize;

    /// <summary>
    /// Снимает защиту заголовка, восстанавливает полный номер пакета из усечённого и
    /// расшифровывает полезную нагрузку пакета, начинающегося с
    /// <paramref name="packetOffset"/>. При неудаче восстанавливает исходные байты
    /// заголовка (защита симметрична), чтобы буфер можно было попробовать другим
    /// кандидатом на сервере, и возвращает false.
    /// </summary>
    public static bool TryOpen(
        byte[] packet,
        int packetOffset,
        int packetLength,
        int packetNumberOffset,
        bool isLongHeader,
        QuicPacketKeys keys,
        long expectedPacketNumber,
        out ulong packetNumber,
        out byte[] payload)
    {
        packetNumber = 0;
        payload = Array.Empty<byte>();

        // Длина номера пакета хранится в защищённых битах первого байта, поэтому её
        // узнают только после снятия защики с первого байта. Снятие симметрично, но
        // для повторной попытки другим ключом байты обязаны вернуться в исходное
        // состояние, поэтому весь разбор обёрнут в try/finally.
        var packetNumberLength = keys.UnmaskFirstByte(packet, packetOffset, packetNumberOffset, isLongHeader);
        var packetNumberUnmasked = false;
        try
        {
            if (packetNumberOffset + packetNumberLength > packetOffset + packetLength)
                return false;

            keys.TogglePacketNumber(packet, packetNumberOffset, packetNumberLength);
            packetNumberUnmasked = true;

            var truncated = ReadPacketNumber(packet.AsSpan(packetNumberOffset, packetNumberLength));
            packetNumber = ReconstructPacketNumber(truncated, packetNumberLength, expectedPacketNumber);

            var payloadOffset = packetNumberOffset + packetNumberLength;
            var cipherLength = packetOffset + packetLength - payloadOffset - QuicPacketKeys.TagSize;
            if (cipherLength < 0)
                return false;

            var associatedData = packet.AsSpan(packetOffset, payloadOffset - packetOffset);
            var cipher = packet.AsSpan(payloadOffset, cipherLength);
            var tag = packet.AsSpan(payloadOffset + cipherLength, QuicPacketKeys.TagSize);

            var plain = new byte[cipherLength];
            using (var gcm = new AesGcm(keys.Key, QuicPacketKeys.TagSize))
            {
                gcm.Decrypt(keys.MakeNonce(packetNumber), cipher, tag, plain, associatedData);
            }

            payload = plain;
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            // Заголовок всегда возвращается в исходное (защищённое) состояние:
            // сервер пробует одну и ту же датаграмму против нескольких кандидатов,
            // поэтому после попытки буфер обязан остаться байт в байт прежним.
            if (packetNumberUnmasked)
                keys.TogglePacketNumber(packet, packetNumberOffset, packetNumberLength);
            keys.ToggleFirstByte(packet, packetOffset, packetNumberOffset, isLongHeader);
        }
    }

    /// <summary>
    /// Восстанавливает полный номер пакета из усечённого по ожидаемому значению
    /// (RFC 9000, раздел 17.1). Значение <paramref name="expected"/> равное -1
    /// означает, что предыдущие пакеты не принимались (тогда номер берётся как есть).
    /// </summary>
    public static ulong ReconstructPacketNumber(ulong truncated, int packetNumberLength, long expected)
    {
        var window = 1UL << (packetNumberLength * 8);
        var halfWindow = window / 2;
        var mask = window - 1;

        if (expected < 0)
            return truncated & mask;

        var expectedValue = (ulong)expected;
        var candidate = (expectedValue & ~mask) | (truncated & mask);
        var maxPacketNumber = (1UL << 62) - 1;

        if (candidate + halfWindow <= expectedValue && candidate < maxPacketNumber - window)
            candidate += window;
        else if (candidate > expectedValue + halfWindow && candidate >= window)
            candidate -= window;

        return candidate;
    }

    /// <summary>
    /// Шифрует номер пакета и кадры (AAD — сам заголовок), затем накладывает защиту
    /// заголовка. plainEnd — конец открытого текста (номер пакета + кадры),
    /// packetStart — начало пакета в буфере.
    /// </summary>
    private static void Seal(byte[] packet, int plainEnd, int packetStart, int packetNumberOffset, int packetNumberLength, bool isLongHeader, QuicPacketKeys keys, ulong packetNumber)
    {
        using var gcm = new AesGcm(keys.Key, QuicPacketKeys.TagSize);

        // Дополнительные данные — только заголовок с номером пакета, без кадров.
        // Защита заголовка накладывается после шифрования, поэтому в AAD байты
        // заголовка ещё не замаскированы.
        var payloadOffset = packetNumberOffset + packetNumberLength;
        var associatedData = packet.AsSpan(packetStart, payloadOffset - packetStart);

        // Шифрование на месте: шифротекст занимает то же место в буфере, что и открытый.
        var plaintext = packet.AsSpan(payloadOffset, plainEnd - payloadOffset);
        var tag = packet.AsSpan(plainEnd, QuicPacketKeys.TagSize);
        gcm.Encrypt(keys.MakeNonce(packetNumber), plaintext, plaintext, tag, associatedData);

        keys.ToggleHeaderProtection(packet, packetStart, packetNumberOffset, packetNumberLength, isLongHeader);
    }

    private static void WritePacketNumber(Span<byte> destination, ulong packetNumber, int length)
    {
        for (var i = length - 1; i >= 0; i--)
            destination[i] = (byte)(packetNumber >> (8 * i));
    }

    private static ulong ReadPacketNumber(ReadOnlySpan<byte> source)
    {
        ulong value = 0;
        foreach (var b in source)
            value = (value << 8) | b;
        return value;
    }

    private static byte[] Slice(byte[] buffer, int offset, int count)
    {
        var result = new byte[count];
        Array.Copy(buffer, offset, result, 0, count);
        return result;
    }
}
