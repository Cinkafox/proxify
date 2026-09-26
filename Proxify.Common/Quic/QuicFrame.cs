namespace Proxify.Common.Quic;

/// <summary>
/// Типы и кодирование кадров QUIC (RFC 9000, раздел 19), которые нужны маскировке
/// туннеля.
///
/// Наружу (в зашифрованную полезную нагрузку пакета) уходят кадры тех же типов и с
/// той же структурой, что и у настоящего клиента QUIC: PADDING, PING, ACK, CRYPTO,
/// STREAM, MAX_DATA/MAX_STREAMS, NEW_CONNECTION_ID, PATH_CHALLENGE/RESPONSE,
/// HANDSHAKE_DONE, KEY_UPDATE, CONNECTION_CLOSE. Наблюдатель не может их прочитать
/// (AEAD), но их набор и порядок формируют ту же картину внутри пакета, что и у
/// настоящего соединения.
///
/// Числовые значения типов взяты из спецификации, включая HANDSHAKE_DONE = 0x1E и
/// KEY_UPDATE = 0x1F (в проекте они часто путают, порядок важен для правдоподобия).
/// </summary>
public static class QuicFrame
{
    public const ulong Padding = 0x00;
    public const ulong Ping = 0x01;
    public const ulong Ack = 0x02;
    public const ulong ResetStream = 0x04;
    public const ulong StopSending = 0x05;
    public const ulong Crypto = 0x06;
    public const ulong NewToken = 0x07;

    /// <summary>STREAM занимает диапазон 0x08..0x0F: биты OFF (0x04), LEN (0x02), FIN (0x01).</summary>
    public const ulong StreamBase = 0x08;

    public const ulong StreamOffBit = 0x04;
    public const ulong StreamLenBit = 0x02;
    public const ulong StreamFinBit = 0x01;

    public const ulong MaxData = 0x10;
    public const ulong MaxStreamData = 0x11;
    public const ulong MaxStreamsUni = 0x12;
    public const ulong MaxStreamsBidi = 0x13;
    public const ulong DataBlocked = 0x14;
    public const ulong StreamDataBlocked = 0x15;
    public const ulong NewConnectionId = 0x18;
    public const ulong RetireConnectionId = 0x19;
    public const ulong PathChallenge = 0x1A;
    public const ulong PathResponse = 0x1B;
    public const ulong ConnectionCloseTransport = 0x1C;
    public const ulong ConnectionCloseApplication = 0x1D;
    public const ulong HandshakeDone = 0x1E;
    public const ulong KeyUpdate = 0x1F;

    /// <summary>Тип кадра STREAM с явными смещением и длиной (тело всегда с обоими битами).</summary>
    public const ulong StreamWithOffsetAndLength = StreamBase | StreamOffBit | StreamLenBit;

    /// <summary>Код приложения в CONNECTION_CLOSE при штатном закрытии туннеля.</summary>
    public const ulong ApplicationCloseCode = 0x00;

    public static void WriteAck(QuicWriter writer, in QuicAck ack)
    {
        writer.WriteVarInt(Ack);
        writer.WriteVarInt(ack.LargestAcknowledged);
        writer.WriteVarInt(ack.AckDelay);
        writer.WriteVarInt(ack.RangeCount);
        writer.WriteVarInt(ack.FirstAckRange);
        foreach (var (gap, range) in ack.Ranges)
        {
            writer.WriteVarInt(gap);
            writer.WriteVarInt(range);
        }
    }

    /// <summary>Кадр PING — служебный, но «побуждающий к подтверждению» (ack-eliciting).</summary>
    public static void WritePing(QuicWriter writer) => writer.WriteVarInt(Ping);

    /// <summary>
    /// Кадр CRYPTO: байты рукопожатия TLS. В Initial уходит ClientHello/ServerHello,
    /// в Handshake — содержимое уровня Handshake (у нас — кадр рукопожатия туннеля).
    /// </summary>
    public static void WriteCrypto(QuicWriter writer, ulong offset, ReadOnlySpan<byte> data)
    {
        writer.WriteVarInt(Crypto);
        writer.WriteVarInt(offset);
        writer.WriteVarInt((ulong)data.Length);
        writer.WriteBytes(data);
    }

    /// <summary>Кадр STREAM с данными потока и явными смещением и длиной.</summary>
    public static void WriteStream(QuicWriter writer, ulong streamId, ulong offset, ReadOnlySpan<byte> data, bool fin = false)
    {
        writer.WriteVarInt(StreamWithOffsetAndLength | (fin ? StreamFinBit : 0));
        writer.WriteVarInt(streamId);
        writer.WriteVarInt(offset);
        writer.WriteVarInt((ulong)data.Length);
        writer.WriteBytes(data);
    }

    public static void WriteMaxData(QuicWriter writer, ulong value)
    {
        writer.WriteVarInt(MaxData);
        writer.WriteVarInt(value);
    }

    public static void WriteMaxStreams(QuicWriter writer, bool bidirectional, ulong value)
    {
        writer.WriteVarInt(bidirectional ? MaxStreamsBidi : MaxStreamsUni);
        writer.WriteVarInt(value);
    }

    public static void WriteNewConnectionId(QuicWriter writer, ulong sequence, ulong retirePriorTo, ReadOnlySpan<byte> cid, ReadOnlySpan<byte> token)
    {
        writer.WriteVarInt(NewConnectionId);
        writer.WriteVarInt(sequence);
        writer.WriteVarInt(retirePriorTo);
        writer.WriteByte((byte)cid.Length);
        writer.WriteBytes(cid);
        writer.WriteBytes(token);
    }

    public static void WritePathChallenge(QuicWriter writer, ReadOnlySpan<byte> data)
    {
        writer.WriteVarInt(PathChallenge);
        writer.WriteBytes(data);
    }

    public static void WritePathResponse(QuicWriter writer, ReadOnlySpan<byte> data)
    {
        writer.WriteVarInt(PathResponse);
        writer.WriteBytes(data);
    }

    public static void WriteHandshakeDone(QuicWriter writer) => writer.WriteVarInt(HandshakeDone);

    /// <summary>Кадр KEY_UPDATE (RFC 9001, раздел 6): длина равна 1, значение — фаза ключей.</summary>
    public static void WriteKeyUpdate(QuicWriter writer, bool requestUpdate)
    {
        writer.WriteVarInt(KeyUpdate);
        writer.WriteVarInt(1);
        writer.WriteByte(requestUpdate ? (byte)0 : (byte)1);
    }

    public static void WriteConnectionCloseApplication(QuicWriter writer, ulong errorCode, ReadOnlySpan<byte> reason)
    {
        writer.WriteVarInt(ConnectionCloseApplication);
        writer.WriteVarInt(errorCode);
        writer.WriteVarInt((ulong)reason.Length);
        writer.WriteBytes(reason);
    }

    public static void WriteConnectionCloseTransport(QuicWriter writer, ulong errorCode, ulong frameType, ReadOnlySpan<byte> reason)
    {
        writer.WriteVarInt(ConnectionCloseTransport);
        writer.WriteVarInt(errorCode);
        writer.WriteVarInt(frameType);
        writer.WriteVarInt((ulong)reason.Length);
        writer.WriteBytes(reason);
    }
}

/// <summary>Содержимое кадра ACK в разобранном виде (см. QuicAckState).</summary>
public readonly struct QuicAck
{
    /// <summary>Пустой кадр ACK: все поля необязательны и заполняются инициализаторами.</summary>
    public QuicAck()
    {
    }

    /// <summary>Наибольший подтверждаемый номер пакета.</summary>
    public ulong LargestAcknowledged { get; init; }

    /// <summary>Задержка подтверждения в единицах 2^ack_delay_exponent микросекунд.</summary>
    public ulong AckDelay { get; init; }

    /// <summary>Число дополнительных диапазонов после первого.</summary>
    public ulong RangeCount { get; init; }

    /// <summary>Размер первого диапазона (largest - smallest).</summary>
    public ulong FirstAckRange { get; init; }

    /// <summary>Пары (gap, range) для остальных диапазонов, по убыванию номеров.</summary>
    public IReadOnlyList<(ulong Gap, ulong Range)> Ranges { get; init; } = Array.Empty<(ulong, ulong)>();
}
