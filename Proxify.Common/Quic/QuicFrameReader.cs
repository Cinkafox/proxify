namespace Proxify.Common.Quic;

/// <summary>
/// Разбор кадров QUIC в расшифрованной полезной нагрузке пакета.
///
/// Возвращает только то, что нужно маскировке: данные потока туннеля, служебные
/// кадры (ACK/PING/KEY_UPDATE/PATH_CHALLENGE/CONNECTION_CLOSE) и признак того, что
/// кадр «побуждает к подтверждению» (ack-eliciting) — по нему ведётся учёт
/// подтверждений и решается, нужно ли отвечать. Неизвестные типы кадров
/// пропускаются по RFC 9000, но их длину узнать нельзя, поэтому такой пакет
/// помечается как неразобранный, чтобы не принять мусор за данные туннеля.
/// </summary>
public ref struct QuicFrameReader
{
    private readonly ReadOnlySpan<byte> _payload;
    private int _offset;

    public QuicFrameReader(ReadOnlySpan<byte> payload)
    {
        _payload = payload;
        _offset = 0;
        // Valid = true по умолчанию: если разбор дойдёт до конца полезной нагрузки
        // без ошибки, последний кадр останется корректным. Ошибка разбора
        // устанавливает Valid = false (см. Fail), что отличает «конец» от «мусора».
        Current = new QuicFrameInfo { Valid = true };
    }

    /// <summary>Описание последнего прочитанного кадра.</summary>
    public QuicFrameInfo Current;

    /// <summary>Читает очередной кадр. Возвращает false в конце полезной нагрузки.</summary>
    public bool Read()
    {
        while (_offset < _payload.Length)
        {
            if (!QuicVarInt.TryRead(_payload[_offset..], out var type, out var typeSize))
                return Fail();

            _offset += typeSize;

            // PADDING идёт до конца пакета и не считается отдельным кадром.
            if (type == QuicFrame.Padding)
            {
                var start = _offset;
                while (_offset < _payload.Length && _payload[_offset] == 0)
                    _offset++;
                if (start == _offset)
                    continue;
                Current = QuicFrameInfo.ForPadding(_offset - start);
                return true;
            }

            if (type < QuicFrame.StreamBase || type > QuicFrame.StreamBase + 0x07)
            {
                switch (type)
                {
                    case QuicFrame.Ping:
                        Current = QuicFrameInfo.ForSimple(QuicFrame.Ping, ackEliciting: true);
                        return true;

                    case QuicFrame.Ack:
                        return ReadAck();

                    case QuicFrame.Crypto:
                    {
                        if (!TryVarInt(out var offset) || !TryVarInt(out var length) || !TryBytes((int)length, out var data))
                            return Fail();
                        Current = QuicFrameInfo.ForCrypto(offset, data, ackEliciting: true);
                        return true;
                    }

                    case QuicFrame.NewConnectionId:
                    {
                        if (!TryVarInt(out _) || !TryVarInt(out _) || !TryByte(out var cidLength) ||
                            !TryBytes(cidLength, out _) || !TryBytes(16, out _))
                            return Fail();
                        Current = QuicFrameInfo.ForSimple(QuicFrame.NewConnectionId, ackEliciting: true);
                        return true;
                    }

                    case QuicFrame.RetireConnectionId:
                        if (!TryVarInt(out _))
                            return Fail();
                        Current = QuicFrameInfo.ForSimple(QuicFrame.RetireConnectionId, ackEliciting: true);
                        return true;

                    case QuicFrame.PathChallenge:
                    case QuicFrame.PathResponse:
                    {
                        if (!TryBytes(8, out var data))
                            return Fail();
                        Current = type == QuicFrame.PathChallenge
                            ? QuicFrameInfo.ForPathChallenge(data)
                            : QuicFrameInfo.ForPathResponse(data);
                        return true;
                    }

                    case QuicFrame.MaxData:
                        if (!TryVarInt(out _))
                            return Fail();
                        Current = QuicFrameInfo.ForSimple(QuicFrame.MaxData, ackEliciting: true);
                        return true;

                    case QuicFrame.MaxStreamsBidi:
                    case QuicFrame.MaxStreamsUni:
                        if (!TryVarInt(out _))
                            return Fail();
                        Current = QuicFrameInfo.ForSimple(type, ackEliciting: true);
                        return true;

                    case QuicFrame.HandshakeDone:
                        Current = QuicFrameInfo.ForSimple(QuicFrame.HandshakeDone, ackEliciting: true);
                        return true;

                    case QuicFrame.KeyUpdate:
                    {
                        if (!TryVarInt(out var length) || length != 1 || !TryByte(out var requestUpdate))
                            return Fail();
                        Current = QuicFrameInfo.ForKeyUpdate(requestUpdate == 0);
                        return true;
                    }

                    case QuicFrame.ConnectionCloseTransport:
                    {
                        if (!TryVarInt(out var code) || !TryVarInt(out var frameType) || !TryVarInt(out var reasonLength) ||
                            !TryBytes((int)reasonLength, out var reason))
                            return Fail();
                        Current = QuicFrameInfo.ForConnectionClose(code, frameType, reason, transport: true);
                        return true;
                    }

                    case QuicFrame.ConnectionCloseApplication:
                    {
                        if (!TryVarInt(out var code) || !TryVarInt(out var reasonLength) || !TryBytes((int)reasonLength, out var reason))
                            return Fail();
                        Current = QuicFrameInfo.ForConnectionClose(code, 0, reason, transport: false);
                        return true;
                    }

                    default:
                        // Неизвестный тип: длину кадра вычислить нельзя, пакет неразобран.
                        return Fail();
                }
            }

            // STREAM: 0x08..0x0F
            {
                var fin = (type & QuicFrame.StreamFinBit) != 0;
                var hasOffset = (type & QuicFrame.StreamOffBit) != 0;
                var hasLength = (type & QuicFrame.StreamLenBit) != 0;

                if (!TryVarInt(out var streamId))
                    return Fail();

                // Смещение в потоке нужно получателю: по нему он отбрасывает уже
                // принятые байты при потерях, поэтому оно не может быть потеряно.
                var offset = 0UL;
                if (hasOffset && !TryVarInt(out offset))
                    return Fail();

                if (hasLength)
                {
                    if (!TryVarInt(out var length) || !TryBytes((int)length, out var data))
                        return Fail();
                    Current = QuicFrameInfo.ForStream(streamId, offset, fin, data);
                }
                else
                {
                    // Без бита LEN данные идут до конца полезной нагрузки пакета.
                    var data = _payload[_offset..];
                    _offset = _payload.Length;
                    Current = QuicFrameInfo.ForStream(streamId, offset, fin, data);
                }

                return true;
            }
        }

        return false;
    }

    private bool Fail()
    {
        Current = QuicFrameInfo.Invalid;
        return false;
    }

    private bool ReadAck()
    {
        if (!TryVarInt(out var largest) || !TryVarInt(out var delay) || !TryVarInt(out var rangeCount) ||
            !TryVarInt(out var firstRange))
            return Fail();

        // Ограничиваем число диапазонов: кадр ACK у настоящего клиента тоже короткий.
        if (rangeCount > 32)
            return Fail();

        var ranges = new List<(ulong, ulong)>((int)rangeCount);
        for (var i = 0UL; i < rangeCount; i++)
        {
            if (!TryVarInt(out var gap) || !TryVarInt(out var range))
                return Fail();
            ranges.Add((gap, range));
        }

        Current = QuicFrameInfo.ForAck(new QuicAck
        {
            LargestAcknowledged = largest,
            AckDelay = delay,
            RangeCount = rangeCount,
            FirstAckRange = firstRange,
            Ranges = ranges,
        });
        return true;
    }

    private bool TryVarInt(out ulong value)
    {
        if (!QuicVarInt.TryRead(_payload[_offset..], out value, out var size))
        {
            value = 0;
            return false;
        }

        return Advance(size);
    }

    private bool TryByte(out byte value)
    {
        if (_offset >= _payload.Length)
        {
            value = 0;
            return false;
        }

        value = _payload[_offset];
        return Advance(1);
    }

    private bool TryBytes(int count, out ReadOnlySpan<byte> data)
    {
        if (count < 0 || _offset + count > _payload.Length)
        {
            data = default;
            return false;
        }

        data = _payload.Slice(_offset, count);
        return Advance(count);
    }

    private bool Advance(int count)
    {
        _offset += count;
        return true;
    }
}

/// <summary>Описание одного кадра QUIC, полученного при разборе пакета.</summary>
public ref struct QuicFrameInfo
{
    public ulong Type;

    /// <summary>Побуждает ли кадр отправку подтверждения (влияет на учёт ACK).</summary>
    public bool AckEliciting;

    /// <summary>Число байт PADDING (для оценки заполненности пакета).</summary>
    public int PaddingLength;

    public ReadOnlySpan<byte> Data;
    public ulong Offset;
    public ulong StreamId;
    public bool Fin;

    public bool HasAck;
    public QuicAck Ack;

    public bool KeyUpdate;

    /// <summary>Просит ли отправитель KEY_UPDATE встречный ответ с новой фазой ключей.</summary>
    public bool KeyUpdateRequest;
    public bool PathChallenge;
    public bool PathResponse;
    public bool ConnectionClose;
    public ulong ErrorCode;

    /// <summary>Разобран ли кадр (false — полезная нагрузка не является корректной).</summary>
    public bool Valid;

    public static QuicFrameInfo Invalid => new() { Valid = false };

    public static QuicFrameInfo ForPadding(int length) => new() { Type = QuicFrame.Padding, PaddingLength = length, Valid = true };

    public static QuicFrameInfo ForSimple(ulong type, bool ackEliciting) => new() { Type = type, AckEliciting = ackEliciting, Valid = true };

    public static QuicFrameInfo ForCrypto(ulong offset, ReadOnlySpan<byte> data, bool ackEliciting) => new()
    {
        Type = QuicFrame.Crypto,
        Offset = offset,
        Data = data,
        AckEliciting = ackEliciting,
        Valid = true,
    };

    public static QuicFrameInfo ForStream(ulong streamId, ulong offset, bool fin, ReadOnlySpan<byte> data) => new()
    {
        Type = QuicFrame.StreamWithOffsetAndLength,
        StreamId = streamId,
        Offset = offset,
        Fin = fin,
        Data = data,
        AckEliciting = true,
        Valid = true,
    };

    public static QuicFrameInfo ForAck(QuicAck ack) => new() { Type = QuicFrame.Ack, HasAck = true, Ack = ack, Valid = true };

    public static QuicFrameInfo ForKeyUpdate(bool requestUpdate) => new()
    {
        Type = QuicFrame.KeyUpdate,
        KeyUpdate = true,
        KeyUpdateRequest = requestUpdate,
        AckEliciting = true,
        Valid = true,
    };

    public static QuicFrameInfo ForPathChallenge(ReadOnlySpan<byte> data) => new()
    {
        Type = QuicFrame.PathChallenge,
        Data = data,
        PathChallenge = true,
        AckEliciting = true,
        Valid = true,
    };

    public static QuicFrameInfo ForPathResponse(ReadOnlySpan<byte> data) => new()
    {
        Type = QuicFrame.PathResponse,
        Data = data,
        PathResponse = true,
        Valid = true,
    };

    public static QuicFrameInfo ForConnectionClose(ulong errorCode, ulong frameType, ReadOnlySpan<byte> reason, bool transport) => new()
    {
        Type = transport ? QuicFrame.ConnectionCloseTransport : QuicFrame.ConnectionCloseApplication,
        ErrorCode = errorCode,
        Data = reason,
        ConnectionClose = true,
        Valid = true,
    };
}
