using System.Buffers.Binary;

namespace Proxify.Common.Quic;

/// <summary>
/// Целые числа переменной длины QUIC (RFC 9000, раздел 16) и буфер записи кадра.
///
/// Переменная длина нужна для типов кадров, смещений потока, длин в кадрах
/// CRYPTO/STREAM/ACK и для поля Length длинного заголовка. Значение кодируется
/// 1, 2, 4 или 8 байтами в зависимости от величины; старшие биты первого байта
/// содержат длину кодирования (все остальные биты — значение).
///
/// Буфер записи растёт по мере добавления байтов и отдаётся копией в
/// <see cref="ToArray"/> — пакеты QUIC собираются целиком перед отправкой.
/// </summary>
public static class QuicVarInt
{
    /// <summary>Максимальное значение: 2^62-1.</summary>
    public const ulong MaxValue = (1UL << 62) - 1;

    /// <summary>Длина кодирования значения в байтах (1, 2, 4 или 8).</summary>
    public static int SizeOf(ulong value) => value switch
    {
        < 0x40 => 1,
        < 0x4000 => 2,
        < 0x4000_0000 => 4,
        _ => 8,
    };

    /// <summary>Пишет значение в начало буфера. Возвращает число записанных байтов.</summary>
    public static int Write(Span<byte> destination, ulong value)
    {
        var size = SizeOf(value);
        if (destination.Length < size)
            throw new ArgumentException("Буфер меньше длины переменного целого.", nameof(destination));
        if (value > MaxValue)
            throw new ArgumentOutOfRangeException(nameof(value), "Значение больше 2^62-1.");

        switch (size)
        {
            case 1:
                destination[0] = (byte)value;
                break;
            case 2:
                destination[0] = (byte)(0x40 | (value >> 8));
                destination[1] = (byte)value;
                break;
            case 4:
                destination[0] = (byte)(0x80 | (value >> 24));
                destination[1] = (byte)(value >> 16);
                destination[2] = (byte)(value >> 8);
                destination[3] = (byte)value;
                break;
            default:
                destination[0] = (byte)(0xC0 | (value >> 56));
                destination[1] = (byte)(value >> 48);
                destination[2] = (byte)(value >> 40);
                destination[3] = (byte)(value >> 32);
                destination[4] = (byte)(value >> 24);
                destination[5] = (byte)(value >> 16);
                destination[6] = (byte)(value >> 8);
                destination[7] = (byte)value;
                break;
        }

        return size;
    }

    /// <summary>
    /// Читает значение из начала буфера. Возвращает false, если данных не хватает
    /// или длина кодирования противоречива.
    /// </summary>
    public static bool TryRead(ReadOnlySpan<byte> source, out ulong value, out int consumed)
    {
        value = 0;
        consumed = 0;
        if (source.Length == 0)
            return false;

        var size = 1 << (source[0] >> 6);
        if (source.Length < size)
            return false;

        var result = (ulong)(source[0] & 0x3F);
        for (var i = 1; i < size; i++)
            result = (result << 8) | source[i];

        value = result;
        consumed = size;
        return true;
    }
}

/// <summary>
/// Буфер последовательной записи байтов и переменных целых: используется для
/// сборки полезной нагрузки пакетов QUIC (кадры ACK/STREAM/CRYPTO/PADDING).
/// </summary>
public sealed class QuicWriter
{
    private byte[] _buffer;
    private int _length;

    public QuicWriter(int capacity = 256)
    {
        _buffer = new byte[Math.Max(16, capacity)];
    }

    public int Length => _length;

    public void WriteByte(byte value)
    {
        EnsureCapacity(1);
        _buffer[_length++] = value;
    }

    public void WriteVarInt(ulong value)
    {
        var size = QuicVarInt.SizeOf(value);
        EnsureCapacity(size);
        QuicVarInt.Write(_buffer.AsSpan(_length), value);
        _length += size;
    }

    public void WriteBytes(ReadOnlySpan<byte> value)
    {
        EnsureCapacity(value.Length);
        value.CopyTo(_buffer.AsSpan(_length));
        _length += value.Length;
    }

    /// <summary>Дописывает N нулевых байт — так кодируется кадр PADDING в QUIC.</summary>
    public void WritePadding(int count)
    {
        if (count <= 0)
            return;
        EnsureCapacity(count);
        _buffer.AsSpan(_length, count).Clear();
        _length += count;
    }

    public byte[] ToArray()
    {
        var result = new byte[_length];
        Array.Copy(_buffer, 0, result, 0, _length);
        return result;
    }

    private void EnsureCapacity(int extra)
    {
        if (_length + extra <= _buffer.Length)
            return;

        var capacity = _buffer.Length;
        while (capacity < _length + extra)
            capacity *= 2;
        Array.Resize(ref _buffer, capacity);
    }
}
