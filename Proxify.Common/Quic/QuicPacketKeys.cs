using System.Security.Cryptography;
using System.Text;

namespace Proxify.Common.Quic;

/// <summary>
/// Ключевой материал пакетов QUIC (RFC 9001) и защита заголовков.
///
/// Ключи пакетов — это AES-128-GCM с ключом 16 байт, вектором инициализации
/// 12 байт и меткой 16 байт. Вектор выводится из номера пакета:
/// nonce = iv XOR (номер пакета, выровненный вправо до 12 байт) — так же, как в
/// настоящем QUIC, поэтому номера пакетов должны строго расти в пределах одной
/// фазы ключей (иначе повторится пара ключ/nonce).
///
/// Защита заголовка (раздел 5.4) маскирует младшие биты первого байта и байты
/// номера пакета: 4 бита у длинного заголовка и 5 бит у короткого. Маска берётся
/// из AES-ECB(ключ hp, 16 байт выборки с отступа pn_offset+4). Благодаря этому
/// наблюдатель не видит ни типа пакета, ни длины номера пакета в первом байте.
///
/// Два семейства ключей:
///  * уровня Initial/Handshake — выводятся из публичной соли версии 1 и DCID
///    (Initial) либо из общего секрета направления (Handshake). Наблюдатель их не
///    выведет, поэтому содержимое рукопожатия туннеля не раскрывается;
///  * уровень 1-RTT — выводится из сессионного ключа (ECDH), то есть уникален
///    для каждого рукопожатия: номера пакетов можно начинать заново без риска
///    повтора nonce.
/// </summary>
public sealed class QuicPacketKeys
{
    /// <summary>Метка аутентификации AES-GCM в QUIC (16 байт).</summary>
    public const int TagSize = 16;

    /// <summary>Соль Initial-пакетов QUIC версии 1 (RFC 9001, раздел 5.2).</summary>
    public static ReadOnlySpan<byte> InitialSaltV1 => new byte[]
    {
        0x38, 0x76, 0x2C, 0xF7, 0xF5, 0x59, 0x34, 0xB3,
        0x4D, 0x17, 0x9A, 0xE6, 0xA4, 0xC8, 0x0C, 0xAD,
        0xCC, 0xBB, 0x7F, 0x0A,
    };

    private readonly object _gate = new();
    private readonly byte[] _maskBlock = new byte[16];
    private ICryptoTransform? _hpEncryptor;

    private QuicPacketKeys(byte[] key, byte[] iv, byte[] hp)
    {
        Key = key;
        Iv = iv;
        Hp = hp;
    }

    /// <summary>Ключ шифрования полезной нагрузки (16 байт).</summary>
    public byte[] Key { get; }

    /// <summary>Вектор инициализации (12 байт).</summary>
    public byte[] Iv { get; }

    /// <summary>Ключ защиты заголовка (16 байт).</summary>
    public byte[] Hp { get; }

    /// <summary>
    /// Ключи уровня Initial: как в настоящем QUIC, из публичной соли версии 1 и
    /// DCID из заголовка пакета. Позволяет разобрать Initial любому наблюдателю —
    /// ровно как у настоящего соединения, — и одновременно позволяет обеим
    /// сторонам маскировки проверить подлинность пакета.
    /// </summary>
    public static QuicPacketKeys ForInitial(ReadOnlySpan<byte> dcid, bool isClient)
    {
        // HKDF-Extract(salt, DCID). HKDF.DeriveKey здесь неприменим: он всегда
        // выполняет и Extract, и Expand, а на уровне Initial нужен именно
        // промежуточный PRK из шага Extract.
        var initialSecret = Extract(InitialSaltV1, dcid);
        try
        {
            var secret = ExpandLabel(initialSecret, isClient ? "client in" : "server in", 32);
            try
            {
                return FromSecret(secret);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(initialSecret);
        }
    }

    /// <summary>Ключи из секрета уровня: quic key / quic iv / quic hp.</summary>
    public static QuicPacketKeys FromSecret(ReadOnlySpan<byte> secret)
    {
        var key = ExpandLabel(secret, "quic key", 16);
        var iv = ExpandLabel(secret, "quic iv", 12);
        var hp = ExpandLabel(secret, "quic hp", 16);
        return new QuicPacketKeys(key, iv, hp);
    }

    /// <summary>
    /// Ключи 1-RTT для фазы номер phase: секрет фазы выводится из базового
    /// секрета направления, поэтому смена фазы не требует согласования — получатель
    /// пробует текущую и предыдущую фазы.
    /// </summary>
    public static QuicPacketKeys ForPhase(ReadOnlySpan<byte> baseSecret, uint phase)
    {
        var info = Encoding.ASCII.GetBytes("pn=" + phase);
        var secret = HKDF.DeriveKey(HashAlgorithmName.SHA256, baseSecret.ToArray(), 32, salt: null, info);
        try
        {
            return FromSecret(secret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>Вектор инициализации конкретного пакета: iv XOR номер пакета.</summary>
    public byte[] MakeNonce(ulong packetNumber)
    {
        var nonce = (byte[])Iv.Clone();
        for (var i = 0; i < 8; i++)
            nonce[4 + i] ^= (byte)(packetNumber >> (8 * (7 - i)));
        return nonce;
    }

    /// <summary>
    /// Снимает защиту заголовка пакета (для приёма) либо применяет её (для отправки):
    /// операция симметрична. packetStart — начало пакета внутри буфера датаграммы
    /// (в coalesced-датаграмме не обязательно 0), pnOffset/pnLength — положение и
    /// длина номера пакета в том же буфере.
    /// </summary>
    public void ToggleHeaderProtection(byte[] packet, int packetStart, int pnOffset, int pnLength, bool isLongHeader)
    {
        ToggleFirstByte(packet, packetStart, pnOffset, isLongHeader);
        TogglePacketNumber(packet, pnOffset, pnLength);
    }

    /// <summary>
    /// Снимает (или накладывает) защиту младших битов первого байта. При приёме
    /// возвращает длину номера пакета, которая хранится в этих же, замаскированных
    /// битах (RFC 9001, раздел 5.4.2), — вызывающий код обязан размаскировать
    /// номер пакета сразу после этого.
    /// </summary>
    public int UnmaskFirstByte(byte[] packet, int packetStart, int pnOffset, bool isLongHeader)
    {
        var mask = HeaderMask(packet, pnOffset);
        packet[packetStart] ^= (byte)(mask[0] & (isLongHeader ? 0x0F : 0x1F));
        return (packet[packetStart] & 0x03) + 1;
    }

    /// <summary>Накладывает (снимает) защиту младших битов первого байта.</summary>
    public void ToggleFirstByte(byte[] packet, int packetStart, int pnOffset, bool isLongHeader)
    {
        var mask = HeaderMask(packet, pnOffset);
        packet[packetStart] ^= (byte)(mask[0] & (isLongHeader ? 0x0F : 0x1F));
    }

    /// <summary>Накладывает (снимает) защиту байтов номера пакета.</summary>
    public void TogglePacketNumber(byte[] packet, int pnOffset, int pnLength)
    {
        if (pnLength <= 0 || pnOffset < 0 || pnOffset + pnLength > packet.Length)
            return;

        var mask = _maskBlock;
        for (var i = 0; i < pnLength; i++)
            packet[pnOffset + i] ^= mask[1 + i];
    }

    /// <summary>
    /// Маска защиты заголовка: AES-ECB ключом hp по 16-байтной выборке, взятой с
    /// отступом 4 байта после начала номера пакета.
    /// </summary>
    private byte[] HeaderMask(byte[] packet, int pnOffset)
    {
        if (pnOffset < 0 || pnOffset + 4 + 16 > packet.Length)
            return ZeroMask;

        lock (_gate)
        {
            if (_hpEncryptor == null)
            {
                var aes = Aes.Create();
                aes.Key = (byte[])Hp.Clone();
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                _hpEncryptor = aes.CreateEncryptor();
            }

            var sample = new byte[16];
            Array.Copy(packet, pnOffset + 4, sample, 0, 16);
            _hpEncryptor.TransformBlock(sample, 0, 16, _maskBlock, 0);
            return _maskBlock;
        }
    }

    private static readonly byte[] ZeroMask = new byte[16];

    /// <summary>HKDF-Extract (RFC 5869): HMAC-SHA256 с солью в качестве ключа.</summary>
    public static byte[] Extract(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> inputKeyMaterial)
    {
        var key = salt.ToArray();
        var ikm = inputKeyMaterial.ToArray();
        try
        {
            using var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(ikm);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    /// <summary>HKDF-Expand-Label в виде TLS 1.3 (метка с префиксом "tls13 ").</summary>
    public static byte[] ExpandLabel(ReadOnlySpan<byte> secret, string label, int length)
    {
        var labelBytes = Encoding.ASCII.GetBytes("tls13 " + label);
        // struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
        var info = new byte[2 + 1 + labelBytes.Length + 1];
        info[0] = (byte)(length >> 8);
        info[1] = (byte)length;
        info[2] = (byte)labelBytes.Length;
        labelBytes.CopyTo(info, 3);

        return HkdfExpand(secret, info, length);
    }

    /// <summary>
    /// HKDF-Expand (RFC 5869) по уже извлечённому PRK. В .NET есть только
    /// <see cref="HKDF.DeriveKey"/>, который дополнительно выполняет Extract, поэтому
    /// Expand реализован здесь: для ключей QUIC критично, чтобы они считались
    /// ровно так же, как в настоящем стеке.
    /// </summary>
    public static byte[] HkdfExpand(ReadOnlySpan<byte> prk, ReadOnlySpan<byte> info, int length)
    {
        if (length <= 0)
            return Array.Empty<byte>();

        var result = new byte[length];
        var prkBytes = prk.ToArray();
        var block = Array.Empty<byte>();
        var offset = 0;
        var counter = 1;

        using var hmac = new HMACSHA256(prkBytes);
        while (offset < length)
        {
            var input = new byte[block.Length + info.Length + 1];
            Buffer.BlockCopy(block, 0, input, 0, block.Length);
            info.CopyTo(input.AsSpan(block.Length));
            input[^1] = (byte)counter;

            block = hmac.ComputeHash(input);
            var take = Math.Min(block.Length, length - offset);
            Buffer.BlockCopy(block, 0, result, offset, take);
            offset += take;
            counter++;
        }

        CryptographicOperations.ZeroMemory(prkBytes);
        return result;
    }
}
