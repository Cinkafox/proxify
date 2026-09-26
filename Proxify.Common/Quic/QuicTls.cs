using System.Security.Cryptography;
using System.Text;

namespace Proxify.Common.Quic;

/// <summary>
/// Сообщения TLS 1.3 внутри кадров CRYPTO первых пакетов QUIC: ClientHello, который
/// уходит в Initial-пакете клиента, и ServerHello в Initial-пакете сервера, плюс
/// параметры транспорта QUIC (расширение 0x39).
///
/// Зачем это нужно: наблюдатель ТСПУ, умеющий разбирать Initial-пакеты QUIC, выводит
/// их ключи из публичной соли версии 1 и видит открытый ClientHello — имя сервера
/// (SNI), набор шифров и параметры транспорта. Если вместо ClientHello в пакете
/// лежит мусор, такой анализатор получает «некорректное рукопожатие», и соединение
/// выглядит аномальным. Поэтому ClientHello собирается как настоящий: правильная
/// структура handshake-сообщения, версия 0x0303, случайные значения, key_share
/// X25519, ALPN h3, наборы групп и алгоритмов подписи, параметры транспорта и
/// паддинг до характерного размера.
///
/// Настоящего TLS-рукопожатия при этом не происходит: обмен ключами, сертификаты и
/// Finished не вычисляются, а на уровне Handshake передаётся закрытый кадр
/// рукопожатия туннеля. Для классификации трафика этого достаточно, а полезная
/// нагрузка остаётся неразбираемой для наблюдателя.
/// </summary>
public static class QuicTls
{
    /// <summary>Handshake-сообщение ClientHello.</summary>
    public const byte HandshakeClientHello = 0x01;

    /// <summary>Handshake-сообщение ServerHello.</summary>
    public const byte HandshakeServerHello = 0x02;

    /// <summary>Длина заголовка handshake-сообщения: тип и трёхбайтная длина тела.</summary>
    public const int HandshakeHeaderSize = 4;

    private const ushort LegacyVersion = 0x0303;
    private const byte LegacyVersionHigh = 0x03;
    private const byte LegacyVersionLow = 0x03;
    private const ushort Tls13 = 0x0304;
    private const ushort TlsAes128GcmSha256 = 0x1301;
    private const byte TlsAes128GcmSha256High = 0x13;
    private const byte TlsAes128GcmSha256Low = 0x01;
    private const byte Tls13High = 0x03;
    private const byte Tls13Low = 0x04;
    private const ushort ExtensionServerName = 0x0000;
    private const ushort ExtensionSupportedGroups = 0x000A;
    private const ushort ExtensionEcPointFormats = 0x000B;
    private const ushort ExtensionSignatureAlgorithms = 0x000D;
    private const ushort ExtensionAlpn = 0x0010;
    private const ushort ExtensionPadding = 0x0015;
    private const ushort ExtensionSupportedVersions = 0x002B;
    private const ushort ExtensionPskKeyExchangeModes = 0x002D;
    private const ushort ExtensionKeyShare = 0x0033;
    private const ushort ExtensionQuicTransportParameters = 0x0039;

    private const ushort GroupX25519 = 0x001D;
    private const ushort GroupSecp256r1 = 0x0017;
    private const ushort GroupSecp384r1 = 0x0018;

    /// <summary>
    /// Собирает ClientHello с набором расширений и параметрами транспорта.
    /// Возвращает байты потока CRYPTO, готовые к упаковке в кадр CRYPTO, и
    /// идентификатор сессии (его сервер обязан отразить в ServerHello).
    /// Тело дополняется расширением padding до размера <paramref name="targetLength"/>
    /// байт: настоящие клиенты так же выравнивают ClientHello, скрывая его размер.
    /// </summary>
    public static byte[] BuildClientHello(
        string serverName,
        int targetLength,
        byte[] transportParameters,
        out byte[] sessionId)
    {
        sessionId = RandomNumberGenerator.GetBytes(32);

        var fixedExtensions = new List<byte[]>
        {
            BuildGrease(),
            BuildServerName(serverName),
            BuildSupportedGroups(),
            BuildEcPointFormats(),
            BuildSignatureAlgorithms(),
            BuildAlpn(),
            BuildSupportedVersions(),
            BuildPskKeyExchangeModes(),
            BuildKeyShare(),
            BuildQuicTransportParametersExtension(transportParameters),
        };

        // Заголовок ClientHello: версия, random, session id, шифры, сжатие.
        var header = new QuicWriter(64);
        header.WriteByte(LegacyVersionHigh);
        header.WriteByte(LegacyVersionLow);
        header.WriteBytes(RandomNumberGenerator.GetBytes(32));
        header.WriteByte((byte)sessionId.Length);
        header.WriteBytes(sessionId);
        // Набор шифров: только три шифра TLS 1.3 — столько предлагают настоящие
        // клиенты QUIC, шифры TLS 1.2 в QUIC неприменимы.
        header.WriteByte(0x00);
        header.WriteByte(0x06);
        header.WriteByte(TlsAes128GcmSha256High);
        header.WriteByte(TlsAes128GcmSha256Low);
        header.WriteByte(0x13);
        header.WriteByte(0x02);
        header.WriteByte(0x13);
        header.WriteByte(0x03);
        // Методы сжатия: null.
        header.WriteByte(0x01);
        header.WriteByte(0x00);

        // Длина ClientHello (4 байта заголовка handshake-сообщения) складывается из
        // фиксированной части, поля длины массива расширений и самих расширений.
        const int extensionVectorOverhead = 2;
        const int paddingExtensionOverhead = 4;
        var paddingLength = targetLength - HandshakeHeaderSize - header.Length
                            - extensionVectorOverhead - Sum(fixedExtensions) - paddingExtensionOverhead;
        if (paddingLength > 0)
            fixedExtensions.Add(BuildPadding(paddingLength));

        var body = new QuicWriter(header.Length + extensionVectorOverhead + Sum(fixedExtensions) + 8);
        body.WriteBytes(header.ToArray());

        // Поле длины массива расширений идёт перед самими расширениями.
        var extensionsLength = Sum(fixedExtensions);
        body.WriteByte((byte)(extensionsLength >> 8));
        body.WriteByte((byte)extensionsLength);
        foreach (var extension in fixedExtensions)
            body.WriteBytes(extension);

        return WrapHandshake(HandshakeClientHello, body.ToArray());
    }

    /// <summary>
    /// Собирает ServerHello, отражающий session id и версию из ClientHello и несущий
    /// собственные параметры транспорта и открытый ключ key_share.
    /// </summary>
    public static byte[] BuildServerHello(ReadOnlySpan<byte> sessionId, byte[] transportParameters)
    {
        var body = new QuicWriter(256);
        body.WriteByte(LegacyVersionHigh);
        body.WriteByte(LegacyVersionLow);
        body.WriteBytes(RandomNumberGenerator.GetBytes(32));
        body.WriteByte((byte)sessionId.Length);
        body.WriteBytes(sessionId);
        body.WriteByte(TlsAes128GcmSha256High);
        body.WriteByte(TlsAes128GcmSha256Low);
        body.WriteByte(0x00); // legacy_compression_method

        var extensions = new QuicWriter(128);
        var supportedVersions = new QuicWriter(4);
        supportedVersions.WriteByte(Tls13High);
        supportedVersions.WriteByte(Tls13Low);
        AppendExtension(extensions, ExtensionSupportedVersions, supportedVersions.ToArray());

        var keyShare = new QuicWriter(40);
        keyShare.WriteByte((byte)(GroupSecp256r1 >> 8));
        keyShare.WriteByte((byte)GroupSecp256r1);
        keyShare.WriteByte(32);
        keyShare.WriteBytes(CreateP256PublicKey());
        AppendExtension(extensions, ExtensionKeyShare, keyShare.ToArray());

        AppendExtension(extensions, ExtensionQuicTransportParameters, transportParameters);

        body.WriteByte((byte)(extensions.Length >> 8));
        body.WriteByte((byte)extensions.Length);
        body.WriteBytes(extensions.ToArray());

        return WrapHandshake(HandshakeServerHello, body.ToArray());
    }

    /// <summary>
    /// Собирает параметры транспорта QUIC. Сервер обязан отразить исходный
    /// идентификатор соединения и свой собственный, клиент — только свой.
    /// </summary>
    public static byte[] BuildTransportParameters(
        ReadOnlySpan<byte> originalDcid,
        ReadOnlySpan<byte> initialSourceDcid,
        bool isServer)
    {
        var writer = new QuicWriter(128);

        if (isServer)
            AppendParameter(writer, 0x00, originalDcid.ToArray()); // original_destination_connection_id
        AppendParameter(writer, 0x01, new byte[] { 0x00, 0x00, 0x75, 0x30 }); // max_idle_timeout = 30000 мс
        AppendParameter(writer, 0x03, new byte[] { 0x05, 0xAA }); // max_udp_payload_size = 1450
        AppendParameter(writer, 0x04, EncodeVarInt(1 << 20)); // initial_max_data
        AppendParameter(writer, 0x05, EncodeVarInt(1 << 18)); // initial_max_stream_data_bidi_local
        AppendParameter(writer, 0x06, EncodeVarInt(1 << 18)); // initial_max_stream_data_bidi_remote
        AppendParameter(writer, 0x07, EncodeVarInt(1 << 18)); // initial_max_stream_data_uni
        AppendParameter(writer, 0x08, EncodeVarInt(64)); // initial_max_streams_bidi
        AppendParameter(writer, 0x09, EncodeVarInt(64)); // initial_max_streams_uni
        AppendParameter(writer, 0x0A, new byte[] { 0x03 }); // ack_delay_exponent = 3
        AppendParameter(writer, 0x0B, new byte[] { 0x19 }); // max_ack_delay = 25 мс
        AppendParameter(writer, 0x0E, new byte[] { 0x04 }); // active_connection_id_limit = 4
        AppendParameter(writer, 0x0F, initialSourceDcid.ToArray()); // initial_source_connection_id

        return writer.ToArray();
    }

    /// <summary>
    /// Разбирает начало ClientHello: возвращает длину сообщения handshake и
    /// session id, чтобы сервер мог отразить его в ServerHello и продолжить
    /// смещение криптографического потока с правильного места.
    /// </summary>
    public static bool TryReadClientHello(ReadOnlySpan<byte> cryptoStream, out byte[] sessionId, out int messageLength)
    {
        sessionId = Array.Empty<byte>();
        messageLength = 0;

        // Поток CRYPTO — это сообщения handshake: тип (1 байт) + длина (3 байта) +
        // тело. Тело ClientHello начинается сразу после заголовка сообщения.
        if (cryptoStream.Length < HandshakeHeaderSize + 41 || cryptoStream[0] != HandshakeClientHello)
            return false;

        var helloLength = ReadUInt24(cryptoStream.Slice(1));
        messageLength = HandshakeHeaderSize + helloLength;
        if (helloLength < 41 || cryptoStream.Length < HandshakeHeaderSize + helloLength)
            return false;

        // Пропускаем legacy_version (2) и random (32).
        var offset = HandshakeHeaderSize + 2 + 32;
        if (offset >= cryptoStream.Length)
            return false;

        var sessionIdLength = cryptoStream[offset];
        offset++;
        if (sessionIdLength > 32 || cryptoStream.Length < offset + sessionIdLength)
            return false;

        sessionId = cryptoStream.Slice(offset, sessionIdLength).ToArray();
        return true;
    }

    private static byte[] WrapHandshake(byte type, byte[] body)
    {
        var writer = new QuicWriter(body.Length + 8);
        writer.WriteByte(type);
        writer.WriteByte((byte)(body.Length >> 16));
        writer.WriteByte((byte)(body.Length >> 8));
        writer.WriteByte((byte)body.Length);
        writer.WriteBytes(body);
        return writer.ToArray();
    }

    private static byte[] BuildServerName(string serverName)
    {
        var host = Encoding.ASCII.GetBytes(serverName);
        var name = new QuicWriter(host.Length + 8);
        name.WriteByte(0x00); // host_name
        name.WriteByte((byte)(host.Length >> 8));
        name.WriteByte((byte)host.Length);
        name.WriteBytes(host);

        var list = new QuicWriter(name.Length + 4);
        list.WriteByte((byte)(name.Length >> 8));
        list.WriteByte((byte)name.Length);
        list.WriteBytes(name.ToArray());

        return WithExtensionHeader(ExtensionServerName, list.ToArray());
    }

    private static byte[] BuildSupportedGroups()
    {
        var writer = new QuicWriter(16);
        writer.WriteByte(0x00);
        writer.WriteByte(0x08);
        writer.WriteByte((byte)(GroupX25519 >> 8));
        writer.WriteByte((byte)GroupX25519);
        writer.WriteByte((byte)(GroupSecp256r1 >> 8));
        writer.WriteByte((byte)GroupSecp256r1);
        writer.WriteByte((byte)(GroupSecp384r1 >> 8));
        writer.WriteByte((byte)GroupSecp384r1);
        return WithExtensionHeader(ExtensionSupportedGroups, writer.ToArray());
    }

    private static byte[] BuildEcPointFormats()
    {
        var writer = new QuicWriter(4);
        writer.WriteByte(0x01);
        writer.WriteByte(0x00);
        return WithExtensionHeader(ExtensionEcPointFormats, writer.ToArray());
    }

    private static byte[] BuildSignatureAlgorithms()
    {
        var writer = new QuicWriter(24);
        writer.WriteByte(0x00);
        writer.WriteByte(0x0A);
        foreach (var value in new ushort[] { 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201, 0x0203 })
        {
            writer.WriteByte((byte)(value >> 8));
            writer.WriteByte((byte)value);
        }
        return WithExtensionHeader(ExtensionSignatureAlgorithms, writer.ToArray());
    }

    private static byte[] BuildAlpn()
    {
        // ALPN: "h3" — так объявляет транспорт QUIC поверх HTTP/3.
        // ProtocolNameList = opaque<2..255> из ProtocolName, а ProtocolName =
        // opaque name<1..255>, то есть длина списка 3, затем длина имени 2.
        var writer = new QuicWriter(8);
        writer.WriteByte(0x00);
        writer.WriteByte(0x03);
        writer.WriteByte(0x02);
        writer.WriteByte((byte)'h');
        writer.WriteByte((byte)'3');
        return WithExtensionHeader(ExtensionAlpn, writer.ToArray());
    }

    private static byte[] BuildSupportedVersions()
    {
        // В ClientHello extension_data — это SelectorList, то есть список с
        // однобайтовой длиной: длина 2, затем версия TLS 1.3 (0x0304).
        var writer = new QuicWriter(8);
        writer.WriteByte(0x02);
        writer.WriteByte(Tls13High);
        writer.WriteByte(Tls13Low);
        return WithExtensionHeader(ExtensionSupportedVersions, writer.ToArray());
    }

    private static byte[] BuildPskKeyExchangeModes()
    {
        var writer = new QuicWriter(4);
        writer.WriteByte(0x01);
        writer.WriteByte(0x01); // psk_dhe_ke
        return WithExtensionHeader(ExtensionPskKeyExchangeModes, writer.ToArray());
    }

    /// <summary>
    /// Расширение с key_share: пара — группа и 32-байтный открытый ключ. Открытый
    /// ключ настоящий (выведен из свежей эфемерной пары), поэтому разборщик,
    /// который попытается его декодировать, получит корректную точку кривой.
    /// Вычислять общий секрет при этом не нужно — рукопожатие не продолжается.
    ///
    /// Используется secp256r1, а не x25519: последний недоступен .NET на некоторых
    /// платформах (в том числе на OpenSSL в Linux), а набор групп в ClientHello
    /// secp256r1 входит наравне с x25519.
    /// </summary>
    public static byte[] BuildKeyShare()
    {
        var share = CreateP256PublicKey();
        var writer = new QuicWriter(48);
        // KeyShareClientHello: client_shares — список с однобайтовой длиной, затем
        // запись KeyShare: группа (2 байта) + key_exchange_length (2 байта) + ключ.
        // Длина списка не включает саму себя: 2 + 2 + 32 = 36, всего 37 байт.
        writer.WriteByte(0x24);
        writer.WriteByte((byte)(GroupSecp256r1 >> 8));
        writer.WriteByte((byte)(GroupSecp256r1 & 0xFF));
        writer.WriteByte(0x00);
        writer.WriteByte(0x20);
        writer.WriteBytes(share);
        return WithExtensionHeader(ExtensionKeyShare, writer.ToArray());
    }

    private static byte[] CreateP256PublicKey()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        return ecdh.ExportParameters(false).Q.X!;
    }

    private static byte[] BuildGrease()
    {
        // GREASE-расширение: настоящие клиенты всегда отправляют хотя бы одно
        // значение из зарезервированного набора, чтобы усложнять снятие отпечатка.
        var value = RandomNumberGenerator.GetBytes(2);
        value[0] = (byte)(value[0] | 0x0A);
        value[1] = (byte)(value[1] | 0x0A);
        return WithExtensionHeader((ushort)((value[0] << 8) | value[1]), new byte[] { 0x00 });
    }

    /// <summary>
    /// Расширение padding: value — ровно <paramref name="dataLength"/> нулевых байт.
    /// Настоящие клиенты добивают им ClientHello, поэтому размер рукопожатия
    /// выглядит правдоподобно, а длина пакета Initial не выдаёт объём Auth.
    /// </summary>
    private static byte[] BuildPadding(int dataLength)
    {
        var writer = new QuicWriter(dataLength + 4);
        writer.WritePadding(dataLength);
        return WithExtensionHeader(ExtensionPadding, writer.ToArray());
    }

    private static byte[] BuildQuicTransportParametersExtension(byte[] parameters) =>
        WithExtensionHeader(ExtensionQuicTransportParameters, parameters);

    private static byte[] WithExtensionHeader(ushort type, byte[] data)
    {
        var writer = new QuicWriter(data.Length + 4);
        AppendExtension(writer, type, data);
        return writer.ToArray();
    }

    private static void AppendExtension(QuicWriter writer, ushort type, byte[] data)
    {
        writer.WriteByte((byte)(type >> 8));
        writer.WriteByte((byte)type);
        writer.WriteByte((byte)(data.Length >> 8));
        writer.WriteByte((byte)data.Length);
        writer.WriteBytes(data);
    }

    private static void AppendParameter(QuicWriter writer, ulong id, byte[] value)
    {
        writer.WriteVarInt(id);
        writer.WriteVarInt((ulong)value.Length);
        writer.WriteBytes(value);
    }

    private static byte[] EncodeVarInt(ulong value)
    {
        var writer = new QuicWriter(8);
        writer.WriteVarInt(value);
        return writer.ToArray();
    }

    private static int Sum(List<byte[]> parts)
    {
        var total = 0;
        foreach (var part in parts)
            total += part.Length;
        return total;
    }

    private static int ReadUInt24(ReadOnlySpan<byte> source) => (source[0] << 16) | (source[1] << 8) | source[2];
}
