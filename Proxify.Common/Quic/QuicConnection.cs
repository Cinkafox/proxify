using System.Security.Cryptography;
using System.Text;
using Proxify.Common.Crypto;

namespace Proxify.Common.Quic;

/// <summary>Роль кадра туннеля при отправке — влияет на форму пакета QUIC.</summary>
public enum WireFrameRole
{
    /// <summary>Обычные данные потока.</summary>
    Data,

    /// <summary>Служебный кадр поддержания соединения (пинг).</summary>
    Keepalive,

    /// <summary>Кадр при штатном закрытии туннеля (сопровождается CONNECTION_CLOSE).</summary>
    Close,

    /// <summary>Кадр рукопожатия: уходит в первом обмене, а не в потоке 1-RTT.</summary>
    Handshake,
}

/// <summary>Что оказалось в принятой датаграмме.</summary>
public enum QuicPacketOutcome
{
    /// <summary>Датаграмма не наша (чужая, искажённая или от другой версии маскировки).</summary>
    Unknown,

    /// <summary>Пакет наш, но кадра туннеля в нём нет: ACK, CRYPTO, PADDING.</summary>
    Handshake,

    /// <summary>Пакет наш и содержит кадр туннеля.</summary>
    Tunnel,

    /// <summary>Закрытие соединения: получен CONNECTION_CLOSE.</summary>
    Closed,
}

/// <summary>Пространства номеров пакетов QUIC (RFC 9000, раздел 12.3).</summary>
public enum QuicPacketNumberSpace
{
    Initial,
    Handshake,
    Application,
}

/// <summary>
/// Состояние маскировки туннеля под вид соединения QUIC.
///
/// На проводе вместо «случайных байт» идут пакеты настоящего QUIC v1 поверх UDP:
///
///  * первый обмен — как у клиента: Initial-пакет с настоящим ClientHello
///    (длина датаграммы не меньше 1200 байт, как требует RFC), затем пакет
///    уровня Handshake. Ключи Initial выводятся из публичной соли версии 1 и
///    DCID, то есть наблюдатель может их вычислить и увидеть корректное
///    рукопожатие — ровно как у настоящего клиента;
///  * ключи уровня Handshake общие, но выведены из зарегистрированного ключа
///    клиента: кадр рукопожатия туннеля (Auth/AuthAck) лежит в кадре CRYPTO
///    и наблюдателю недоступен;
///  * весь последующий обмен идёт пакетами 1-RTT с кадрами STREAM, ACK, PING,
///    MAX_DATA и паддингом. Ключи 1-RTT выводятся из сессионного ключа ECDH,
///    то есть уникальны для каждого рукопожатия;
///  * в одну датаграмму объединяются пакеты (coalescing), подтверждения
///    добавляются в каждый второй пакет, размеры датаграмм выбираются из
///    правдоподобного набора, а номера пакетов и фазы ключей меняются так же,
///    как в настоящем соединении.
///
/// Содержимое кадров туннеля шифруется дополнительно сессионным шифром
/// (TunnelCipher), поэтому даже при наличии wire-ключа полезная нагрузка остаётся
/// защищённой.
///
/// Все операции выполняются под внутренним замком, поэтому экземпляр можно
/// использовать из нескольких потоков.
/// </summary>
public sealed class QuicConnection
{
    /// <summary>Длина идентификатора соединения (для короткого заголовка она фиксирована).</summary>
    public const int CidLength = 8;

    /// <summary>Номер пакета в потоке, на который клиент инициирует первый поток.</summary>
    private const ulong TunnelStreamId = 0;

    /// <summary>
    /// Имя сервера по умолчанию для SNI в ClientHello режима quic. Рукопожатие
    /// на этом не останавливается, но настоящий клиент без SNI не ходит, поэтому
    /// подставляется правдоподобное имя, а настоящее задаётся настройкой.
    /// </summary>
    public const string DefaultServerName = "www.cloudflare.com";

    /// <summary>
    /// Наибольший кадр туннеля, который помещается в одну датаграмму без
    /// фрагментации IP. Кадр игры длиннее этого уйдёт в датаграмму больше
    /// 1452 байт и будет разбит на IP-фрагменты — работать будет, но такой
    /// пакет уже не похож на обычный QUIC.
    /// </summary>
    public const int MaxTunnelFrame = QuicPacket.MaxDatagram - 64;

    /// <summary>Сколько эпох рукопожатия перебирается при поиске незнакомого CID.</summary>
    private const int MaxEpochScan = 24;
    /// <summary>Сколько пакетов отправляется до смены фазы ключей (KEY_UPDATE).</summary>
    private const ulong PacketsPerPhase = 4096;

    private const double AckCoalesceProbability = 0.65;
    private const double DataPaddingProbability = 0.35;
    private const double PingProbability = 0.03;
    private const double ControlProbability = 0.05;

    /// <summary>Служебные кадры, которые ходят между деловыми пакетами.</summary>
    private const int ExtraNone = 0;
    private const int ExtraMaxData = 1;
    private const int ExtraMaxStreams = 2;
    private const int ExtraPing = 3;

    private static readonly TimeSpan AckDelay = TimeSpan.FromMilliseconds(25);

    /// <summary>Правдоподобные размеры датаграмм с данными (как у заполняющего путь клиента).</summary>
    private static readonly int[] RealisticDatagramSizes = { 512, 640, 768, 896, 1024, 1152, 1200, 1280, 1350, 1400 };

    /// <summary>Размеры первого пакета Initial: 1200 байт — минимум по RFC.</summary>
    private static readonly int[] InitialDatagramSizes = { 1200, 1216, 1232, 1248, 1264, 1280 };

    /// <summary>Размеры ClientHello: настоящие клиенты выравнивают его расширением padding.</summary>
    private static readonly int[] ClientHelloSizes = { 480, 496, 512, 528, 544, 560 };

    private readonly bool _isClient;
    private readonly string _serverName;

    private readonly byte[] _c2sSecret;
    private readonly byte[] _s2cSecret;

    private readonly Dictionary<int, (byte[] Server, byte[] Client)> _cids = new();
    private readonly object _cidGate = new();

    private readonly object _gate = new();

    private readonly QuicAckState _txAcksInitial = new();
    private readonly QuicAckState _txAcksHandshake = new();
    private readonly QuicAckState _txAcksApp = new();

    private readonly QuicAckState _rxAcksInitial = new();
    private readonly QuicAckState _rxAcksHandshake = new();
    private readonly QuicAckState _rxAcksApp = new();

    private byte[]? _appSecretTx;
    private byte[]? _appSecretRx;

    private QuicPacketKeys? _initialTxKeys;
    private QuicPacketKeys? _initialRxKeys;
    private QuicPacketKeys? _handshakeTxKeys;
    private QuicPacketKeys? _handshakeRxKeys;
    private QuicPacketKeys? _txKeys;

    private int _epoch;
    private int _flights;
    private uint _txPhase;
    private uint _rxPhase;
    private bool _rxKeyUpdateRequest;

    private ulong _txInitialPn;
    private ulong _txHandshakePn;
    private ulong _txAppPn;
    private ulong _txCryptoOffset;
    private ulong _txStreamOffset;

    private long _rxLargestInitialPn = -1;
    private long _rxLargestHandshakePn = -1;
    private long _rxLargestAppPn = -1;

    private ulong _rxStreamEnd;
    private ulong _peerCryptoEnd;
    private byte[] _peerSessionId = Array.Empty<byte>();

    private bool _handshakeDoneSent;
    private bool _closed;

    private QuicConnection(byte[] c2sSecret, byte[] s2cSecret, bool isClient, string serverName)
    {
        _c2sSecret = c2sSecret;
        _s2cSecret = s2cSecret;
        _isClient = isClient;
        _serverName = serverName;
    }

    /// <summary>
    /// Создаёт состояние соединения из зарегистрированной пары ключей клиента.
    /// Идентификаторы соединения и секреты уровня Handshake выводятся из этой
    /// пары, поэтому обе стороны получают одинаковые значения, а посторонний их
    /// вычислить не может.
    /// </summary>
    public static QuicConnection Create(ECDsa identityKey, bool isClient, string serverName)
    {
        var spki = TunnelKeys.ExportSpkiDer(identityKey);
        return new QuicConnection(
            TunnelKeys.DeriveQuicSecret(spki, TunnelKeys.QuicInfoClientToServer),
            TunnelKeys.DeriveQuicSecret(spki, TunnelKeys.QuicInfoServerToClient),
            isClient,
            serverName);
    }

    /// <summary>Номер текущего рукопожатия: каждое новое меняет идентификаторы соединения.</summary>
    public int Epoch => _epoch;

    /// <summary>true для прокси-клиента (машина B), false для прокси-сервера.</summary>
    public bool IsClient => _isClient;

    /// <summary>
    /// Устанавливает ключи 1-RTT. Вызывается сразу после вывода сессионного ключа
    /// ECDH: с этого момента обычные кадры туннеля идут в пакетах 1-RTT. Состояние
    /// отправки и приёма сбрасывается, так как ключи новые и номера пакетов можно
    /// начинать заново без риска повтора nonce.
    /// </summary>
    public void AttachSessionKey(byte[] sessionKey)
    {
        if (sessionKey.Length != TunnelKeys.SessionKeySize)
            throw new ArgumentException($"Сессионный ключ должен быть {TunnelKeys.SessionKeySize} байт.", nameof(sessionKey));

        lock (_gate)
        {
            _appSecretTx = DeriveAppSecret(sessionKey, _isClient ? "c2s" : "s2c");
            _appSecretRx = DeriveAppSecret(sessionKey, _isClient ? "s2c" : "c2s");

            _txKeys = null;
            _txPhase = 0;
            _rxPhase = 0;
            _rxKeyUpdateRequest = false;
            _txAppPn = 0;
            _rxLargestAppPn = -1;
            _txStreamOffset = 0;
            _rxStreamEnd = 0;
            _handshakeDoneSent = false;
            _txAcksApp.Reset();
            _rxAcksApp.Reset();
        }
    }

    /// <summary>
    /// Первый обмен клиента: два пакета в двух датаграммах. Первый — Initial с
    /// настоящим ClientHello, растянутый до 1200+ байт; второй — пакет уровня
    /// Handshake с кадром Auth туннеля внутри кадра CRYPTO. Именно так выглядит
    /// начало соединения QUIC со стороны клиента.
    /// </summary>
    public byte[][] BuildClientFlight(byte[] handshakeFrame)
    {
        lock (_gate)
        {
            _closed = false;
            _epoch = _flights++;
            ResetHandshakeSpace();
            ResetHandshakeReceiveState();

            // Initial: ClientHello в кадре CRYPTO + паддинг до 1200 байт.
            var target = PickInitialSize();
            var transportParameters = QuicTls.BuildTransportParameters(default, LocalCid(_epoch), isServer: false);
            var helloSize = ClientHelloSizes[Random.Shared.Next(ClientHelloSizes.Length)];
            var clientHello = QuicTls.BuildClientHello(_serverName, helloSize, transportParameters, out _);
            var clientHelloLength = (ulong)clientHello.Length;

            var initialFrames = new QuicWriter(target + 16);
            QuicFrame.WriteCrypto(initialFrames, 0, clientHello);
            PadLongPacket(initialFrames, target, QuicLongPacketType.Initial, packetNumberLength: 1);

            var initial = QuicPacket.BuildLong(
                QuicLongPacketType.Initial,
                RemoteCid(_epoch),
                LocalCid(_epoch),
                Array.Empty<byte>(),
                _txInitialPn++,
                1,
                InitialTxKeys(),
                initialFrames.ToArray());

            // Handshake: кадр Auth в кадре CRYPTO со смещением, равным длине
            // ClientHello (поток CRYPTO общий для всех уровней), плюс небольшой
            // паддинг: у настоящего клиента такой пакет тоже небольшой.
            var handshakeFrames = new QuicWriter(handshakeFrame.Length + 128);
            QuicFrame.WriteCrypto(handshakeFrames, clientHelloLength, handshakeFrame);
            handshakeFrames.WritePadding(Random.Shared.Next(0, 48));

            var handshake = QuicPacket.BuildLong(
                QuicLongPacketType.Handshake,
                RemoteCid(_epoch),
                LocalCid(_epoch),
                Array.Empty<byte>(),
                _txHandshakePn++,
                1,
                HandshakeTxKeys(),
                handshakeFrames.ToArray());

            return new[] { initial, handshake };
        }
    }

    /// <summary>
    /// Тот же первый обмен клиента, но одной даграммой: пакет Initial с ClientHello и
    /// пакет Handshake с кадром рукопожатия объединяются (coalescing) — так клиент
    /// отправляет рукопожатие одной датаграммой, и длина Initial в ней остаётся
    /// не меньше 1200 байт, как того требует RFC 9000.
    /// </summary>
    public byte[] BuildClientHandshakeDatagram(byte[] handshakeFrame)
    {
        var flight = BuildClientFlight(handshakeFrame);
        return Concat(flight[0], flight[1]);
    }

    /// <summary>
    /// Первый обмен сервера: пакет Initial с ServerHello и пакет Handshake с
    /// кадром AuthAck, объединённые в одну датаграмму (coalescing) и растянутые до
    /// 1200 байт — так отвечает настоящий сервер. Заодно сервер подтверждает
    /// Initial и Handshake клиента, как это делает QUIC.
    /// </summary>
    public byte[] BuildServerFlight(byte[] handshakeFrame)
    {
        lock (_gate)
        {
            _closed = false;

            var sessionId = _peerSessionId.Length == 0
                ? RandomNumberGenerator.GetBytes(32)
                : _peerSessionId;

            // Сервер обязан отразить original_destination_connection_id — тот самый
            // DCID, который клиент выбрал для своего первого пакета, то есть
            // собственный идентификатор сервера, а также исходный SCID клиента.
            var transportParameters = QuicTls.BuildTransportParameters(LocalCid(_epoch), RemoteCid(_epoch), isServer: true);
            var serverHello = QuicTls.BuildServerHello(sessionId, transportParameters);

            var initialFrames = new QuicWriter(1600);
            QuicFrame.WriteCrypto(initialFrames, 0, serverHello);
            _txAcksInitial.TryWriteAck(initialFrames, AckDelay);

            // Handshake продолжает поток CRYPTO после сообщений клиента.
            var handshakeFrames = new QuicWriter(1600);
            QuicFrame.WriteCrypto(handshakeFrames, _peerCryptoEnd, handshakeFrame);
            _txAcksHandshake.TryWriteAck(handshakeFrames, AckDelay);

            // До минимальных 1200 байт растягивается вся датаграмма, то есть хвост
            // пакета Handshake.
            var target = PickInitialSize();
            var padding = target -
                          QuicPacket.LongPacketLength(QuicLongPacketType.Initial, CidLength, CidLength, 0, 1, initialFrames.Length) -
                          QuicPacket.LongPacketLength(QuicLongPacketType.Handshake, CidLength, CidLength, 0, 1, handshakeFrames.Length);
            handshakeFrames.WritePadding(Math.Max(0, padding));

            var initial = QuicPacket.BuildLong(
                QuicLongPacketType.Initial,
                RemoteCid(_epoch),
                LocalCid(_epoch),
                Array.Empty<byte>(),
                _txInitialPn++,
                1,
                InitialTxKeys(),
                initialFrames.ToArray());

            var handshake = QuicPacket.BuildLong(
                QuicLongPacketType.Handshake,
                RemoteCid(_epoch),
                LocalCid(_epoch),
                Array.Empty<byte>(),
                _txHandshakePn++,
                1,
                HandshakeTxKeys(),
                handshakeFrames.ToArray());

            return Concat(initial, handshake);
        }
    }

    /// <summary>
    /// Заворачивает кадр туннеля в датаграмму QUIC: пакет 1-RTT с кадром STREAM,
    /// при необходимости объединённый с пакетами-подтверждениями уровней
    /// Initial/Handshake и дополненный служебными кадрами.
    /// </summary>
    public byte[] Wrap(byte[] frame, WireFrameRole role = WireFrameRole.Data)
    {        lock (_gate)
        {
            // Подтверждения пакетов уровней Initial/Handshake нельзя нести в пакете
            // 1-RTT: у него другое пространство номеров. Настоящий клиент отправляет
            // их отдельными пакетами, объединёнными в одну датаграмму с деловым.
            var prefix = BuildHandshakeAckDatagram();

            if (_appSecretTx == null)
            {
                // Ключи 1-RTT ещё не установлены (рукопожатие не завершено) —
                // кадр уходит на уровне Handshake внутри CRYPTO.
                var handshakeLevel = WrapHandshakeLevel(frame);
                return prefix == null ? handshakeLevel : Concat(prefix, handshakeLevel);
            }

            var packet = WrapApplicationFrame(frame, role);
            return prefix == null ? packet : Concat(prefix, packet);
        }
    }

    /// <summary>
    /// Разбирает датаграмму: перебирает объединённые пакеты, проверяет
    /// принадлежность по идентификатору соединения, снимает защиту заголовка,
    /// расшифровывает и возвращает первый найденный кадр туннеля. Служебные пакеты
    /// (ACK, PING, CRYPTO) не считаются ошибкой — они дают
    /// <see cref="QuicPacketOutcome.Handshake"/>.
    /// </summary>
    public QuicPacketOutcome TryUnwrap(byte[] datagram, int length, out byte[] frame)
    {
        frame = Array.Empty<byte>();
        var outcome = QuicPacketOutcome.Unknown;

        if (length <= 0 || length > datagram.Length)
            return outcome;

        lock (_gate)
        {
            var offset = 0;
            while (offset < length)
            {
                var remaining = length - offset;

                if ((datagram[offset] & QuicPacket.HeaderFormLong) != 0)
                {
                    if (!QuicPacket.TryParseLongHeader(datagram, offset, remaining, out var header))
                        break;

                    // Чужая версия или повторная попытка: рукопожатие не продолжаем.
                    if (header.Version != QuicPacket.Version1 || header.Type == QuicLongPacketType.Retry)
                        break;

                    if (!TryMatchPeerCid(header.Dcid, out var epoch) || !AdoptPeerEpoch(epoch))
                        break;

                    var isInitial = header.Type == QuicLongPacketType.Initial;
                    var space = isInitial ? QuicPacketNumberSpace.Initial : QuicPacketNumberSpace.Handshake;
                    var keys = isInitial ? InitialRxKeys() : HandshakeRxKeys();

                    if (!TryOpenAndHandle(datagram, header.Offset, header.PacketLength - header.Offset,
                            header.PacketNumberOffset, isLongHeader: true,
                            keys, space, out var opened))
                        break;

                    outcome = Merge(outcome, opened.Outcome);
                    if (opened.Frame.Length > 0)
                        frame = opened.Frame;

                    // Длинный заголовок содержит длину пакета, поэтому в датаграмме
                    // могут быть и другие пакеты.
                    offset = header.PacketLength;
                    continue;
                }

                if (!QuicPacket.TryParseShortHeader(datagram, offset, remaining, CidLength, out var pnOffset))
                    break;
                if (_appSecretRx == null)
                    break;
                if (!TryMatchPeerCid(datagram.AsSpan(offset + 1, CidLength), out var shortEpoch) || !AdoptPeerEpoch(shortEpoch))
                    break;
                if (!TryOpenApplication(datagram, offset, remaining, pnOffset, out var openedShort))
                    break;

                outcome = Merge(outcome, openedShort.Outcome);
                if (openedShort.Frame.Length > 0)
                    frame = openedShort.Frame;

                // У короткого заголовка нет поля длины: такой пакет всегда последний.
                break;
            }
        }

        return outcome;
    }

    // --- Приём ---

    /// <summary>
    /// Пробует расшифровать пакет 1-RTT: у него нет идентификатора рукопожатия, но
    /// фаза ключей может отличаться от ожидаемой (получатель ещё не увидел
    /// KEY_UPDATE), поэтому проверяются обе фазы.
    /// </summary>
    private bool TryOpenApplication(
        byte[] datagram,
        int packetOffset,
        int packetLength,
        int packetNumberOffset,
        out Opened opened)
    {
        opened = default;

        foreach (var keys in RxKeyCandidates())
        {
            if (QuicPacket.TryOpen(
                    datagram, packetOffset, packetLength, packetNumberOffset,
                    isLongHeader: false, keys, _rxLargestAppPn, out var packetNumber, out var payload))
            {
                return HandlePayload(payload, packetNumber, QuicPacketNumberSpace.Application, out opened);
            }
        }

        return false;
    }

    private bool TryOpenAndHandle(
        byte[] datagram,
        int packetOffset,
        int packetLength,
        int packetNumberOffset,
        bool isLongHeader,
        QuicPacketKeys keys,
        QuicPacketNumberSpace space,
        out Opened opened)
    {
        opened = default;

        var expected = space switch
        {
            QuicPacketNumberSpace.Initial => _rxLargestInitialPn,
            QuicPacketNumberSpace.Handshake => _rxLargestHandshakePn,
            _ => _rxLargestAppPn,
        };

        if (!QuicPacket.TryOpen(
                datagram, packetOffset, packetLength, packetNumberOffset,
                isLongHeader, keys, expected, out var packetNumber, out var payload))
            return false;

        return HandlePayload(payload, packetNumber, space, out opened);
    }

    /// <summary>
    /// Разбирает расшифрованную полезную нагрузку: отмечает пакет для ACK, извлекает
    /// кадр туннеля и учитывает служебные кадры (KEY_UPDATE, CONNECTION_CLOSE).
    /// </summary>
    private bool HandlePayload(byte[] payload, ulong packetNumber, QuicPacketNumberSpace space, out Opened opened)
    {
        opened = default;

        if (IsDuplicate(space, packetNumber))
        {
            // Дубликат: настоящий получатель отвечает на него пустым ACK.
            opened = new Opened(QuicPacketOutcome.Handshake, Array.Empty<byte>());
            return true;
        }

        switch (space)
        {
            case QuicPacketNumberSpace.Initial:
                _rxLargestInitialPn = (long)packetNumber;
                break;
            case QuicPacketNumberSpace.Handshake:
                _rxLargestHandshakePn = (long)packetNumber;
                break;
            default:
                _rxLargestAppPn = (long)packetNumber;
                break;
        }

        var frame = Array.Empty<byte>();
        var outcome = QuicPacketOutcome.Handshake;
        var ackEliciting = false;

        var reader = new QuicFrameReader(payload);
        while (reader.Read())
        {
            var info = reader.Current;
            if (!info.Valid)
            {
                opened = new Opened(QuicPacketOutcome.Unknown, Array.Empty<byte>());
                return true;
            }

            if (info.AckEliciting)
                ackEliciting = true;

            switch (space)
            {
                case QuicPacketNumberSpace.Initial:
                    if (info.Type == QuicFrame.Crypto)
                    {
                        _peerCryptoEnd = Math.Max(_peerCryptoEnd, info.Offset + (ulong)info.Data.Length);
                        if (QuicTls.TryReadClientHello(info.Data, out var sessionId, out _))
                            _peerSessionId = sessionId;
                    }

                    break;

                case QuicPacketNumberSpace.Handshake:
                    if (info.Type == QuicFrame.Crypto)
                    {
                        // Поток CRYPTO общий для всех уровней, поэтому начало AuthAck
                        // сервера — это конец ClientHello и Auth клиента.
                        _peerCryptoEnd = Math.Max(_peerCryptoEnd, info.Offset + (ulong)info.Data.Length);
                        if (info.Data.Length > 0)
                            frame = info.Data.ToArray();
                    }

                    break;

                default:
                    if (info.Type >= QuicFrame.StreamBase && info.Type <= QuicFrame.StreamBase + 0x07)
                    {
                        // Данные потока: отбрасываем то, что уже принято, и принимаем
                        // всё, что идёт после. Пропуски возможны — потери в UDP для
                        // туннеля штатны (передача повторяется выше по стеку).
                        if (frame.Length == 0)
                        {
                            var end = info.Offset + (ulong)info.Data.Length;
                            if (end > _rxStreamEnd)
                            {
                                var skip = (int)Math.Max(0, _rxStreamEnd - info.Offset);
                                frame = info.Data.Length > skip
                                    ? info.Data[skip..].ToArray()
                                    : Array.Empty<byte>();
                                _rxStreamEnd = end;
                            }
                        }
                    }
                    else if (info.KeyUpdate)
                    {
                        // KEY_UPDATE: получатель переходит на следующую фазу ключей.
                        // Ответный KEY_UPDATE отправляем, только если нас об этом
                        // попросили, иначе фазы разъедутся.
                        _rxPhase ^= 1;
                        _rxKeyUpdateRequest = info.KeyUpdateRequest;
                    }
                    else if (info.ConnectionClose)
                    {
                        _closed = true;
                        outcome = QuicPacketOutcome.Closed;
                    }
                    else if (info.PathChallenge)
                    {
                        // Настоящий клиент отвечает на PATH_CHALLENGE; здесь ответ
                        // не важен для туннеля, достаточно корректного учёта пакета.
                    }

                    break;
            }
        }

        // Пакет учитывается один раз, независимо от числа кадров в нём: номер
        // пакета — это номер датаграммы, а не кадров.
        switch (space)
        {
            case QuicPacketNumberSpace.Initial:
                _rxAcksInitial.RecordPacket(packetNumber, ackEliciting);
                break;
            case QuicPacketNumberSpace.Handshake:
                _rxAcksHandshake.RecordPacket(packetNumber, ackEliciting);
                break;
            default:
                _rxAcksApp.RecordPacket(packetNumber, ackEliciting);
                break;
        }

        // Кадр туннеля в пакете важнее служебных кадров, но CONNECTION_CLOSE важнее
        // всего: он означает закрытие соединения, а не доставку данных.
        if (frame.Length > 0 && outcome != QuicPacketOutcome.Closed)
            outcome = QuicPacketOutcome.Tunnel;

        opened = new Opened(outcome, frame);
        return true;
    }

    private bool IsDuplicate(QuicPacketNumberSpace space, ulong packetNumber) => space switch
    {
        QuicPacketNumberSpace.Initial => _rxLargestInitialPn >= 0 && packetNumber <= (ulong)_rxLargestInitialPn,
        QuicPacketNumberSpace.Handshake => _rxLargestHandshakePn >= 0 && packetNumber <= (ulong)_rxLargestHandshakePn,
        _ => _rxLargestAppPn >= 0 && packetNumber <= (ulong)_rxLargestAppPn,
    };

    /// <summary>
    /// Сводит исходы пакетов одной датаграммы. Пакеты с кадром туннеля важнее
    /// служебных, но служебный пакет, который мы всё же открыли, должен означать
    /// «датаграмма наша» — иначе вызывающая сторона решит, что её не понимают.
    /// </summary>
    private static QuicPacketOutcome Merge(QuicPacketOutcome current, QuicPacketOutcome next) => next switch
    {
        QuicPacketOutcome.Tunnel or QuicPacketOutcome.Closed => next,
        QuicPacketOutcome.Handshake when current == QuicPacketOutcome.Unknown => QuicPacketOutcome.Handshake,
        _ => current
    };

    private readonly struct Opened
    {
        public Opened(QuicPacketOutcome outcome, byte[] frame)
        {
            Outcome = outcome;
            Frame = frame;
        }

        public QuicPacketOutcome Outcome { get; }

        public byte[] Frame { get; }
    }

    // --- Формирование пакетов 1-RTT ---

    private byte[] WrapApplicationFrame(byte[] frame, WireFrameRole role)
    {
        var keys = TxKeys();
        var streamOffset = _txStreamOffset;
        _txStreamOffset += (ulong)frame.Length;

        var packetNumberLength = PacketNumberLength(_txAppPn);
        var streamFrame = MeasureStreamFrame(streamOffset, frame.Length);
        var ackSize = _txAcksApp.MeasureAck(AckDelay);

        // Подтверждение, если накопилось, умещается в тот же пакет и есть шанс.
        var ackInline = ackSize > 0 &&
                        Random.Shared.NextDouble() < AckCoalesceProbability &&
                        streamFrame + ackSize + PacketOverhead(packetNumberLength) + 64 <= QuicPacket.MaxDatagram;
        if (ackInline)
            ackSize = 0;

        var extra = role == WireFrameRole.Keepalive ? ExtraPing : PickExtra(role);

        // Настоящий сервер сообщает клиенту о завершении рукопожатия в первом же
        // пакете 1-RTT.
        var handshakeDone = !_isClient && !_handshakeDoneSent;

        // Смена фазы ключей объявляется в последнем пакете старой фазы.
        var keyUpdate = _txAppPn + 1 >= PacketsPerPhase;

        var closeSize = role == WireFrameRole.Close
            ? QuicVarInt.SizeOf(QuicFrame.ConnectionCloseApplication) + 2
            : 0;

        var natural = streamFrame + ackSize + ExtraSize(extra) + closeSize +
                      (handshakeDone ? 1 : 0) + (keyUpdate ? 3 : 0) +
                      PacketOverhead(packetNumberLength);
        var target = role == WireFrameRole.Data ? ChooseDataSize(natural) : natural;

        var frames = new QuicWriter(target + 32);
        if (ackInline)
            _txAcksApp.TryWriteAck(frames, AckDelay);

        if (handshakeDone)
        {
            QuicFrame.WriteHandshakeDone(frames);
            _handshakeDoneSent = true;
        }

        if (_rxKeyUpdateRequest)
        {
            // Ответный KEY_UPDATE: подтверждаем смену фазы, иначе собеседник
            // продолжит слать в прежнюю.
            QuicFrame.WriteKeyUpdate(frames, requestUpdate: false);
            _rxKeyUpdateRequest = false;
        }

        if (role == WireFrameRole.Keepalive)
            QuicFrame.WritePing(frames);

        QuicFrame.WriteStream(frames, TunnelStreamId, streamOffset, frame, fin: role == WireFrameRole.Close);
        WriteExtra(frames, extra);

        if (role == WireFrameRole.Close)
            QuicFrame.WriteConnectionCloseApplication(frames, QuicFrame.ApplicationCloseCode, ReadOnlySpan<byte>.Empty);

        _closed = role == WireFrameRole.Close;

        if (keyUpdate)
            QuicFrame.WriteKeyUpdate(frames, requestUpdate: false);

        frames.WritePadding(Math.Max(0, target - natural));

        var packet = QuicPacket.BuildShort(
            RemoteCid(_epoch),
            (_txPhase & 1) == 1,
            _txAppPn,
            packetNumberLength,
            keys,
            frames.ToArray());

        _txAppPn++;

        if (_txAppPn >= PacketsPerPhase)
        {
            _txPhase++;
            _txKeys = null;
            _txAppPn = 0;
        }

        return packet;
    }

    /// <summary>
    /// Кадр на уровне Handshake (используется только до установки ключей 1-RTT):
    /// пакет Handshake с кадром CRYPTO и небольшим паддингом.
    /// </summary>
    private byte[] WrapHandshakeLevel(byte[] frame)
    {
        var frames = new QuicWriter(frame.Length + 64);
        QuicFrame.WriteCrypto(frames, _peerCryptoEnd + (ulong)_txCryptoOffset, frame);
        _txCryptoOffset += (ulong)frame.Length;
        frames.WritePadding(Random.Shared.Next(0, 32));

        return QuicPacket.BuildLong(
            QuicLongPacketType.Handshake,
            RemoteCid(_epoch),
            LocalCid(_epoch),
            Array.Empty<byte>(),
            _txHandshakePn++,
            1,
            HandshakeTxKeys(),
            frames.ToArray());
    }

    /// <summary>
    /// Отдельная датаграмма с подтверждениями пакетов уровней Initial/Handshake —
    /// её настоящий клиент отправляет сразу после получения первого пакета сервера,
    /// объединяя оба пакета в одну датаграмму. Возвращает null, если подтверждать
    /// нечего или отправлять нечем (сервер в эту фазу не вмешивается).
    /// </summary>
    private byte[]? BuildHandshakeAckDatagram()
    {
        if (!_isClient || (!_txAcksInitial.HasPending && !_txAcksHandshake.HasPending))
            return null;

        var initialFrames = new QuicWriter(64);
        if (!_txAcksInitial.TryWriteAck(initialFrames, AckDelay))
            initialFrames.WritePadding(Random.Shared.Next(0, 16));

        var handshakeFrames = new QuicWriter(64);
        if (!_txAcksHandshake.TryWriteAck(handshakeFrames, AckDelay))
            handshakeFrames.WritePadding(Random.Shared.Next(0, 16));

        var initial = QuicPacket.BuildLong(
            QuicLongPacketType.Initial,
            RemoteCid(_epoch),
            LocalCid(_epoch),
            Array.Empty<byte>(),
            _txInitialPn++,
            1,
            InitialTxKeys(),
            initialFrames.ToArray());

        var handshake = QuicPacket.BuildLong(
            QuicLongPacketType.Handshake,
            RemoteCid(_epoch),
            LocalCid(_epoch),
            Array.Empty<byte>(),
            _txHandshakePn++,
            1,
            HandshakeTxKeys(),
            handshakeFrames.ToArray());

        return Concat(initial, handshake);
    }

    // --- Ключи и идентификаторы соединения ---

    private static byte[] DeriveAppSecret(byte[] sessionKey, string direction) =>
        HKDF.DeriveKey(
            HashAlgorithmName.SHA256, sessionKey, TunnelKeys.QuicSecretSize,
            salt: null, info: Encoding.ASCII.GetBytes("proxify-quic-v1-1rtt-" + direction));

    private byte[] HandshakeSecret(int epoch, bool sending)
    {
        var clientToServer = _isClient == sending;
        var baseSecret = clientToServer ? _c2sSecret : _s2cSecret;
        var direction = clientToServer ? "c2s" : "s2c";
        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256, baseSecret, TunnelKeys.QuicSecretSize, salt: null,
            info: Encoding.ASCII.GetBytes("proxify-quic-v1-hs-" + direction + "-" + epoch));
    }

    /// <summary>
    /// Ключи Initial выводятся из исходного DCID, который выбрал клиент для первого
    /// пакета. Сервер в своём ответе меняет местами DCID и SCID, но соль остаётся
    /// прежней — иначе клиент не смог бы расшифровать ответ.
    /// </summary>
    private QuicPacketKeys InitialTxKeys() => _initialTxKeys ??= QuicPacketKeys.ForInitial(InitialDcid(_epoch), _isClient);

    private QuicPacketKeys InitialRxKeys() => _initialRxKeys ??= QuicPacketKeys.ForInitial(InitialDcid(_epoch), !_isClient);

    /// <summary>
    /// Исходный DCID, выбранный клиентом, — по нему выводятся все ключи Initial
    /// (RFC 9001): это собственный идентификатор сервера, а не собеседника, так
    /// как на стороне сервера DCID ответных пакетов — уже идентификатор клиента.
    /// </summary>
    private byte[] InitialDcid(int epoch) => ServerCid(epoch);

    private QuicPacketKeys HandshakeTxKeys() => _handshakeTxKeys ??= QuicPacketKeys.FromSecret(HandshakeSecret(_epoch, sending: true));

    private QuicPacketKeys HandshakeRxKeys() => _handshakeRxKeys ??= QuicPacketKeys.FromSecret(HandshakeSecret(_epoch, sending: false));

    private QuicPacketKeys TxKeys() => _txKeys ??= QuicPacketKeys.ForPhase(_appSecretTx!, _txPhase);

    /// <summary>
    /// Ключи приёма: текущая фаза и соседняя. Соседняя нужна, пока получатель не
    /// увидел KEY_UPDATE, отправленный в последнем пакете предыдущей фазы.
    /// </summary>
    private QuicPacketKeys[] RxKeyCandidates() => new[]
    {
        QuicPacketKeys.ForPhase(_appSecretRx!, _rxPhase),
        QuicPacketKeys.ForPhase(_appSecretRx!, _rxPhase ^ 1),
    };

    /// <summary>Собственный идентификатор соединения — тот, под которым нас знает собеседник.</summary>
    private byte[] LocalCid(int epoch) => _isClient ? ClientCid(epoch) : ServerCid(epoch);

    /// <summary>Идентификатор собеседника — тот, который мы пишем в DCID.</summary>
    private byte[] RemoteCid(int epoch) => _isClient ? ServerCid(epoch) : ClientCid(epoch);

    private byte[] ServerCid(int epoch) => Cids(epoch).Server;

    private byte[] ClientCid(int epoch) => Cids(epoch).Client;

    private (byte[] Server, byte[] Client) Cids(int epoch)
    {
        lock (_cidGate)
        {
            if (_cids.TryGetValue(epoch, out var existing))
                return existing;

            var server = QuicPacketKeys.ExpandLabel(_c2sSecret, "proxify-quic-v1-dcid-" + epoch, CidLength);
            var client = QuicPacketKeys.ExpandLabel(_c2sSecret, "proxify-quic-v1-scid-" + epoch, CidLength);
            if (_cids.Count > 64)
                _cids.Clear();

            _cids[epoch] = (server, client);
            return (server, client);
        }
    }

    /// <summary>
    /// Ищет, какому рукопожатию (эпохе) принадлежит идентификатор соединения из
    /// заголовка. Сначала проверяются текущая и соседние эпохи, затем начальный
    /// диапазон: после перезапуска клиента эпоха сбрасывается, и сервер обязан её
    /// узнать по идентификатору.
    /// </summary>
    /// <summary>
    /// Поле DCID пакета — это идентификатор <em>получателя</em>, поэтому сверять его
    /// нужно со своим собственным идентификатором, а не с идентификатором собеседника.
    /// Пробуем соседние и более новые epoch: собеседник мог уже перейти на новый.
    /// </summary>
    private bool TryMatchPeerCid(ReadOnlySpan<byte> dcid, out int epoch)
    {
        epoch = _epoch;
        if (dcid.Length != CidLength)
            return false;

        for (var e = Math.Max(0, _epoch - 1); e <= _epoch + 1 && e <= MaxEpochScan; e++)
        {
            if (dcid.SequenceEqual(LocalCid(e)))
            {
                epoch = e;
                return true;
            }
        }

        for (var e = 0; e <= Math.Min(MaxEpochScan, _epoch + 8); e++)
        {
            if (dcid.SequenceEqual(LocalCid(e)))
            {
                epoch = e;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Принимает эпоху собеседника. Эпохой управляет клиент, поэтому сервер следует
    /// за ним, а клиент принимает только свою. Возвращает false, если эпоха не
    /// годится: пакет адресован другому рукопожатию.
    /// </summary>
    private bool AdoptPeerEpoch(int epoch)
    {
        if (_isClient)
            return epoch == _epoch;
        if (epoch <= _epoch)
            return epoch == _epoch;

        _epoch = epoch;
        ResetHandshakeSpace();
        ResetHandshakeReceiveState();
        return true;
    }

    /// <summary>
    /// Сбрасывает состояние уровней Initial/Handshake для новой эпохи: ключи
    /// другие, значит и номера пакетов можно начинать заново.
    /// </summary>
    private void ResetHandshakeSpace()
    {
        _initialTxKeys = null;
        _initialRxKeys = null;
        _handshakeTxKeys = null;
        _handshakeRxKeys = null;
        _txInitialPn = 0;
        _txHandshakePn = 0;
        _txCryptoOffset = 0;
        _txAcksInitial.Reset();
        _txAcksHandshake.Reset();
    }

    /// <summary>
    /// Приёмная часть уровней Initial и Handshake при переходе на новую эпоху
    /// обнуляется: новая эпоха — это новые ключи и новые номера пакетов с нуля,
    /// поэтому принятое раньше не должно помешать приёмнику.
    /// </summary>
    private void ResetHandshakeReceiveState()
    {
        _rxLargestInitialPn = -1;
        _rxLargestHandshakePn = -1;
        _rxAcksInitial.Reset();
        _rxAcksHandshake.Reset();
        _peerCryptoEnd = 0;
        _peerSessionId = Array.Empty<byte>();
    }

    // --- Служебные кадры и размеры ---

    private int MeasureStreamFrame(ulong offset, int payloadLength) =>
        QuicVarInt.SizeOf(QuicFrame.StreamWithOffsetAndLength) +
        QuicVarInt.SizeOf(TunnelStreamId) +
        QuicVarInt.SizeOf(offset) +
        QuicVarInt.SizeOf((ulong)payloadLength) +
        payloadLength;

    private int PacketOverhead(int packetNumberLength) =>
        QuicPacket.ShortPacketLength(CidLength, packetNumberLength, 0);

    /// <summary>Выбирает один из редких служебных кадров, которые ходят между деловыми.</summary>
    private static int PickExtra(WireFrameRole role)
    {
        if (role != WireFrameRole.Data)
            return ExtraNone;

        var roll = Random.Shared.NextDouble();
        if (roll >= ControlProbability + PingProbability)
            return ExtraNone;
        if (roll < PingProbability)
            return ExtraPing;

        return Random.Shared.Next(2) == 0 ? ExtraMaxData : ExtraMaxStreams;
    }

    private static int ExtraSize(int extra) => extra switch
    {
        ExtraMaxData => QuicVarInt.SizeOf(QuicFrame.MaxData) + QuicVarInt.SizeOf(1UL << 20),
        ExtraMaxStreams => QuicVarInt.SizeOf(QuicFrame.MaxStreamsBidi) + QuicVarInt.SizeOf(64),
        ExtraPing => QuicVarInt.SizeOf(QuicFrame.Ping),
        _ => 0,
    };

    private static void WriteExtra(QuicWriter frames, int extra)
    {
        switch (extra)
        {
            case ExtraMaxData:
                QuicFrame.WriteMaxData(frames, 1UL << 20);
                break;
            case ExtraMaxStreams:
                QuicFrame.WriteMaxStreams(frames, bidirectional: true, 64);
                break;
            case ExtraPing:
                QuicFrame.WritePing(frames);
                break;
        }
    }

    private static int ChooseDataSize(int minimum)
    {
        if (minimum > QuicPacket.MaxDatagram || Random.Shared.NextDouble() >= DataPaddingProbability)
            return minimum;

        foreach (var candidate in RealisticDatagramSizes)
        {
            if (candidate >= minimum)
                return candidate;
        }

        return minimum;
    }

    private static int PickInitialSize() => InitialDatagramSizes[Random.Shared.Next(InitialDatagramSizes.Length)];

    private static int PacketNumberLength(ulong packetNumber) => packetNumber switch
    {
        < 0x100 => 1,
        < 0x10000 => Random.Shared.Next(100) < 85 ? 2 : 3,
        _ => 3,
    };

    /// <summary>
    /// Дописывает кадры PADDING так, чтобы пакет длинного заголовка занял ровно
    /// <paramref name="target"/> байт. Если пакет уже больше цели, ничего не
    /// меняется: превышение 1200 байт для Initial не опасно, недобор опасен.
    /// </summary>
    private static void PadLongPacket(QuicWriter frames, int target, QuicLongPacketType type, int packetNumberLength)
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var length = QuicPacket.LongPacketLength(type, CidLength, CidLength, 0, packetNumberLength, frames.Length);
            var delta = target - length;
            if (delta <= 0)
                return;

            frames.WritePadding(delta);
        }
    }

    private static byte[] Concat(byte[] first, byte[] second)
    {
        var result = new byte[first.Length + second.Length];
        Buffer.BlockCopy(first, 0, result, 0, first.Length);
        Buffer.BlockCopy(second, 0, result, first.Length, second.Length);
        return result;
    }
}
