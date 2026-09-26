using System.Security.Cryptography;
using System.Text;
using Proxify.Common.Crypto;
using Proxify.Common.Quic;

namespace Proxify.SelfTest;

/// <summary>
/// Самопроверка маскировки под вид QUIC. Проверяет то, ради чего она делается:
///
///  1. Initial-пакет читается сторонним наблюдателем, который знает только
///     публичную соль QUIC v1 и видит заголовок: ClientHello разбирается как
///     настоящий (SNI, ALPN h3, key_share, параметры транспорта);
///  2. Handshake-пакет таким наблюдателем не читается: ключи уровня Handshake
///     выведены из зарегистрированного ключа клиента, а не из публичной соли;
///  3. клиент и сервер понимают пакеты друг друга, включая объединённые
///     датаграммы, а кадры туннеля доходят без потерь в обоих направлениях;
///  4. чужой ключ не подходит: пакеты другого клиента не принимаются.
///
/// Прав администратора не требует, поэтому выполняется всегда.
/// Возвращает число проваленных проверок.
/// </summary>
internal static class QuicSelfTest
{
    private const string ServerName = "example.com";

    public static int Run()
    {
        Console.WriteLine("=== Самопроверка маскировки под вид QUIC ===");

        var (clientPem, _) = TunnelKeys.GeneratePem();
        using var clientKey = TunnelKeys.ImportPrivatePem(clientPem);
        var (foreignPem, _) = GenerateForeignKey();
        using var foreignKey = TunnelKeys.ImportPrivatePem(foreignPem);

        var client = QuicConnection.Create(clientKey, isClient: true, ServerName);
        var server = QuicConnection.Create(clientKey, isClient: false, ServerName);

        var auth = RandomNumberGenerator.GetBytes(TunnelKeys.PointSize * 2 + TunnelKeys.NonceSize + TunnelKeys.SignatureSize);
        var authAck = RandomNumberGenerator.GetBytes(64);

        var clientFlight = client.BuildClientFlight(auth);
        var serverFlight = server.BuildServerFlight(authAck);

        var failures = 0;
        failures += CheckClientFlightShape(clientFlight);
        failures += CheckServerFlightShape(serverFlight);
        failures += CheckObserverCanReadInitial(clientFlight[0]);
        failures += CheckObserverCannotReadHandshake(clientFlight[1], clientFlight[0]);
        failures += CheckHandshakeHandoff(clientFlight, serverFlight, auth, authAck);
        failures += CheckDataRoundTrip(client, server);
        failures += CheckForeignKeyRejected(client, foreignKey, auth);
        failures += CheckClientHelloStructure(clientFlight[0]);
        failures += CheckWireObfuscatorModes(clientKey);
        failures += CheckModeMismatch(clientKey, foreignKey);
        failures += CheckRepeatedHandshake();

        Console.WriteLine();
        return failures;
    }

    /// <summary>
    /// Повторное рукопожатие (например, клиент переподключился после таймаута):
    /// начинается новая эпоха с новыми ключами и номерами пакетов с нуля. Сервер
    /// обязан принять её как новую, а не выбросить как повтор старой.
    /// </summary>
    private static int CheckRepeatedHandshake()
    {
        Console.WriteLine("[11] Повторное рукопожатие: новая эпоха принимается, старая не мешает");
        try
        {
            var (clientPem, _) = TunnelKeys.GeneratePem();
            using var key = TunnelKeys.ImportPrivatePem(clientPem);
            var client = WireObfuscator.Create(key, weAreClient: true, WireObfuscationMode.Quic, ServerName);
            var server = WireObfuscator.Create(key, weAreClient: false, WireObfuscationMode.Quic, ServerName);

            byte[] firstFlight = Array.Empty<byte>();

            for (var attempt = 1; attempt <= 3; attempt++)
            {
                var auth = RandomNumberGenerator.GetBytes(96 + attempt);
                var ack = RandomNumberGenerator.GetBytes(40 + attempt);

                var flight = client.Wrap(auth, WireFrameRole.Handshake);
                if (attempt == 1)
                    firstFlight = flight;

                Expect(server.Unwrap(flight, flight.Length, out var receivedAuth) == WireOutcome.Tunnel,
                    $"попытка {attempt}: сервер не принял рукопожатие");
                Expect(receivedAuth.AsSpan().SequenceEqual(auth), $"попытка {attempt}: кадр Auth искажён");

                var response = server.Wrap(ack, WireFrameRole.Handshake);
                Expect(client.Unwrap(response, response.Length, out var receivedAck) == WireOutcome.Tunnel,
                    $"попытка {attempt}: клиент не принял AuthAck");
                Expect(receivedAck.AsSpan().SequenceEqual(ack), $"попытка {attempt}: кадр AuthAck искажён");
            }

            // Повтор первого рукопожатия — уже устаревшая эпоха со своими CID.
            Expect(server.Unwrap(firstFlight, firstFlight.Length, out _) == WireOutcome.Unknown,
                "пакет устаревшей эпохи принят как актуальный");

            return 0;
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
    }

    // --- 9-11. Оболочка WireObfuscator во всех режимах ---

    /// <summary>
    /// Проверяет то, чем реально пользуются сессии: оболочку WireObfuscator в
    /// каждом режиме и полный цикл Auth → AuthAck → данные через неё.
    /// </summary>
    private static int CheckWireObfuscatorModes(ECDsa clientKey)
    {
        Console.WriteLine("[9] Оболочка WireObfuscator: off, random и quic");
        try
        {
            foreach (var mode in new[] { WireObfuscationMode.Off, WireObfuscationMode.Random, WireObfuscationMode.Quic })
            {
                var client = WireObfuscator.Create(clientKey, weAreClient: true, mode, ServerName);
                var server = WireObfuscator.Create(clientKey, weAreClient: false, mode, ServerName);
                Expect(client.Mode == mode && server.Mode == mode, $"режим {mode} не сохранился");

                var auth = RandomNumberGenerator.GetBytes(96);
                var ack = RandomNumberGenerator.GetBytes(48);
                var payload = RandomNumberGenerator.GetBytes(600);

                // Рукопожатие: клиент шлёт первый обмен, сервер — ответ.
                var firstFlight = client.Wrap(auth, WireFrameRole.Handshake);
                var firstOutcome = server.Unwrap(firstFlight, firstFlight.Length, out var receivedAuth);
                Expect(firstOutcome == WireOutcome.Tunnel, $"{mode}: рукопожатие не принято ({firstOutcome})");
                Expect(receivedAuth.AsSpan().SequenceEqual(auth), $"{mode}: кадр рукопожатия искажён");

                var response = server.Wrap(ack, WireFrameRole.Handshake);
                Expect(client.Unwrap(response, response.Length, out var receivedAck) == WireOutcome.Tunnel,
                    $"{mode}: ответ рукопожатия не принят");
                Expect(receivedAck.AsSpan().SequenceEqual(ack), $"{mode}: кадр AuthAck искажён");

                // Данные идут уже в пакетах 1-RTT (в режиме off — без оболочки).
                var sessionKey = RandomNumberGenerator.GetBytes(TunnelKeys.SessionKeySize);
                client.AttachSessionKey(sessionKey);
                server.AttachSessionKey(sessionKey);

                var data = client.Wrap(payload, WireFrameRole.Data);
                Expect(server.Unwrap(data, data.Length, out var receivedData) == WireOutcome.Tunnel,
                    $"{mode}: данные не приняты");
                Expect(receivedData.AsSpan().SequenceEqual(payload), $"{mode}: данные искажены");

                // Служебный пакет без кадра туннеля не должен считаться ошибкой и
                // не должен выдавать мусор вместо кадра.
                var ping = client.Wrap(new byte[] { 0x7F }, WireFrameRole.Keepalive);
                var pingOutcome = server.Unwrap(ping, ping.Length, out var pingFrame);
                Expect(pingOutcome == WireOutcome.Tunnel, $"{mode}: пинг не принят ({pingOutcome})");
                Expect(pingFrame.AsSpan().SequenceEqual(new byte[] { 0x7F }), $"{mode}: пинг искажён");

                // Закрытие туннеля. Признать CONNECTION_CLOSE может только режим quic:
                // в режиме random это просто зашифрованный кадр, а без оболочки —
                // обычный кадр данных.
                var close = server.Wrap(new byte[] { 0x01 }, WireFrameRole.Close);
                var closeOutcome = client.Unwrap(close, close.Length, out _);
                if (mode == WireObfuscationMode.Quic)
                    Expect(closeOutcome == WireOutcome.Closed, "quic: CONNECTION_CLOSE не распознан");
                else
                    Expect(closeOutcome == WireOutcome.Tunnel, $"{mode}: закрытие потеряно");
            }

            return 0;
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
    }

    /// <summary>
    /// Режимы должны различаться: пакет, собранный в одном режиме, не принимается
    /// в другом, иначе маскировка не добавляет ничего.
    /// </summary>
    private static int CheckModeMismatch(ECDsa clientKey, ECDsa foreignKey)
    {
        Console.WriteLine("[10] Режимы не путают друг друга: quic ≠ random, чужой ключ ≠ свой");
        try
        {
            var quic = WireObfuscator.Create(clientKey, weAreClient: true, WireObfuscationMode.Quic, ServerName);
            var random = WireObfuscator.Create(clientKey, weAreClient: false, WireObfuscationMode.Random, ServerName);
            var foreign = WireObfuscator.Create(foreignKey, weAreClient: false, WireObfuscationMode.Quic, ServerName);

            var sessionKey = RandomNumberGenerator.GetBytes(TunnelKeys.SessionKeySize);
            quic.AttachSessionKey(sessionKey);
            foreign.AttachSessionKey(sessionKey);

            // Первый пакет рукопожатия несёт длинный заголовок QUIC — по нему
            // датаграмма режима quic опознаётся сторонним наблюдателем без ключей.
            var datagram = quic.Wrap(RandomNumberGenerator.GetBytes(400), WireFrameRole.Handshake);
            Expect(WireObfuscator.LooksLikeQuic(datagram, datagram.Length), "датаграмма режима quic не узнаётся по заголовку");
            Expect(random.Unwrap(datagram, datagram.Length, out _) == WireOutcome.Unknown, "режим random принял пакет режима quic");
            Expect(foreign.Unwrap(datagram, datagram.Length, out _) == WireOutcome.Unknown, "чужой ключ принял пакет");

            // И наоборот: пакет режима random не должен читаться как quic.
            var randomDatagram = random.Wrap(RandomNumberGenerator.GetBytes(400), WireFrameRole.Data);
            Expect(!WireObfuscator.LooksLikeQuic(randomDatagram, randomDatagram.Length),
                "датаграмма режима random ошибочно распознана как QUIC");

            return 0;
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
    }

    /// <summary>Ключ постороннего клиента: его пакеты наш сервер принимать не должен.</summary>
    private static (string PrivatePem, string PublicPem) GenerateForeignKey()
    {
        var (privatePem, publicPem) = TunnelKeys.GeneratePem();
        return (privatePem, publicPem);
    }

    // --- 1. Форма первого пакета клиента ---

    private static int CheckClientFlightShape(byte[][] flight)
    {
        Console.WriteLine("[1] Первый пакет клиента: длинный заголовок, версия 1, 1200+ байт");
        try
        {
            Expect(flight.Length == 2, "ожидались два пакета: Initial и Handshake");

            var initial = flight[0];
            Expect(initial.Length >= QuicPacket.MinInitialDatagram, $"Initial короче 1200 байт: {initial.Length}");

            if (!QuicPacket.TryParseLongHeader(initial, 0, initial.Length, out var header))
                return Fail("заголовок Initial не разобран");

            Expect(header.Version == QuicPacket.Version1, "версия не 1");
            Expect(header.Type == QuicLongPacketType.Initial, "тип не Initial");
            Expect(header.Dcid.Length == QuicConnection.CidLength, $"длина DCID {header.Dcid.Length}");
            Expect(header.Scid.Length == QuicConnection.CidLength, $"длина SCID {header.Scid.Length}");

            // Второй пакет — Handshake в отдельной датаграмме.
            Expect(QuicPacket.TryParseLongHeader(flight[1], 0, flight[1].Length, out var second), "Handshake не разобран");
            Expect(second.Type == QuicLongPacketType.Handshake, "второй пакет не Handshake");

            // Первый байт: длинный заголовок, форсированный бит, тип в битах 4..5.
            // После защиты заголовка тип замаскирован, поэтому проверяем до неё косвенно:
            // разбор уже прошёл, значит первые байты корректны.
            return 0;
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
    }

    // --- 2. Форма первого пакета сервера ---

    private static int CheckServerFlightShape(byte[] flight)
    {
        Console.WriteLine("[2] Ответ сервера: Initial и Handshake объединены в одну датаграмму");
        try
        {
            Expect(flight.Length >= QuicPacket.MinInitialDatagram, $"датаграмма сервера короче 1200: {flight.Length}");
            Expect(QuicPacket.TryParseLongHeader(flight, 0, flight.Length, out var initial), "первый пакет не разобран");
            Expect(initial.Type == QuicLongPacketType.Initial, "сервер начал не с Initial");
            Expect(initial.Dcid.Length == QuicConnection.CidLength, $"длина DCID ответа {initial.Dcid.Length}");

            // Граница первого пакета известна без расшифровки — это и позволяет
            // разбирать объединённые датаграммы.
            Expect(QuicPacket.TryParseLongHeader(flight, initial.PacketLength, flight.Length - initial.PacketLength, out var second),
                "второй пакет объединённой датаграммы не разобран");
            Expect(second.Type == QuicLongPacketType.Handshake, "второй пакет не Handshake");
            return 0;
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
    }

    // --- 3. Наблюдатель читает Initial ---

    /// <summary>
    /// Главное требование: сторонний наблюдатель, знающий публичную соль версии 1
    /// и видящий заголовок, обязан расшифровать Initial и получить настоящий
    /// ClientHello — иначе соединение выглядит аномальным.
    /// </summary>
    private static int CheckObserverCanReadInitial(byte[] datagram)
    {
        Console.WriteLine("[3] Наблюдатель с публичной солью QUIC v1 читает ClientHello");
        try
        {
            if (!QuicPacket.TryParseLongHeader(datagram, 0, datagram.Length, out var header))
                return Fail("заголовок не разобран");

            // Наблюдатель не знает ничего, кроме соли версии и DCID из заголовка.
            var keys = QuicPacketKeys.ForInitial(header.Dcid, isClient: true);
            if (!QuicPacket.TryOpen(datagram, 0, datagram.Length, header.PacketNumberOffset,
                    isLongHeader: true, keys, expectedPacketNumber: -1, out _, out var payload))
                return Fail("Initial не расшифрован публичными ключами");

            var crypto = ReadCryptoData(payload);
            Expect(crypto.Length > 0, "в Initial нет кадра CRYPTO");
            Expect(crypto[0] == QuicTls.HandshakeClientHello, "поток CRYPTO начинается не с ClientHello");

            if (!QuicTls.TryReadClientHello(crypto, out var sessionId, out var messageLength))
                return Fail("ClientHello не разобран");

            Expect(messageLength == crypto.Length, $"длина ClientHello {messageLength} != {crypto.Length}");
            Expect(sessionId.Length == 32, $"session id {sessionId.Length} байт вместо 32");
            return 0;
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
    }

    // --- 4. Наблюдатель не читает Handshake ---

    private static int CheckObserverCannotReadHandshake(byte[] handshakeDatagram, byte[] initialDatagram)
    {
        Console.WriteLine("[4] Наблюдатель НЕ читает Handshake: ключи не из публичной соли");
        try
        {
            if (!QuicPacket.TryParseLongHeader(handshakeDatagram, 0, handshakeDatagram.Length, out var header))
                return Fail("заголовок Handshake не разобран");

            Expect(QuicPacket.TryParseLongHeader(initialDatagram, 0, initialDatagram.Length, out var initial), "Initial не разобран");

            // Соль та же, но Handshake-ключи из неё не выводятся — в этом весь смысл.
            var publicKeys = QuicPacketKeys.ForInitial(initial.Dcid, isClient: false);
            var opened = QuicPacket.TryOpen(handshakeDatagram, 0, handshakeDatagram.Length, header.PacketNumberOffset,
                isLongHeader: true, publicKeys, expectedPacketNumber: -1, out _, out _);
            Expect(!opened, "Handshake-пакет расшифрован ключами Initial — содержимое не защищено");
            return 0;
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
    }

    // --- 5. Передача рукопожатия туннеля ---

    private static int CheckHandshakeHandoff(byte[][] clientFlight, byte[] serverFlight, byte[] auth, byte[] authAck)
    {
        Console.WriteLine("[5] Auth клиента и AuthAck сервера доходят внутри CRYPTO");
        try
        {
            var (clientPem, _) = TunnelKeys.GeneratePem();
            using var key = TunnelKeys.ImportPrivatePem(clientPem);
            var client = QuicConnection.Create(key, isClient: true, ServerName);
            var server = QuicConnection.Create(key, isClient: false, ServerName);

            var flight = client.BuildClientFlight(auth);
            var receivedAuth = Array.Empty<byte>();

            // Клиент шлёт Initial и Handshake отдельными датаграммами.
            for (var i = 0; i < flight.Length; i++)
            {
                var outcome = server.TryUnwrap(flight[i], flight[i].Length, out var frame);
                Expect(outcome != QuicPacketOutcome.Unknown, $"датаграмма {i} не принята сервером");
                if (outcome == QuicPacketOutcome.Tunnel)
                    receivedAuth = frame;
            }

            Expect(receivedAuth.AsSpan().SequenceEqual(auth), "сервер не получил кадр Auth");

            var response = server.BuildServerFlight(authAck);
            var outcomeResponse = client.TryUnwrap(response, response.Length, out var receivedAck);
            Expect(outcomeResponse == QuicPacketOutcome.Tunnel, "клиент не принял ответ сервера");
            Expect(receivedAck.AsSpan().SequenceEqual(authAck), "клиент не получил кадр AuthAck");
            return 0;
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
    }

    // --- 6. Данные туннеля в обе стороны ---

    private static int CheckDataRoundTrip(QuicConnection client, QuicConnection server)
    {
        Console.WriteLine("[6] Кадры туннеля в пакетах 1-RTT в обоих направлениях");
        try
        {
            var sessionKey = RandomNumberGenerator.GetBytes(TunnelKeys.SessionKeySize);
            client.AttachSessionKey(sessionKey);
            server.AttachSessionKey(sessionKey);

            // Клиент обязан подтвердить пакеты сервера отдельной датаграммой
            // уровней Initial/Handshake — она объединяется с деловым пакетом.
            var toServer = new List<byte[]>();
            var request = RandomNumberGenerator.GetBytes(700);
            toServer.Add(client.Wrap(request, WireFrameRole.Data));

            var gotRequest = Array.Empty<byte>();
            foreach (var datagram in toServer)
            {
                var outcome = server.TryUnwrap(datagram, datagram.Length, out var frame);
                Expect(outcome != QuicPacketOutcome.Unknown, "датаграмма клиента не принята сервером");
                if (outcome == QuicPacketOutcome.Tunnel)
                    gotRequest = frame;
            }

            Expect(gotRequest.AsSpan().SequenceEqual(request), $"сервер получил {gotRequest.Length} из {request.Length} байт");

            // Ответ сервера, включая подтверждение и служебные кадры.
            var response = RandomNumberGenerator.GetBytes(400);
            var reply = server.Wrap(response, WireFrameRole.Data);
            var outcomeReply = client.TryUnwrap(reply, reply.Length, out var replyFrame);
            Expect(outcomeReply == QuicPacketOutcome.Tunnel, "датаграмма сервера не принята клиентом");
            Expect(replyFrame.AsSpan().SequenceEqual(response), $"клиент получил {replyFrame.Length} из {response.Length} байт");

            // Пинг и закрытие проходят по тому же пути: пакет сервера принимает клиент.
            var keepalive = server.Wrap(new byte[] { 0x7F }, WireFrameRole.Keepalive);
            Expect(client.TryUnwrap(keepalive, keepalive.Length, out var ping) == QuicPacketOutcome.Tunnel, "пинг не принят клиентом");
            Expect(ping.AsSpan().SequenceEqual(new byte[] { 0x7F }), "пинг доставлен с искажением");

            // Повтор уже принятого номера пакета обязан отбрасываться как дубликат.
            Expect(client.TryUnwrap(keepalive, keepalive.Length, out _) != QuicPacketOutcome.Tunnel, "повторный пакет не отброшен как дубликат");

            // CONNECTION_CLOSE должен распознаваться, а не теряться среди данных.
            var closing = server.Wrap(new byte[] { 0x01 }, WireFrameRole.Close);
            Expect(client.TryUnwrap(closing, closing.Length, out _) == QuicPacketOutcome.Closed, "CONNECTION_CLOSE не распознан");

            // Ничего лишнего не теряется на серии пакетов разного размера.
            var total = 0;
            for (var i = 0; i < 200; i++)
            {
                var payload = RandomNumberGenerator.GetBytes(1 + i % 1200);
                var datagram = client.Wrap(payload, WireFrameRole.Data);
                Expect(datagram.Length <= QuicPacket.MaxDatagram, $"датаграмма {datagram.Length} байт длиннее предела");
                var outcome = server.TryUnwrap(datagram, datagram.Length, out var frame);
                Expect(outcome == QuicPacketOutcome.Tunnel, $"пакет {i} не доставлен");
                Expect(frame.AsSpan().SequenceEqual(payload), $"пакет {i}: получено {frame.Length} из {payload.Length} байт");
                total += frame.Length;
            }

            Console.WriteLine($"    пронесено {total} байт за 200 пакетов");
            return 0;
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
    }

    // --- 7. Чужой ключ не подходит ---

    private static int CheckForeignKeyRejected(QuicConnection client, ECDsa foreignKey, byte[] auth)
    {
        Console.WriteLine("[7] Соединение с чужим ключом не принимается");
        try
        {
            var server = QuicConnection.Create(foreignKey, isClient: false, ServerName);
            var flight = client.BuildClientFlight(auth);

            for (var i = 0; i < flight.Length; i++)
            {
                var outcome = server.TryUnwrap(flight[i], flight[i].Length, out _);
                Expect(outcome == QuicPacketOutcome.Unknown, $"датаграмма {i} принята чужим ключом");
            }

            return 0;
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
    }

    // --- 8. Структура ClientHello ---

    /// <summary>
    /// Разбор ClientHello «глазами» анализатора: длина вектора расширений должна
    /// совпадать с его содержимым, а SNI и ALPN — читаться как настоящие.
    /// </summary>
    private static int CheckClientHelloStructure(byte[] datagram)
    {
        Console.WriteLine("[8] Структура ClientHello: длина расширений, SNI, ALPN");
        try
        {
            if (!QuicPacket.TryParseLongHeader(datagram, 0, datagram.Length, out var header))
                return Fail("заголовок не разобран");

            var keys = QuicPacketKeys.ForInitial(header.Dcid, isClient: true);
            if (!QuicPacket.TryOpen(datagram, 0, datagram.Length, header.PacketNumberOffset,
                    isLongHeader: true, keys, expectedPacketNumber: -1, out _, out var payload))
                return Fail("Initial не расшифрован");

            var crypto = ReadCryptoData(payload);

            // handshake: тип (1) + длина (3), затем тело ClientHello.
            var bodyLength = (crypto[1] << 16) | (crypto[2] << 8) | crypto[3];
            Expect(bodyLength == crypto.Length - 4, $"длина тела {bodyLength} != {crypto.Length - 4}");

            var body = crypto.AsSpan(4);
            var o = 2 + 32; // legacy_version + random
            o += 1 + body[o]; // session id
            var cipherSuitesLength = (body[o] << 8) | body[o + 1];
            Expect(cipherSuitesLength == 6, $"набор шифров {cipherSuitesLength} байт вместо 6");
            Expect(((body[o + 2] << 8) | body[o + 3]) == 0x1301, "первый шифр не TLS_AES_128_GCM_SHA256");
            o += 2 + cipherSuitesLength;
            o += 1 + body[o]; // методы сжатия

            var extensionsLength = (body[o] << 8) | body[o + 1];
            o += 2;
            Expect(o + extensionsLength == body.Length, $"длина расширений {extensionsLength} не сходится с телом ClientHello");

            var foundAlpn = false;
            var foundKeyShare = false;
            var foundTransportParameters = false;
            var end = o + extensionsLength;
            while (o + 4 <= end)
            {
                var type = (ushort)((body[o] << 8) | body[o + 1]);
                var length = (body[o + 2] << 8) | body[o + 3];
                o += 4;
                if (o + length > end)
                    return Fail($"расширение {type:X4} выходит за границы");

                var data = body.Slice(o, length);
                switch (type)
                {
                    case 0x0000: // server_name
                    {
                        // ServerNameList — двухбайтовая длина, затем имя: тип (1 байт)
                        // + двухбайтовая длина + само имя.
                        var listLength = (data[0] << 8) | data[1];
                        Expect(listLength == data.Length - 2, $"длина списка имён {listLength} не сходится");
                        Expect(data[2] == 0x00, "тип имени не host_name");
                        var nameLength = (data[3] << 8) | data[4];
                        var name = Encoding.ASCII.GetString(data.Slice(5, nameLength));
                        Expect(name == ServerName, $"SNI «{name}» вместо «{ServerName}»");
                        break;
                    }

                    case 0x0010: // alpn
                    {
                        var listLength = (data[0] << 8) | data[1];
                        Expect(listLength == data.Length - 2, $"длина списка ALPN {listLength} не сходится");
                        var nameLength = data[2];
                        Expect(data.Slice(3, nameLength).SequenceEqual("h3"u8), "ALPN не h3");
                        foundAlpn = true;
                        break;
                    }

                    case 0x0033: // key_share
                    {
                        // client_shares — список с однобайтовой длиной, затем группа
                        // и двухбайтовая длина открытого ключа.
                        var sharesLength = data[0];
                        Expect(sharesLength == data.Length - 1, "длина key_share не сходится");
                        Expect(((data[1] << 8) | data[2]) == 0x0017, "key_share не для secp256r1");
                        var keyLength = (data[3] << 8) | data[4];
                        Expect(keyLength == 32 && sharesLength == keyLength + 4, "key_share не содержит 32-байтный ключ");
                        foundKeyShare = true;
                        break;
                    }

                    case 0x0039: // quic_transport_parameters
                        foundTransportParameters = true;
                        break;
                }

                o += length;
            }

            Expect(foundAlpn, "нет расширения ALPN");
            Expect(foundKeyShare, "нет расширения key_share");
            Expect(foundTransportParameters, "нет параметров транспорта QUIC");
            return 0;
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
    }

    /// <summary>Склеивает содержимое кадров CRYPTO пакета в порядке передачи.</summary>
    private static byte[] ReadCryptoData(byte[] payload)
    {
        using var stream = new MemoryStream();
        var reader = new QuicFrameReader(payload);
        while (reader.Read())
        {
            if (!reader.Current.Valid)
                break;
            if (reader.Current.Type == QuicFrame.Crypto)
                stream.Write(reader.Current.Data);
        }

        return stream.ToArray();
    }

    /// <summary>Проверка с отчётом: первое нарушение прерывает проверку и даёт одну ошибку.</summary>
    private static void Expect(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private static int Fail(string message)
    {
        Console.WriteLine($"    ОШИБКА: {message}");
        return 1;
    }
}
