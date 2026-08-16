using System.Net;
using System.Net.Sockets;
using System.Text;
using Proxify.Client;
using Proxify.Common;

Console.OutputEncoding = Encoding.UTF8;
Console.WriteLine("=== Самопроверка RawSocket (RealIP) ===");
Console.WriteLine("Проверяет подмену исходного IP и перехват ответов на loopback.");
Console.WriteLine("Запускать ТОЛЬКО от имени администратора (Windows) / root (Linux).");
Console.WriteLine();

// Тестовые параметры
var testClientIp = IPAddress.Parse("203.0.113.10"); // TEST-NET-3, безопасный тестовый адрес
const int testClientPort = 33333;
const int gamePort = 7777;
var gameIp = IPAddress.Loopback;

var failures = 0;

try
{
    // 1. Игровой UDP-сервер на 127.0.0.1:7777
    using var gameServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, gamePort));
    Console.WriteLine($"[1] Игровой сервер слушает {gameIp}:{gamePort}");

    // 2. Сниффер ответов на loopback
    using var sniffer = new SniffSocket(IPAddress.Loopback);
    Console.WriteLine($"[2] Сниффер запущен на {IPAddress.Loopback}");

    // 3. Loopback-алиас для тестового IP клиента
    using var aliases = new LoopbackAliasManager(true);
    aliases.Add(testClientIp);
    Console.WriteLine($"[3] Loopback-алиас для {testClientIp} добавлен");

    // 4. Инжектор
    using var injector = new RawInjector(gameIp, (ushort)gamePort);
    Console.WriteLine($"[4] RawSocket-инжектор создан");

    // 5. Инжектируем пакет с подменённым источником
    var payload = Encoding.UTF8.GetBytes("Hello from spoofed client");
    Console.WriteLine($"[5] Инжектируем пакет от {testClientIp}:{testClientPort} -> {gameIp}:{gamePort}");
    injector.Inject(testClientIp, (ushort)testClientPort, payload);

    // 6. Сервер должен получить пакет с подменённым RemoteEndPoint
    Console.WriteLine("[6] Ждём пакет на игровом сервере...");
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
    var received = await gameServer.ReceiveAsync(cts.Token);
    var receivedFrom = $"{received.RemoteEndPoint.Address}:{received.RemoteEndPoint.Port}";
    var expectedFrom = $"{testClientIp}:{testClientPort}";
    var body = Encoding.UTF8.GetString(received.Buffer);

    Console.WriteLine($"    Получено от: {receivedFrom}, данные: {body}");
    if (receivedFrom == expectedFrom && body == "Hello from spoofed client")
        Console.WriteLine("    OK: подмена исходного IP работает.");
    else
    {
        Console.WriteLine($"    FAIL: ожидалось от {expectedFrom}");
        failures++;
    }

    // 7. Сервер отвечает на адрес, с которого «пришёл» пакет
    Console.WriteLine($"[7] Игровой сервер отвечает на {received.RemoteEndPoint}");
    gameServer.Send(Encoding.UTF8.GetBytes("Reply from game server"), received.RemoteEndPoint);

    // 8. Сниффер должен перехватить ответ (src port = gamePort)
    Console.WriteLine("[8] Ждём перехват ответа сниффером...");
    var captured = sniffer.WaitForReply((ushort)gamePort, TimeSpan.FromSeconds(5));
    if (captured != null)
    {
        Console.WriteLine($"    Перехвачен ответ: {captured.SourceIp}:{captured.SourcePort} -> {captured.DestinationIp}:{captured.DestinationPort}");
        if (captured.SourcePort == gamePort &&
            captured.DestinationIp.Equals(testClientIp) &&
            captured.DestinationPort == testClientPort)
            Console.WriteLine("    OK: перехват ответов работает.");
        else
        {
            Console.WriteLine("    FAIL: ответ перехвачен, но адреса не совпадают.");
            failures++;
        }
    }
    else
    {
        Console.WriteLine("    FAIL: ответ не был перехвачен сниффером.");
        failures++;
    }
}
catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
{
    Console.WriteLine($"[!] Недостаточно прав. Запустите от имени администратора: {ex.Message}");
    failures++;
}
catch (Exception ex)
{
    Console.WriteLine($"[!] Ошибка: {ex.Message}");
    Console.WriteLine(ex);
    failures++;
}
finally
{
    Console.WriteLine();
    Console.WriteLine(failures == 0
        ? "ИТОГ: все проверки пройдены."
        : $"ИТОГ: {failures} проверок провалено. Проверьте права администратора и параметры машины.");
}

/// <summary>
/// Упрощённый сниффер для самопроверки.
/// </summary>
internal sealed class SniffSocket : IDisposable
{
    private readonly Socket _socket;
    private readonly Task<CapturedPacket?> _captureTask;

    public SniffSocket(IPAddress bindIp)
    {
        _socket = PlatformSockets.CreateSnifferSocket();

        _captureTask = Task.Run(ReceiveLoop);
    }

    public CapturedPacket? WaitForReply(ushort gamePort, TimeSpan timeout)
    {
        var result = _captureTask.WaitAsync(timeout).GetAwaiter().GetResult();
        return result;
    }

    private CapturedPacket? ReceiveLoop()
    {
        var buffer = new byte[65535];
        while (true)
        {
            EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            var received = _socket.ReceiveFrom(buffer, ref from);
            if (!Packets.TryParseUdp(buffer, received, out var srcIp, out var dstIp, out var srcPort, out var dstPort, out _))
                continue;

            if (!IPAddress.IsLoopback(srcIp))
                continue;

            return new CapturedPacket(srcIp, srcPort, dstIp, dstPort);
        }
    }

    public void Dispose() => _socket.Dispose();
}

internal sealed record CapturedPacket(IPAddress SourceIp, ushort SourcePort, IPAddress DestinationIp, ushort DestinationPort);
