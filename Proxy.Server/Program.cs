using System.Net;
using System.Net.Sockets;
using System.Text;
using Proxify.Common;

Console.OutputEncoding = Encoding.UTF8;

PrintUsage();

int listenPort = args.Length > 0 && int.TryParse(args[0], out int lp) ? lp : 27015;
IPEndPoint proxyClient = NetUtils.TryParseEndpoint(args.Length > 1 ? args[1] : null, out var pc)
    ? pc
    : new IPEndPoint(IPAddress.Loopback, 5600);

string? key = args.Length > 2 ? args[2] : null;
TunnelCipher? cipher = string.IsNullOrEmpty(key) ? null : TunnelCipher.FromPassphrase(key);

Console.WriteLine("=== Прокси-сервер (RealIP) ===");
Console.WriteLine($"Порт для клиентов игры    : {listenPort}");
Console.WriteLine($"Прокси-клиент (машина B)  : {proxyClient}");
Console.WriteLine($"Шифрование туннеля        : {(cipher != null ? "вкл (AES-256-GCM)" : "выкл")}");
Console.WriteLine();

using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, listenPort));
Console.WriteLine("Ожидание пакетов от клиентов игры...");
Console.WriteLine();

while (true)
{
    UdpReceiveResult result;
    try
    {
        result = await udp.ReceiveAsync();
    }
    catch (SocketException ex)
    {
        // Windows может вернуть WSAECONNRESET (10054) на UDP-сокете после ICMP
        // "порт недоступен" (например, если прокси-клиент ещё не запущен).
        // Такие ошибки преходящи — продолжаем принимать дальше.
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [warn] Ошибка приёма: {ex.Message}");
        continue;
    }
    catch (ObjectDisposedException)
    {
        break;
    }

    _ = HandlePacket(udp, result.RemoteEndPoint, result.Buffer, proxyClient, cipher);
}

static void PrintUsage()
{
    Console.WriteLine("Прокси-сервер: перенаправляет UDP-трафик клиентов игры прокси-клиенту,");
    Console.WriteLine("сохраняя настоящий IP клиента (подмена выполняется прокси-клиентом).");
    Console.WriteLine();
    Console.WriteLine("Использование: Proxy.Server [listenPort] [proxyClientIp:proxyClientPort] [key]");
    Console.WriteLine("  listenPort              - порт, на который подключаются клиенты игры (по умолч. 27015)");
    Console.WriteLine("  proxyClientIp:port      - адрес прокси-клиента на машине с игровым сервером (по умолч. 127.0.0.1:5600)");
    Console.WriteLine("  key                     - ключ шифрования (одинаковый у сервера и клиента). Если задан -");
    Console.WriteLine("                            кадры туннеля шифруются AES-256-GCM; если нет - без шифрования.");
    Console.WriteLine();
}

static async Task HandlePacket(UdpClient udp, IPEndPoint from, byte[] data, IPEndPoint proxyClient, TunnelCipher? cipher)
{
    try
    {
        if (from.Equals(proxyClient))
        {
            // Кадр от прокси-клиента (ответ игрового сервера) -> переслать реальному клиенту.
            byte? frameType = Frame.PeekFrameType(data, data.Length);
            if (frameType == Frame.TypeData && cipher != null)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен незашифрованный кадр, но шифрование включено. Проверьте ключ у прокси-клиента.");
                return;
            }
            if (frameType == Frame.TypeDataEncrypted && cipher == null)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен зашифрованный кадр, но ключ не задан. Запустите с тем же ключом, что и прокси-клиент.");
                return;
            }

            if (Frame.TryDecodeData(data, data.Length, cipher, out var clientIp, out ushort clientPort, out var payload))
            {
                var target = new IPEndPoint(clientIp, clientPort);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ответ ->] {target} ({payload.Length} байт)");
                await udp.SendAsync(payload, target);
            }
            else
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать кадр от {from}.");
            }
        }
        else
        {
            // Пакет от реального клиента -> завернуть в кадр и отправить прокси-клиенту.
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [клиент ->] {from} ({data.Length} байт)");
            var frame = Frame.EncodeData(from.Address, (ushort)from.Port, data, cipher);
            await udp.SendAsync(frame, proxyClient);
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] {ex.Message}");
    }
}
