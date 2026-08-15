using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using Proxify.Common;

Console.OutputEncoding = Encoding.UTF8;

var cli = new ArgParser("Proxy.Server")
    .Add("port", "UDP-порт, на который подключаются клиенты игры", required: true, shortName: 'p')
    .Add("client", "Адрес прокси-клиента (машина B) в виде ip:port", required: true, shortName: 'c')
    .Add("key", "Ключ шифрования (одинаковый у сервера и клиента). Если задан — кадры шифруются AES-256-GCM", shortName: 'k');

if (!cli.TryParse(args))
{
    Console.WriteLine($"[ошибка конфигурации] {cli.Error}");
    cli.PrintUsage();
    return 1;
}
if (cli.HelpRequested)
    return 0;

int listenPort;
if (!NetUtils.TryParsePort(cli.Get("port"), out listenPort))
{
    Console.WriteLine($"[ошибка конфигурации] '--port {cli.Get("port")}' не является допустимым (ожидается число от 1 до 65535).");
    cli.PrintUsage();
    return 1;
}

IPEndPoint proxyClient;
if (!NetUtils.TryParseEndpoint(cli.Get("client"), out proxyClient))
{
    Console.WriteLine($"[ошибка конфигурации] '--client {cli.Get("client")}' не распознан (ожидается 'ip:port').");
    cli.PrintUsage();
    return 1;
}

string? key = cli.Get("key");
TunnelCipher? cipher = string.IsNullOrEmpty(key) ? null : TunnelCipher.FromPassphrase(key);

Console.WriteLine("=== Прокси-сервер (RealIP) ===");
Console.WriteLine($"Порт для клиентов игры    : {listenPort}");
Console.WriteLine($"Прокси-клиент (машина B)  : {proxyClient}");
Console.WriteLine($"Шифрование туннеля        : {(cipher != null ? "вкл (AES-256-GCM)" : "выкл")}");
Console.WriteLine();

var stats = new TunnelStats();
var seenClients = new ConcurrentDictionary<IPEndPoint, byte>();
int proxyClientContacted = 0;

using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, listenPort));
using var statsTimer = new Timer(_ => stats.Print("прокси-сервер"), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));

Console.WriteLine("Ожидание пакетов от клиентов игры...");
Console.WriteLine("При запуске прокси-клиент отправит PING — сервер ответит PONG и выведет");
Console.WriteLine("диагностику первого контакта.");
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

    _ = HandlePacket(result.RemoteEndPoint, result.Buffer);
}

return 0;

async Task HandlePacket(IPEndPoint from, byte[] data)
{
    try
    {
        byte? frameType = Frame.PeekFrameType(data, data.Length);

        // --- Служебные кадры диагностики (PING/PONG) ---
        if (frameType == Frame.TypePing)
        {
            if (Frame.TryDecodeControl(data, data.Length, Frame.TypePing, cipher, out var token))
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] PING от {from} — прокси-клиент на связи.");
                await udp.SendAsync(Frame.EncodeControl(Frame.TypePong, token, cipher), from);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] PONG отправлен {from}.");
            }
            else
            {
                Interlocked.Increment(ref stats.BadFrames);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] PING от {from} не разобран (возможно, несовпадение ключа).");
            }
            return;
        }
        if (frameType == Frame.TypePong)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Неожиданный PONG от {from} — игнорирую.");
            return;
        }

        if (from.Equals(proxyClient))
        {
            // Кадр от прокси-клиента (ответ игрового сервера) -> переслать реальному клиенту.
            if (Interlocked.Exchange(ref proxyClientContacted, 1) == 0)
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Первый кадр от прокси-клиента {from}.");

            if (frameType == Frame.TypeData && cipher != null)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен незашифрованный кадр, но шифрование включено. Проверьте ключ у прокси-клиента.");
                Interlocked.Increment(ref stats.BadFrames);
                return;
            }
            if (frameType == Frame.TypeDataEncrypted && cipher == null)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен зашифрованный кадр, но ключ не задан. Запустите с тем же ключом, что и прокси-клиент.");
                Interlocked.Increment(ref stats.BadFrames);
                return;
            }

            if (Frame.TryDecodeData(data, data.Length, cipher, out var clientIp, out ushort clientPort, out var payload))
            {
                var target = new IPEndPoint(clientIp, clientPort);
                Interlocked.Increment(ref stats.PacketsIn);
                Interlocked.Increment(ref stats.RepliesRelayed);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ответ ->] {target} ({payload.Length} байт)");
                await udp.SendAsync(payload, target);
            }
            else
            {
                Interlocked.Increment(ref stats.BadFrames);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать кадр от {from}.");
            }
        }
        else
        {
            // Пакет от реального клиента -> завернуть в кадр и отправить прокси-клиенту.
            if (seenClients.TryAdd(from, 0))
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Новый игрок подключился: {from}.");
            Interlocked.Increment(ref stats.PacketsIn);
            Interlocked.Increment(ref stats.PacketsOut);
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
