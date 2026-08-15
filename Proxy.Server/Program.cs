using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using Proxify.Common;

Console.OutputEncoding = Encoding.UTF8;

var cli = new ArgParser("Proxy.Server")
    .Add("port", "UDP-порт, на который подключаются клиенты игры", required: true, shortName: 'p')
    .Add("key", "Ключ шифрования (одинаковый у сервера и клиента). Обязателен — кадры всегда шифруются AES-256-GCM", required: true, shortName: 'k');

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

string key = cli.Get("key")!;
if (string.IsNullOrWhiteSpace(key))
{
    Console.WriteLine("[ошибка конфигурации] '--key' не может быть пустым.");
    cli.PrintUsage();
    return 1;
}

var cipher = TunnelCipher.FromPassphrase(key);

Console.WriteLine("=== Прокси-сервер (RealIP) ===");
Console.WriteLine($"Порт для клиентов игры    : {listenPort}");
Console.WriteLine("Шифрование туннеля        : вкл (AES-256-GCM)");
Console.WriteLine();
Console.WriteLine("Адрес прокси-клиента определяется автоматически по первому кадру туннеля");
Console.WriteLine("(PING или данные) и обновляется при его изменении. Сервер принимает только");
Console.WriteLine("кадры, аутентифицированные ключом, поэтому подменить адрес туннеля нельзя.");
Console.WriteLine();
Console.WriteLine("Ожидание пакетов от клиентов игры...");
Console.WriteLine("При запуске прокси-клиент отправит PING — сервер ответит PONG и выведет");
Console.WriteLine("диагностику первого контакта.");
Console.WriteLine();

var stats = new TunnelStats();
var seenClients = new ConcurrentDictionary<IPEndPoint, byte>();

using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, listenPort));
using var statsTimer = new Timer(_ => stats.Print("прокси-сервер"), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));

// Текущий адрес прокси-клиента. Обучается динамически: сервер запоминает источник
// первого валидного кадра туннеля и обновляет его при изменении (перезапуск клиента,
// смена порта после NAT). Пока адрес не определён, пакеты игроков отбрасываются.
object endpointLock = new();
IPEndPoint? proxyClient = null;
long lastNoClientLogTicks = 0;

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

void LearnProxyClient(IPEndPoint from)
{
    bool changed;
    lock (endpointLock)
    {
        changed = proxyClient == null || !proxyClient.Equals(from);
        if (changed)
            proxyClient = from;
    }

    if (changed)
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Прокси-клиент (машина B) определён: {from}.");
}

IPEndPoint? CurrentProxyClient()
{
    lock (endpointLock)
    {
        return proxyClient;
    }
}

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
                LearnProxyClient(from);
                await udp.SendAsync(Frame.EncodeControl(Frame.TypePong, token, cipher), from);
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
            return;
        }

        // --- Кадры данных от прокси-клиента (ответы игрового сервера) ---
        if (frameType is Frame.TypeData or Frame.TypeDataEncrypted)
        {
            if (frameType == Frame.TypeData)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Получен незашифрованный кадр, но сервер работает только с шифрованием. Проверьте ключ у прокси-клиента.");
                Interlocked.Increment(ref stats.BadFrames);
                return;
            }

            if (Frame.TryDecodeData(data, data.Length, cipher, out var clientIp, out ushort clientPort, out var payload))
            {
                LearnProxyClient(from);
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
            return;
        }

        // --- Пакет от реального клиента игры -> завернуть в кадр и отправить прокси-клиенту ---
        var proxyClientEndpoint = CurrentProxyClient();
        if (proxyClientEndpoint == null)
        {
            long nowTicks = DateTime.UtcNow.Ticks;
            long prev = Interlocked.Read(ref lastNoClientLogTicks);
            if (nowTicks - prev >= TimeSpan.FromSeconds(5).Ticks)
            {
                Interlocked.CompareExchange(ref lastNoClientLogTicks, nowTicks, prev);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Прокси-клиент ещё не установил связь — пакеты от игроков отбрасываются.");
            }
            return;
        }

        if (seenClients.TryAdd(from, 0))
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [диагностика] Новый игрок подключился: {from}.");
        Interlocked.Increment(ref stats.PacketsIn);
        Interlocked.Increment(ref stats.PacketsOut);
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [клиент ->] {from} ({data.Length} байт)");
        var frame = Frame.EncodeData(from.Address, (ushort)from.Port, data, cipher);
        await udp.SendAsync(frame, proxyClientEndpoint);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [ошибка] {ex.Message}");
    }
}
