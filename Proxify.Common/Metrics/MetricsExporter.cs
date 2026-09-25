using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Proxify.Common.Metrics;

/// <summary>
/// Экспортёр метрик Prometheus: отдаёт текстовый формат exposition по HTTP на
/// указанный порт (<c>GET /metrics</c>).
///
/// Слушатель сделан на голом <see cref="TcpListener"/> с минимальным разбором
/// HTTP/1.1, а не на <see cref="HttpListener"/>, потому что последний на Windows
/// требует зарегистрированного URL-ACL для привязки ко всем интерфейсам, а на
/// Linux ведёт себя иначе. Здесь ровно то, что нужно сборщику Prometheus: GET,
/// заголовки, тело ответа — и ничего больше.
///
/// Экземпляр создаётся только если порт задан в аргументах запуска; иначе
/// метрики остаются выключенными (см. <see cref="TryStart"/>).
/// </summary>
public sealed class MetricsExporter : IDisposable
{
    /// <summary>Путь, который отдаёт метрики (совпадает с metrics_path Prometheus).</summary>
    public const string MetricsPath = "/metrics";

    /// <summary>Путь для проверки живости процесса (healthcheck, blackbox exporter).</summary>
    public const string HealthPath = "/-/healthy";

    private const int MaxRequestLineLength = 1024;
    private const int ReadTimeoutMicroseconds = 10_000_000;
    private const int DrainTimeoutMicroseconds = 250_000;
    private const int MaxDrainRounds = 4;
    private const int SendTimeoutMilliseconds = 10_000;
    private static readonly byte[] OkBody = "ok\n"u8.ToArray();
    private static readonly byte[] NotFoundBody = "метрики: /metrics\n"u8.ToArray();
    private static readonly byte[] BadRequestBody = "неполный запрос\n"u8.ToArray();
    private static readonly byte[] MethodBody = "допустим только GET\n"u8.ToArray();
    private static readonly byte[] ErrorBody = "сбор метрик не удался\n"u8.ToArray();

    private static readonly double[] ScrapeDurationBounds =
        { 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 };

    private readonly TcpListener _listener;
    private readonly TunnelMetrics _metrics;
    private readonly Gauge.Child _exporterUp;
    private readonly Counter.Child _scrapes;
    private readonly Counter.Child _scrapeErrors;
    private readonly Histogram.Child _scrapeDuration;
    private readonly CancellationTokenSource _shutdown = new();
    private int _disposed;

    private MetricsExporter(TcpListener listener, int port, TunnelMetrics metrics,
        Gauge exporterUp, Counter scrapes, Counter scrapeErrors, Histogram scrapeDuration)
    {
        _listener = listener;
        Port = port;
        _metrics = metrics;
        _exporterUp = exporterUp.For();
        _exporterUp.Set(1);
        _scrapes = scrapes.For();
        _scrapeErrors = scrapeErrors.For();
        _scrapeDuration = scrapeDuration.For();
    }

    /// <summary>Порт, на котором слушает экспортёр.</summary>
    public int Port { get; }

    /// <summary>Адрес для настройки Prometheus.</summary>
    public string Url => $"http://{DescribeHost()}:{Port.ToString(CultureInfo.InvariantCulture)}{MetricsPath}";

    /// <summary>
    /// Запускает экспортёр, если задан корректный порт. Без аргумента запуска
    /// (<c>--metrics-port</c>) возвращает null — метрики выключены.
    ///
    /// Параметр <paramref name="metricsPort"/> null или 0 означает «метрики не
    /// запрошены». Порт вне 1..65535 — ошибка запуска.
    /// </summary>
    /// <exception cref="InvalidOperationException">Порт занят другим процессом.</exception>
    public static MetricsExporter? TryStart(TunnelMetrics metrics, int? metricsPort)
    {
        if (metricsPort is null or 0)
            return null;

        var port = metricsPort.Value;
        if (port is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(metricsPort), port, "Порт метрик должен быть в диапазоне 1..65535.");

        var listener = new TcpListener(IPAddress.Any, port);
        try
        {
            listener.Start();
        }
        catch (SocketException ex)
        {
            listener.Dispose();
            throw new InvalidOperationException($"Не удалось занять порт метрик {port}: {ex.Message}", ex);
        }

        var boundPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var registry = metrics.Registry;

        var exporter = new MetricsExporter(
            listener,
            boundPort,
            metrics,
            registry.Gauge("proxify_metrics_up", "1, если эндпоинт метрик работает и отдаёт данные."),
            registry.Counter("proxify_metrics_scrapes_total", "Успешных сборов метрик Prometheus."),
            registry.Counter("proxify_metrics_scrape_errors_total", "Неудачных сборов метрик Prometheus."),
            registry.Histogram("proxify_metrics_scrape_duration_seconds",
                "Длительность сборов метрик, секунды.", ScrapeDurationBounds));

        metrics.EnableSampling();
        metrics.ExpositionUrl = exporter.Url;
        _ = Task.Run(exporter.AcceptLoopAsync);
        return exporter;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        _exporterUp.Set(0);
        _shutdown.Cancel();
        try
        {
            _listener.Stop();
        }
        catch (SocketException)
        {
            // слушатель уже остановлен
        }
        _listener.Dispose();
        _shutdown.Dispose();
    }

    private async Task AcceptLoopAsync()
    {
        var token = _shutdown.Token;
        while (!token.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException ex)
            {
                if (token.IsCancellationRequested)
                    break;
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [warn] Метрики: ошибка приёма соединения: {ex.Message}");
                continue;
            }

            // Сбор короткий и синхронный, поэтому соединения обслуживаются в
            // пуле потоков. Таймауты ожидания задаются через Socket.Poll: отмена
            // ожидающей операции чтения рвёт сокет, и ответ уже не отправить.
            client.NoDelay = true;
            client.SendTimeout = SendTimeoutMilliseconds;

            _ = Task.Run(() => Handle(client));
        }
    }

    private void Handle(TcpClient client)
    {
        using (client)
        {
            try
            {
                var requestLine = ReadRequestLine(client);
                if (requestLine == null)
                {
                    WriteStatus(client, 400, "Bad Request", "text/plain; charset=utf-8", BadRequestBody);
                    return;
                }

                var (method, path) = ParseRequestLine(requestLine);
                if (method is not ("GET" or "HEAD"))
                {
                    WriteStatus(client, 405, "Method Not Allowed", "text/plain; charset=utf-8", MethodBody);
                    return;
                }

                switch (path)
                {
                    case MetricsPath or MetricsPath + "/":
                        WriteMetrics(client, method == "HEAD");
                        return;
                    case HealthPath or "/healthz":
                        WriteStatus(client, 200, "OK", "text/plain; charset=utf-8", OkBody);
                        return;
                    default:
                        WriteStatus(client, 404, "Not Found", "text/plain; charset=utf-8", NotFoundBody);
                        return;
                }
            }
            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
            {
                // оборванное соединение клиента
            }
            catch (Exception ex)
            {
                _scrapeErrors.Inc();
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [warn] Метрики: ошибка обслуживания запроса: {ex.Message}");
            }
        }
    }

    private void WriteMetrics(TcpClient client, bool headOnly)
    {
        var stopwatch = Stopwatch.StartNew();
        string body;
        try
        {
            body = _metrics.Registry.Scrape();
        }
        catch (Exception ex)
        {
            _scrapeErrors.Inc();
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [warn] Метрики: сбор не удался: {ex.Message}");
            WriteStatus(client, 500, "Internal Server Error", "text/plain; charset=utf-8", ErrorBody);
            return;
        }
        finally
        {
            stopwatch.Stop();
            _scrapeDuration.Observe(stopwatch.Elapsed.TotalSeconds);
        }

        _scrapes.Inc();
        var payload = Encoding.UTF8.GetBytes(body);
        WriteResponse(client, 200, "OK", MetricsExposition.ContentType, payload, headOnly);
    }

    /// <summary>
    /// Читает строку запроса и отбрасывает остальные заголовки. Тело запроса не
    /// читается: сборщик Prometheus его не присылает, а Keep-Alive не
    /// поддерживается — ответ всегда закрывает соединение.
    /// </summary>
    private static string? ReadRequestLine(TcpClient client)
    {
        var stream = client.GetStream();
        var buffer = new byte[512];
        var request = new StringBuilder();
        var skipNext = false;

        while (true)
        {
            if (!WaitForData(client, ReadTimeoutMicroseconds))
                return null;

            int read;
            try
            {
                read = stream.Read(buffer, 0, buffer.Length);
            }
            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
            {
                return null;
            }

            if (read <= 0)
                return null;

            for (var i = 0; i < read; i++)
            {
                var c = (char)buffer[i];
                if (c == '\n')
                    return request.Length > 0 ? request.ToString() : null;
                if (c == '\r')
                {
                    skipNext = true;
                    continue;
                }
                if (skipNext)
                {
                    skipNext = false;
                    continue;
                }

                request.Append(c);
                if (request.Length > MaxRequestLineLength)
                    return null; // не запрос, а мусор: не тратим время дальше
            }
        }
    }

    private static (string Method, string Path) ParseRequestLine(string requestLine)
    {
        var firstSpace = requestLine.IndexOf(' ');
        if (firstSpace <= 0)
            return ("GET", MetricsPath);

        var method = requestLine[..firstSpace];
        var rest = requestLine[(firstSpace + 1)..].TrimStart();

        var end = rest.IndexOf(' ');
        var target = end > 0 ? rest[..end] : rest;

        var query = target.IndexOf('?');
        if (query >= 0)
            target = target[..query];

        return (method, target);
    }

    /// <summary>
    /// Ждёт появления данных в сокете не дольше указанного времени. false — данных
    /// не было (таймаут) либо соединение закрыто.
    /// </summary>
    private static bool WaitForData(TcpClient client, int timeoutMicroseconds)
    {
        try
        {
            if (!client.Client.Poll(timeoutMicroseconds, SelectMode.SelectRead))
                return false;
            return client.Available > 0;
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            return false;
        }
    }

    /// <summary>
    /// Досчитывает и отбрасывает остаток запроса (заголовки, тело). Без этого
    /// закрытие сокета на непрочитанных данных приводит к RST, который сборщик
    /// Prometheus может увидеть вместо ответа. Число раундов ограничено, чтобы
    /// клиент, шлющий бесконечный поток, не держал соединение.
    /// </summary>
    private static void Drain(TcpClient client)
    {
        var buffer = new byte[1024];
        try
        {
            for (var round = 0; round < MaxDrainRounds; round++)
            {
                if (!WaitForData(client, DrainTimeoutMicroseconds))
                    return;
                if (client.GetStream().Read(buffer, 0, buffer.Length) <= 0)
                    return;
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            // клиент закрыл соединение сам — это нормально
        }
    }

    private static void WriteStatus(TcpClient client, int statusCode, string reason, string contentType, byte[] body)
    {
        try
        {
            Drain(client);
            WriteResponse(client, statusCode, reason, contentType, body, false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or SocketException)
        {
            // клиент оборвал соединение — ничего не предпринимаем
        }
    }

    private static void WriteResponse(TcpClient client, int statusCode, string reason, string contentType,
        byte[] body, bool headOnly)
    {
        var head = new StringBuilder(192);
        head.Append("HTTP/1.1 ").Append(statusCode).Append(' ').Append(reason).Append("\r\n");
        head.Append("Content-Type: ").Append(contentType).Append("\r\n");
        head.Append("Content-Length: ").Append(body.Length.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
        head.Append("Connection: close\r\n\r\n");

        var stream = client.GetStream();
        stream.Write(Encoding.ASCII.GetBytes(head.ToString()));
        if (!headOnly && body.Length > 0)
            stream.Write(body);
        stream.Flush();
    }

    private string DescribeHost()
    {
        // Адрес для подсказки в баннере: тот, что доступен с машины Prometheus.
        try
        {
            foreach (var address in Dns.GetHostAddresses(Dns.GetHostName()))
            {
                if (address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(address))
                    return address.ToString();
            }
        }
        catch (SocketException)
        {
            // имя хоста не разрешилось — подскажем localhost
        }

        return "localhost";
    }
}
