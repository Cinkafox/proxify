using System.Net.Sockets;
using System.Text;
using Proxify.Common.Metrics;

namespace Proxify.SelfTest;

/// <summary>
/// Самопроверка подсистемы метрик: формат exposition Prometheus, корректность
/// счётчиков, гауже и гистограмм, работа HTTP-эндпоинта. Прав администратора не
/// требует, поэтому выполняется даже там, где RawSocket-проверки недоступны.
/// Возвращает число проваленных проверок.
/// </summary>
internal static class MetricsSelfTest
{
    public static int Run()
    {
        var failures = 0;

        Console.WriteLine("=== Самопроверка метрик Prometheus ===");

        failures += CheckExpositionFormat();
        failures += CheckOrderingAndEscaping();
        failures += CheckShortLabelValues();
        failures += CheckCounterAndGauge();
        failures += CheckHistogram();
        failures += CheckDetachedSeries();
        failures += CheckServerLabels();
        failures += CheckExporterDisabled();
        failures += CheckHttpEndpoints();

        Console.WriteLine();
        return failures;
    }

    private static int CheckExpositionFormat()
    {
        Console.WriteLine("[1] Формат exposition: HELP, TYPE, образцы");
        var registry = new MetricsRegistry();
        var counter = registry.Counter("test_requests_total", "Счётчик запросов.", "route");
        counter.For("/a").Inc(3);
        counter.For("/b").Inc();

        var gauge = registry.Gauge("test_up", "Работает ли процесс.");
        gauge.For().Set(1);

        var text = registry.Scrape();
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        return Expect(
            lines.Contains("# HELP test_requests_total Счётчик запросов.")
            && lines.Contains("# TYPE test_requests_total counter")
            && lines.Contains("# TYPE test_up gauge")
            && lines.Contains("test_requests_total{route=\"/a\"} 3")
            && lines.Contains("test_requests_total{route=\"/b\"} 1")
            && lines.Contains("test_up 1")
            && text.EndsWith('\n'),
            "экспозиция содержит корректные строки HELP/TYPE и образцы");
    }

    private static int CheckOrderingAndEscaping()
    {
        Console.WriteLine("[2] Порядок серий и экранирование меток");
        var registry = new MetricsRegistry();
        var counter = registry.Counter("test_escaped_total", "Экранирование.", "note");
        counter.For("просто \"кавычки\" и \\слеш\\").Inc();
        counter.For("строка\nс переводом").Inc();
        counter.For("zzz").Inc();
        counter.For("aaa").Inc();

        var lines = registry.Scrape().Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Where(l => l.StartsWith("test_escaped_total{", StringComparison.Ordinal))
            .ToArray();

        // Порядок по ключу серии: длина значения входит в ключ, поэтому "zzz" идёт
        // раньше "aaa" — главное, что порядок стабильный между сборами.
        var first = string.Join('|', lines);
        var second = string.Join('|', registry.Scrape().Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Where(l => l.StartsWith("test_escaped_total{", StringComparison.Ordinal)));
        var escaped = lines.Any(l => l.Contains("\\\""))
                       && lines.Any(l => l.Contains("\\\\"))
                       && lines.Any(l => l.Contains("\\n"));

        return Expect(
            first == second && escaped && lines.Length == 4,
            "порядок серий стабилен, кавычки/слеши/переводы строк экранированы");
    }

    private static int CheckShortLabelValues()
    {
        Console.WriteLine("[3] For() с неполным набором значений меток");
        var registry = new MetricsRegistry();
        var counter = registry.Counter("test_short_total", "Неполные метки.", "a", "b");
        counter.For("только-одна").Inc();
        counter.For().Inc();
        counter.For("лишние", "значения", "сверх").Inc();

        var text = registry.Scrape();
        return Expect(
            text.Contains("test_short_total{a=\"только-одна\",b=\"\"} 1")
            && text.Contains("test_short_total{a=\"\",b=\"\"} 1")
            && text.Contains("test_short_total{a=\"лишние\",b=\"значения\"} 1"),
            "значения приводятся к числу объявленных меток, лишние отбрасываются");
    }

    private static int CheckCounterAndGauge()
    {
        Console.WriteLine("[4] Счётчики и гаужи");
        var registry = new MetricsRegistry();
        var counter = registry.Counter("test_count_total", "Счётчик.");
        var gauge = registry.Gauge("test_value", "Гау.");

        var child = counter.For();
        for (var i = 0; i < 1000; i++)
            child.Inc(2);
        child.Inc();
        child.Reset();
        child.Inc(7);

        // Сложение double: наивный Interlocked.Add по битам дал бы мусор.
        var value = gauge.For();
        value.Set(0.1);
        value.Add(0.2);
        var sum = value.Value;
        value.Inc();
        value.Inc();
        value.Dec();

        return Expect(
            child.Value == 7
            && Math.Abs(sum - 0.3) < 1e-9
            && Math.Abs(value.Value - 1.3) < 1e-9
            && registry.Scrape().Contains("test_count_total 7"),
            "Inc/Reset у счётчика и Set/Add/Inc/Dec у гаужа дают верные значения");
    }

    private static int CheckHistogram()
    {
        Console.WriteLine("[5] Гистограмма");
        var registry = new MetricsRegistry();
        var histogram = registry.Histogram("test_size_bytes", "Размеры.", new[] { 10d, 100d }, "kind");
        var child = histogram.For("in");
        child.Observe(5);
        child.Observe(50);
        child.Observe(500);

        var text = registry.Scrape();
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        return Expect(
            lines.Contains("# TYPE test_size_bytes histogram")
            && lines.Contains("test_size_bytes_bucket{kind=\"in\",le=\"10\"} 1")
            && lines.Contains("test_size_bytes_bucket{kind=\"in\",le=\"100\"} 2")
            && lines.Contains("test_size_bytes_bucket{kind=\"in\",le=\"+Inf\"} 3")
            && lines.Contains("test_size_bytes_count{kind=\"in\"} 3")
            && lines.Contains("test_size_bytes_sum{kind=\"in\"} 555")
            && !lines.Any(l => l.Contains("test_size_bytes_bucket{kind=\"in\"}{")),
            "бакеты накопительные, есть _sum/_count, метки не дублируются");
    }

    private static int CheckDetachedSeries()
    {
        Console.WriteLine("[6] Отключённые серии не попадают в экспозицию");
        var registry = new MetricsRegistry();
        var counter = registry.Counter("test_detached_total", "Метка правила.", "client");
        counter.Detached.Inc(5);

        var samples = registry.Scrape().Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Where(l => !l.StartsWith('#'))
            .ToArray();
        return Expect(
            samples.Length == 0,
            "инкремент отключённой серии не создаёт ряд");
    }

    private static int CheckServerLabels()
    {
        Console.WriteLine("[7] Серверная роль: ряды по правилам и ручка процесса");
        using var metrics = new TunnelMetrics(MetricsRole.Server, perClientLabels: true);
        var first = metrics.ForClient("client1");
        first.CountPacketsIn(30);
        first.CountPacketsIn(700);
        first.CountRepliesCaptured();
        metrics.ForClient("client2").CountPacketsOut(50);
        metrics.Process.SetQueueDepth(7);

        var text = metrics.Registry.Scrape();
        return Expect(
            text.Contains("proxify_tunnel_packets_in_total{client=\"client1\"} 2")
            && text.Contains("proxify_tunnel_bytes_in_total{client=\"client1\"} 730")
            && text.Contains("proxify_tunnel_replies_captured_total{client=\"client1\"} 1")
            && text.Contains("proxify_tunnel_bytes_out_total{client=\"client2\"} 50")
            && text.Contains("proxify_tunnel_frame_bytes_count{client=\"client1\"} 2")
            && text.Contains("proxify_tunnel_work_queue_depth 7")
            && !text.Contains("client=\"\"")
            && !text.Contains("client=\"(процесс)\""),
            "метки правил есть, у ручки процесса лишних рядов нет");
    }

    private static int CheckExporterDisabled()
    {
        Console.WriteLine("[8] Без --metrics-port экспорт не поднимается");
        using var metrics = new TunnelMetrics(MetricsRole.Client, perClientLabels: false);

        return Expect(
            MetricsExporter.TryStart(metrics, null) == null
            && MetricsExporter.TryStart(metrics, 0) == null
            && metrics.ExpositionUrl == null,
            "без порта (null или 0) экспортёр не создаётся");
    }

    private static int CheckHttpEndpoints()
    {
        Console.WriteLine("[9] HTTP-эндпоинты /metrics, /-/healthy, 404, 405");
        using var metrics = new TunnelMetrics(MetricsRole.Client, perClientLabels: false);
        metrics.ForClient("client").CountPacketsOut(20);

        // Порт 0 недопустим для экспортёра, поэтому свободный ищем сами.
        var port = FreeUdpLikePort();
        using var exporter = MetricsExporter.TryStart(metrics, port);
        if (exporter == null)
            return Fail("экспортёр не поднялся на свободном порту");

        var failures = 0;
        var response = Request(port, "/metrics");
        failures += Expect(
            response.Status == 200
            && response.Head.Contains("text/plain; version=0.0.4", StringComparison.Ordinal)
            && response.Body.Contains("proxify_up 1", StringComparison.Ordinal)
            && response.Body.Contains("proxify_tunnel_packets_out_total 1", StringComparison.Ordinal)
            && response.Body.Contains("proxify_tunnel_bytes_out_total 20", StringComparison.Ordinal)
            && response.Body.Contains("proxify_metrics_up 1", StringComparison.Ordinal),
            "GET /metrics отдаёт экспозицию с proxify_up и счётчиками");

        failures += Expect(Request(port, "/-/healthy").Status == 200, "GET /-/healthy отвечает 200");
        failures += Expect(Request(port, "/healthz").Status == 200, "GET /healthz отвечает 200");
        failures += Expect(Request(port, "/nope").Status == 404, "неизвестный путь отвечает 404");
        failures += Expect(Request(port, "/metrics", "POST").Status == 405, "POST отвечает 405");
        failures += Expect(Request(port, "/metrics?x=1").Status == 200
                           && Request(port, "/metrics?x=1").Body.Contains("proxify_up 1", StringComparison.Ordinal),
            "строка запроса отбрасывается");

        // HEAD должен вернуть заголовки без тела.
        var head = Request(port, "/metrics", "HEAD");
        failures += Expect(head.Status == 200
                           && !head.Body.Contains("proxify_up", StringComparison.Ordinal)
                           && head.Head.Contains("Content-Length:", StringComparison.Ordinal),
            "HEAD отдаёт заголовки без тела");

        failures += CheckLargeHeaders(port);
        failures += CheckParallelScrapes(port);

        return failures;
    }

    /// <summary>
    /// Запрос с заголовками больше одного буфера чтения: остаток запроса нужно
    /// дочитать, иначе закрытие сокета на непрочитанных данных приводит к RST и
    /// клиент видит «пустой ответ» вместо метрик.
    /// </summary>
    private static int CheckLargeHeaders(int port)
    {
        Console.WriteLine("[10] Запрос с большими заголовками");
        var padding = new string('x', 2000);
        var request = $"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Padding: {padding}\r\nAccept: */*\r\n\r\n";

        string body;
        int status;
        try
        {
            using var client = new TcpClient();
            client.SendTimeout = 5000;
            client.ReceiveTimeout = 5000;
            if (!client.ConnectAsync("127.0.0.1", port).Wait(TimeSpan.FromSeconds(5)))
                return Fail("не удалось подключиться");

            using var stream = client.GetStream();
            var bytes = Encoding.ASCII.GetBytes(request);
            stream.Write(bytes);
            stream.Flush();

            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            int read;
            while ((read = stream.Read(chunk, 0, chunk.Length)) > 0)
                buffer.Write(chunk, 0, read);

            var raw = Encoding.UTF8.GetString(buffer.ToArray());
            var separator = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            status = int.TryParse(raw.Split(' ')[1], out var code) ? code : 0;
            body = separator < 0 ? string.Empty : raw[(separator + 4)..];
        }
        catch (Exception ex) when (ex is SocketException or IOException)
        {
            return Fail("соединение оборвалось: " + ex.Message);
        }

        return Expect(status == 200 && body.Contains("proxify_up 1", StringComparison.Ordinal),
            "ответ доставлен целиком, соединение не сброшено");
    }

    /// <summary>Несколько одновременных сборов: каждый должен получить свой ответ.</summary>
    private static int CheckParallelScrapes(int port)
    {
        Console.WriteLine("[11] Параллельные запросы сборщика");
        const int clients = 8;
        var tasks = new Task<bool>[clients];
        for (var i = 0; i < clients; i++)
            tasks[i] = Task.Run(() => Request(port, "/metrics").Status == 200
                                    && Request(port, "/metrics").Body.Contains("proxify_up 1", StringComparison.Ordinal));

        return Expect(Task.WaitAll(tasks, TimeSpan.FromSeconds(20)) && tasks.All(t => t.Result),
            "все параллельные запросы получили ответ");
    }

    /// <summary>
    /// Минимальный HTTP-запрос через сокет: ответ читается целиком до конца,
    /// поскольку сервер закрывает соединение.
    /// </summary>
    private static (int Status, string Head, string Body) Request(int port, string path, string method = "GET")
    {
        try
        {
            using var client = new TcpClient();
            client.NoDelay = true;
            client.SendTimeout = 5000;
            client.ReceiveTimeout = 5000;
            if (!client.ConnectAsync("127.0.0.1", port).Wait(TimeSpan.FromSeconds(5)))
                return (0, string.Empty, string.Empty);

            var request = Encoding.ASCII.GetBytes(
                $"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUser-Agent: SelfTest\r\nAccept: */*\r\n\r\n");
            using var stream = client.GetStream();
            stream.Write(request);
            stream.Flush();

            using var buffer = new MemoryStream();
            var chunk = new byte[4096];
            int read;
            while ((read = stream.Read(chunk, 0, chunk.Length)) > 0)
                buffer.Write(chunk, 0, read);

            var raw = Encoding.UTF8.GetString(buffer.ToArray());
            var separator = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (separator < 0)
                return (0, raw, string.Empty);

            var head = raw[..separator];
            var statusLine = head.Split("\r\n")[0].Split(' ');
            return (statusLine.Length > 1 && int.TryParse(statusLine[1], out var code) ? code : 0,
                head, raw[(separator + 4)..]);
        }
        catch (Exception ex) when (ex is SocketException or IOException)
        {
            return (0, string.Empty, ex.Message);
        }
    }

    private static int FreeUdpLikePort()
    {
        // Экспортёр занимает TCP-порт, поэтому ищем свободный TCP.
        var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static int Expect(bool condition, string description)
    {
        if (condition)
        {
            Console.WriteLine("    OK: " + description + ".");
            return 0;
        }

        Console.WriteLine("    FAIL: " + description + ".");
        return 1;
    }

    private static int Fail(string description)
    {
        Console.WriteLine("    FAIL: " + description + ".");
        return 1;
    }
}
