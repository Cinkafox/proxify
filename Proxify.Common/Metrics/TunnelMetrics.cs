using System.Collections.Concurrent;
using System.Reflection;

namespace Proxify.Common.Metrics;

/// <summary>
/// Роль процесса в схеме прокси. Попадает в метку <c>role</c> метрики
/// <c>proxify_build_info</c> и определяет, получает ли процесс метки
/// <c>client</c> на метриках туннеля.
/// </summary>
public enum MetricsRole
{
    /// <summary>Прокси-сервер (машина A): метрики помечаются именем правила клиента.</summary>
    Server,

    /// <summary>Прокси-клиент (машина B): в процессе одна сессия, метки не нужны.</summary>
    Client,
}

/// <summary>
/// Метрики туннеля: счётчики трафика, состояние сессий и распределение размеров
/// кадров. Заменяет прежнюю раз в минуту печатаемую строку статистики.
///
/// На прокси-сервере метрики помечаются именем правила (<c>client</c>) — имена
/// берутся из server.yml, поэтому кардинальность ограничена конфигом. На
/// прокси-клиенте в процессе одна сессия, и метки не используются вовсе.
///
/// Экземпляр создаётся всегда (счётчики дёшевы и не аллоцируют в горячем пути),
/// но экспорт включается отдельно — см. <see cref="MetricsExporter"/>. Если порт
/// экспорта не задан в аргументах запуска, счётчики никому не отдаются.
/// </summary>
public sealed class TunnelMetrics : IDisposable
{
    /// <summary>Имя метки с именем клиента (правила из server.yml).</summary>
    public const string ClientLabel = "client";

    /// <summary>Как часто обновляются «живые» гаужи (игроки, глубина очереди).</summary>
    public static readonly TimeSpan DefaultSamplingInterval = TimeSpan.FromSeconds(5);

    private static readonly double[] FrameSizeBounds =
        { 64, 128, 256, 512, 1024, 1400, 2048, 4096, 8192, 16384, 32768, 65536 };

    private readonly bool _labeled;
    private readonly TunnelMetricsHandle _shared;
    private readonly ConcurrentDictionary<string, TunnelMetricsHandle> _handles = new(StringComparer.Ordinal);
    private readonly List<Action> _refreshCallbacks = new();

    private readonly Counter _packetsIn;
    private readonly Counter _packetsOut;
    private readonly Counter _bytesIn;
    private readonly Counter _bytesOut;
    private readonly Counter _injected;
    private readonly Counter _repliesCaptured;
    private readonly Counter _repliesRelayed;
    private readonly Counter _badFrames;
    private readonly Gauge _authorized;
    private readonly Gauge _players;
    private readonly Gauge _queueDepth;
    private readonly Histogram _frameBytes;

    private readonly object _sync = new();
    private Timer? _sampler;
    private int _sampling;
    private int _disposed;

    public TunnelMetrics(MetricsRole role, bool perClientLabels, MetricsRegistry? registry = null)
    {
        Registry = registry ?? new MetricsRegistry();
        Role = role;
        _labeled = perClientLabels;

        var labels = perClientLabels ? new[] { ClientLabel } : Array.Empty<string>();

        _packetsIn = Registry.Counter("proxify_tunnel_packets_in_total",
            "Принято пакетов и кадров (от игроков и из туннеля).", labels);
        _packetsOut = Registry.Counter("proxify_tunnel_packets_out_total",
            "Отправлено кадров в туннель прокси-клиенту.", labels);
        _bytesIn = Registry.Counter("proxify_tunnel_bytes_in_total",
            "Принято байт трафика (полезная нагрузка входящих пакетов и кадров).", labels);
        _bytesOut = Registry.Counter("proxify_tunnel_bytes_out_total",
            "Отправлено байт трафика в туннель (размер кадров на проводе).", labels);
        _injected = Registry.Counter("proxify_tunnel_frames_injected_total",
            "Кадров, впрыснуто в игру (передано игровому серверу).", labels);
        _repliesCaptured = Registry.Counter("proxify_tunnel_replies_captured_total",
            "Перехвачено ответов игрового сервера (UDP-правило с захватом).", labels);
        _repliesRelayed = Registry.Counter("proxify_tunnel_replies_relayed_total",
            "Ответов доставлено игроку.", labels);
        _badFrames = Registry.Counter("proxify_tunnel_bad_frames_total",
            "Кадров туннеля, которые не удалось разобрать или проверить.", labels);
        _authorized = Registry.Gauge("proxify_tunnel_authorized",
            "1, если сессия туннеля авторизована, иначе 0.", labels);
        _players = Registry.Gauge("proxify_tunnel_players",
            "Известных игроков (UDP) или активных соединений (TCP).", labels);
        // Очередь общая для всего процесса, поэтому метки правила не имеет.
        _queueDepth = Registry.Gauge("proxify_tunnel_work_queue_depth",
            "Задач, ожидающих в очереди фоновой обработки.");
        _frameBytes = Registry.Histogram("proxify_tunnel_frame_bytes",
            "Распределение размеров кадров туннеля, байт.", FrameSizeBounds, labels);

        // Метрики уровня процесса: меток не имеют, потому что не относятся к правилу.
        var up = Registry.Gauge("proxify_up", "1, если процесс прокси работает и обслуживает туннель.");
        Up = up.For();
        Up.Set(1);

        var startTime = Registry.Gauge("proxify_start_time_seconds", "Момент запуска процесса прокси (Unix-время, секунды).");
        StartTime = startTime.For();
        StartTime.Set(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000d);

        Registry.Gauge("proxify_build_info", "Сборка и роль процесса прокси; значение всегда 1.",
                "version", "role")
            .For(DetectVersion(), Role == MetricsRole.Server ? "server" : "client")
            .Set(1);

        TunnelPort = Registry.Gauge("proxify_tunnel_port", "Порт туннеля, объявленный в аргументах запуска.").For();
        UnauthorizedFrames = Registry.Counter("proxify_tunnel_unauthorized_frames_total",
            "Кадров туннеля, не прошедших авторизацию (ни один зарегистрированный ключ не подошёл).").For();

        // Безымянная конфигурация (прокси-клиент) обслуживается одной общей ручкой.
        _shared = CreateHandle(Array.Empty<string>());
    }

    /// <summary>Реестр метрик: его отдаёт наружу экспортёр.</summary>
    public MetricsRegistry Registry { get; }

    public MetricsRole Role { get; }

    /// <summary>1, пока процесс жив.</summary>
    public Gauge.Child Up { get; }

    /// <summary>Момент запуска процесса (Unix-время, секунды).</summary>
    public Gauge.Child StartTime { get; }

    /// <summary>Порт туннеля.</summary>
    public Gauge.Child TunnelPort { get; }

    /// <summary>Кадры, отклонённые как неавторизованные (уровень процесса).</summary>
    public Counter.Child UnauthorizedFrames { get; }

    /// <summary>
    /// true, если метрики экспортируются. Ставится стартером экспортёра; без
    /// него счётчики накапливаются, но никому не отдаются.
    /// </summary>
    public bool Enabled { get; private set; }

    /// <summary>
    /// Адрес экспорта метрик (null, если метрики выключены). Задаётся
    /// экспортёром при старте.
    /// </summary>
    public string? ExpositionUrl { get; internal set; }

    /// <summary>
    /// Ручка метрик одного правила (прокси-сервер) либо единственная ручка
    /// процесса (прокси-клиент). На сервере ручки кэшируются по имени правила,
    /// поэтому метки в горячем пути не вычисляются заново.
    /// </summary>
    public TunnelMetricsHandle ForClient(string name)
    {
        if (!_labeled)
            return _shared;

        return _handles.GetOrAdd(name, _ => CreateHandle(new[] { name }));
    }

    /// <summary>Ручка метрик уровня процесса (на сервере — без метки client).</summary>
    public TunnelMetricsHandle Process => _shared;

    /// <summary>
    /// Регистрирует обновление «живых» гаужей (игроков, глубины очереди).
    /// Обновления выполняются только если включён экспорт.
    /// </summary>
    public void AddRefreshCallback(Action callback)
    {
        lock (_sync)
            _refreshCallbacks.Add(callback);
    }

    /// <summary>
    /// Включает периодический опрос значений. Вызывается при старте экспортёра;
    /// повторный вызов игнорируется.
    /// </summary>
    public void EnableSampling(TimeSpan? interval = null)
    {
        lock (_sync)
        {
            if (Enabled || _disposed != 0)
                return;

            Enabled = true;
            var period = interval ?? DefaultSamplingInterval;
            _sampler = new Timer(_ => Sample(), null, period, period);
        }
    }

    /// <summary>Однократно опрашивает зарегистрированные источники значений.</summary>
    public void SampleNow() => Sample();

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        Timer? sampler;
        lock (_sync)
        {
            sampler = _sampler;
            _sampler = null;
            Enabled = false;
        }
        sampler?.Dispose();
        Up.Set(0);
    }

    private void Sample()
    {
        // Источники не должны накладываться: иначе опрос задерживается и счётчики
        // «живых» величин отстают.
        if (Interlocked.Exchange(ref _sampling, 1) != 0)
            return;

        try
        {
            Action[] callbacks;
            lock (_sync)
                callbacks = _refreshCallbacks.ToArray();

            foreach (var callback in callbacks)
            {
                try
                {
                    callback();
                }
                catch
                {
                    // Ошибка опроса не должна влиять на работу прокси: гаужи
                    // просто обновятся при следующем тике.
                }
            }
        }
        finally
        {
            Interlocked.Exchange(ref _sampling, 0);
        }
    }

    private TunnelMetricsHandle CreateHandle(string[] labels)
    {
        // На сервере метрики помечены именем правила. Ручке уровня процесса для
        // них соответствуют отключённые серии: пустые ряды с пустой меткой в
        // экспозиции только мешали бы.
        if (_labeled && labels.Length == 0)
        {
            return new TunnelMetricsHandle(
                "(процесс)",
                _packetsIn.Detached,
                _packetsOut.Detached,
                _bytesIn.Detached,
                _bytesOut.Detached,
                _injected.Detached,
                _repliesCaptured.Detached,
                _repliesRelayed.Detached,
                _badFrames.Detached,
                _authorized.Detached,
                _players.Detached,
                _queueDepth.For(),
                _frameBytes.Detached);
        }

        return new TunnelMetricsHandle(
            labels.Length == 0 ? "(процесс)" : labels[0],
            _packetsIn.For(labels),
            _packetsOut.For(labels),
            _bytesIn.For(labels),
            _bytesOut.For(labels),
            _injected.For(labels),
            _repliesCaptured.For(labels),
            _repliesRelayed.For(labels),
            _badFrames.For(labels),
            _authorized.For(labels),
            _players.For(labels),
            _queueDepth.For(),
            _frameBytes.For(labels));
    }

    private static string DetectVersion()
    {
        var informational = Assembly.GetEntryAssembly()?
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;

        if (string.IsNullOrWhiteSpace(informational))
            return "dev";

        var plus = informational.IndexOf('+');
        return plus > 0 ? informational[..plus] : informational;
    }
}

/// <summary>
/// Ручка метрик одного правила (или всего процесса, если метки не используются).
/// Все методы потокобезопасны и не аллоцируют: их можно вызывать на каждый пакет.
/// </summary>
public sealed class TunnelMetricsHandle
{
    private readonly Counter.Child _packetsIn;
    private readonly Counter.Child _packetsOut;
    private readonly Counter.Child _bytesIn;
    private readonly Counter.Child _bytesOut;
    private readonly Counter.Child _injected;
    private readonly Counter.Child _repliesCaptured;
    private readonly Counter.Child _repliesRelayed;
    private readonly Counter.Child _badFrames;
    private readonly Gauge.Child _authorized;
    private readonly Gauge.Child _players;
    private readonly Gauge.Child _queueDepth;
    private readonly Histogram.Child _frameBytes;

    internal TunnelMetricsHandle(
        string label,
        Counter.Child packetsIn,
        Counter.Child packetsOut,
        Counter.Child bytesIn,
        Counter.Child bytesOut,
        Counter.Child injected,
        Counter.Child repliesCaptured,
        Counter.Child repliesRelayed,
        Counter.Child badFrames,
        Gauge.Child authorized,
        Gauge.Child players,
        Gauge.Child queueDepth,
        Histogram.Child frameBytes)
    {
        Label = label;
        _packetsIn = packetsIn;
        _packetsOut = packetsOut;
        _bytesIn = bytesIn;
        _bytesOut = bytesOut;
        _injected = injected;
        _repliesCaptured = repliesCaptured;
        _repliesRelayed = repliesRelayed;
        _badFrames = badFrames;
        _authorized = authorized;
        _players = players;
        _queueDepth = queueDepth;
        _frameBytes = frameBytes;
    }

    /// <summary>Имя правила (метка client) или "(процесс)" для безымянных метрик.</summary>
    public string Label { get; }

    /// <summary>Принят пакет/кадр: <paramref name="payloadBytes"/> — размер полезной нагрузки.</summary>
    public void CountPacketsIn(long payloadBytes)
    {
        _packetsIn.Inc();
        _bytesIn.Inc(payloadBytes);
        _frameBytes.Observe(payloadBytes);
    }

    /// <summary>Отправлен кадр в туннель: <paramref name="wireBytes"/> — размер кадра на проводе.</summary>
    public void CountPacketsOut(long wireBytes)
    {
        _packetsOut.Inc();
        _bytesOut.Inc(wireBytes);
        _frameBytes.Observe(wireBytes);
    }

    /// <summary>Кадр передан игровому серверу (впрыснут в игру).</summary>
    public void CountInjected() => _injected.Inc();

    /// <summary>Перехвачен ответ игрового сервера.</summary>
    public void CountRepliesCaptured() => _repliesCaptured.Inc();

    /// <summary>Ответ доставлен игроку.</summary>
    public void CountRepliesRelayed() => _repliesRelayed.Inc();

    /// <summary>Кадр туннеля не удалось разобрать или проверить.</summary>
    public void CountBadFrame() => _badFrames.Inc();

    /// <summary>Помечает сессию авторизованной (или, наоборот, потерянной).</summary>
    public void SetAuthorized(bool value) => _authorized.Set(value ? 1 : 0);

    /// <summary>Число известных игроков (UDP) или активных соединений (TCP).</summary>
    public void SetPlayers(int value) => _players.Set(value);

    /// <summary>Глубина очереди фоновой обработки.</summary>
    public void SetQueueDepth(int value) => _queueDepth.Set(value);
}
