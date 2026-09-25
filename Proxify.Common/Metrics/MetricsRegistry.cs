namespace Proxify.Common.Metrics;

/// <summary>
/// Реестр метрик процесса: хранит семейства метрик и отдаёт их в текстовом формате
/// Prometheus. Регистрация и сбор потокобезопасны; порядок метрик в выводе
/// стабильный (как порядок регистрации), поэтому diff соседних сборов читаем.
/// </summary>
public sealed class MetricsRegistry
{
    private readonly Dictionary<string, Metric> _metrics = new(StringComparer.Ordinal);
    private readonly List<Metric> _order = new();
    private readonly object _sync = new();

    /// <summary>
    /// Возвращает счётчик, создавая его при первом обращении. Повторный вызов с
    /// тем же именем возвращает уже зарегистрированный счётчик.
    /// </summary>
    public Counter Counter(string name, string help, params string[] labelNames)
    {
        lock (_sync)
        {
            if (_metrics.TryGetValue(name, out var existing))
                return Require<Counter>(existing);

            var counter = new Counter(name, help, Validate(name, help, labelNames));
            Register(counter);
            return counter;
        }
    }

    /// <summary>
    /// Возвращает гауж, создавая его при первом обращении.
    /// </summary>
    public Gauge Gauge(string name, string help, params string[] labelNames)
    {
        lock (_sync)
        {
            if (_metrics.TryGetValue(name, out var existing))
                return Require<Gauge>(existing);

            var gauge = new Gauge(name, help, Validate(name, help, labelNames));
            Register(gauge);
            return gauge;
        }
    }

    /// <summary>
    /// Возвращает гистограмму, создавая её при первом обращении. Границы
    /// <paramref name="bounds"/> сортируются и проверяются на строгий рост.
    /// </summary>
    public Histogram Histogram(string name, string help, double[] bounds, params string[] labelNames)
    {
        lock (_sync)
        {
            if (_metrics.TryGetValue(name, out var existing))
                return Require<Histogram>(existing);

            var sorted = NormalizeBounds(bounds);
            var histogram = new Histogram(name, help, Validate(name, help, labelNames), sorted);
            Register(histogram);
            return histogram;
        }
    }

    /// <summary>Зарегистрированные метрики в порядке регистрации.</summary>
    public IReadOnlyList<Metric> Metrics
    {
        get
        {
            lock (_sync)
                return _order.ToArray();
        }
    }

    /// <summary>Формирует текстовый ответ для <c>GET /metrics</c>.</summary>
    public string Scrape()
    {
        var exposition = new MetricsExposition();
        foreach (var metric in Metrics)
            metric.Write(exposition);
        return exposition.ToString();
    }

    private void Register(Metric metric)
    {
        _metrics[metric.Name] = metric;
        _order.Add(metric);
    }

    private T Require<T>(Metric metric) where T : Metric =>
        metric as T ?? throw new InvalidOperationException(
            $"Метрика '{metric.Name}' уже зарегистрирована как {metric.Type}, а запрошена {typeof(T).Name}.");

    private static string[] Validate(string name, string help, string[] labelNames)
    {
        if (!MetricLabels.IsValidName(name))
            throw new ArgumentException($"Некорректное имя метрики '{name}' (ожидается [a-zA-Z_:][a-zA-Z0-9_:]*).", nameof(name));
        if (string.IsNullOrWhiteSpace(help))
            throw new ArgumentException($"Метрика '{name}' обязана иметь текст справки (-- HELP).", nameof(help));

        foreach (var label in labelNames)
        {
            if (!MetricLabels.IsValidName(label))
                throw new ArgumentException($"Некорректное имя метки '{label}' в метрике '{name}'.", nameof(labelNames));
        }
        return labelNames.Length == 0 ? Array.Empty<string>() : (string[])labelNames.Clone();
    }

    private static double[] NormalizeBounds(double[] bounds)
    {
        if (bounds == null || bounds.Length == 0)
            throw new ArgumentException("Гистограмма требует хотя бы одну границу интервала.", nameof(bounds));

        var sorted = (double[])bounds.Clone();
        Array.Sort(sorted);
        for (var i = 1; i < sorted.Length; i++)
        {
            if (sorted[i] <= sorted[i - 1])
                throw new ArgumentException("Границы интервалов гистограммы должны быть строго возрастающими.", nameof(bounds));
        }
        return sorted;
    }
}
