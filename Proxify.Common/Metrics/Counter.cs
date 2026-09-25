using System.Collections.Concurrent;

namespace Proxify.Common.Metrics;

/// <summary>
/// Монотонный счётчик Prometheus. Значение только увеличивается, поэтому сброс
/// при перезапуске процесса штатен (Prometheus сам распознаёт его в rate()).
///
/// Серии (наборы значений меток) кэшируются: <see cref="For"/> вызывается один раз
/// на правило, а обновления идут через <see cref="Child.Inc(long)"/> без
/// аллокаций и поисков по словарю — это горячий путь на каждый пакет.
/// </summary>
public sealed class Counter : Metric
{
    private readonly ConcurrentDictionary<string, Child> _series = new(StringComparer.Ordinal);
    private Child? _detached;

    internal Counter(string name, string help, string[] labelNames)
        : base(name, help, MetricType.Counter, labelNames)
    {
    }

    /// <summary>
    /// Возвращает серию для набора значений меток; при повторном вызове с тем же
    /// набором возвращается тот же объект.
    /// </summary>
    public Child For(params string?[] labelValues)
    {
        // Значения приводятся к числу объявленных меток: недостающие становятся
        // пустыми, лишние отбрасываются. Иначе экспозиция, идущая по именам
        // меток, вышла бы за границы массива значений.
        var count = LabelNames.Count;
        var key = MetricLabels.Key(labelValues, count);
        return _series.GetOrAdd(
            key,
            _ => new Child(key, MetricLabels.Normalize(labelValues, count)));
    }

    /// <summary>
    /// Серия, которая не попадает в экспозицию. Нужна ручкам уровня процесса для
    /// метрик, помеченных именем правила: считать им нечего, а пустые ряды в
    /// метриках лишни.
    /// </summary>
    public Child Detached => _detached ??= new Child(
        "\u0000detached",
        MetricLabels.Normalize(Array.Empty<string?>(), LabelNames.Count));

    /// <summary>Серия счётчика: инкремент без блокировок и аллокаций.</summary>
    public sealed class Child
    {
        private long _value;

        internal Child(string sortKey, string[] labelValues)
        {
            SortKey = sortKey;
            LabelValues = labelValues;
        }

        /// <summary>Ключ серии: по нему выстраивается стабильный порядок вывода.</summary>
        internal string SortKey { get; }

        internal string[] LabelValues { get; }

        /// <summary>Текущее значение серии.</summary>
        public long Value => Interlocked.Read(ref _value);

        /// <summary>Увеличивает счётчик на 1.</summary>
        public void Inc() => Interlocked.Increment(ref _value);

        /// <summary>Увеличивает счётчик на заданную величину.</summary>
        public void Inc(long delta) => Interlocked.Add(ref _value, delta);

        /// <summary>Сбрасывает счётчик в 0 (для самопроверки).</summary>
        public void Reset() => Interlocked.Exchange(ref _value, 0);
    }

    internal override void Write(MetricsExposition exposition)
    {
        exposition.Help(Name, Help);
        exposition.Type(Name, "counter");
        foreach (var series in _series.Values.OrderBy(c => c.SortKey, StringComparer.Ordinal))
            exposition.Sample(Name, LabelNames, series.LabelValues, series.Value);
    }
}
