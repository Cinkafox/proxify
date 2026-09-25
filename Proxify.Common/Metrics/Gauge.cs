using System.Collections.Concurrent;

namespace Proxify.Common.Metrics;

/// <summary>
/// Текущее значение Prometheus: может расти и падать. Хранится как
/// <see cref="double"/>; атомарные операции выполняются через <see cref="Interlocked"/>
/// по битовому представлению (для NaN атомарность не гарантируется — такие значения
/// в гаужах не используются).
/// </summary>
public sealed class Gauge : Metric
{
    private readonly ConcurrentDictionary<string, Child> _series = new(StringComparer.Ordinal);
    private Child? _detached;

    internal Gauge(string name, string help, string[] labelNames)
        : base(name, help, MetricType.Gauge, labelNames)
    {
    }

    /// <summary>
    /// Возвращает серию для набора значений меток; при повторном вызове с тем же
    /// набором возвращается тот же объект.
    /// </summary>
    public Child For(params string?[] labelValues)
    {
        // Значения приводятся к числу объявленных меток, см. Counter.For.
        var count = LabelNames.Count;
        var key = MetricLabels.Key(labelValues, count);
        return _series.GetOrAdd(
            key,
            _ => new Child(key, MetricLabels.Normalize(labelValues, count)));
    }

    /// <summary>Серия, которая не попадает в экспозицию (см. <see cref="Counter.Detached"/>).</summary>
    public Child Detached => _detached ??= new Child(
        "\u0000detached",
        MetricLabels.Normalize(Array.Empty<string?>(), LabelNames.Count));

    /// <summary>Серия гаужа.</summary>
    public sealed class Child
    {
        private long _bits;

        internal Child(string sortKey, string[] labelValues)
        {
            SortKey = sortKey;
            LabelValues = labelValues;
        }

        /// <summary>Ключ серии: по нему выстраивается стабильный порядок вывода.</summary>
        internal string SortKey { get; }

        internal string[] LabelValues { get; }

        /// <summary>Текущее значение серии.</summary>
        public double Value => BitConverter.Int64BitsToDouble(Volatile.Read(ref _bits));

        /// <summary>Присваивает значение.</summary>
        public void Set(double value) => Interlocked.Exchange(ref _bits, BitConverter.DoubleToInt64Bits(value));

        /// <summary>
        /// Прибавляет величину (может быть отрицательной). Сложение double не
        /// поддерживается атомарно, поэтому цикл CAS: пока значение меняют другие
        /// потоки, повторяем попытку. Частое пересечение конкурентно работающих
        /// Add реже, чем чтение гаужа, которое всегда выполняется без блокировок.
        /// </summary>
        public void Add(double delta)
        {
            while (true)
            {
                var currentBits = Volatile.Read(ref _bits);
                var current = BitConverter.Int64BitsToDouble(currentBits);
                var updated = BitConverter.DoubleToInt64Bits(current + delta);
                if (Interlocked.CompareExchange(ref _bits, updated, currentBits) == currentBits)
                    return;
            }
        }

        /// <summary>Увеличивает на 1.</summary>
        public void Inc() => Add(1);

        /// <summary>Уменьшает на 1.</summary>
        public void Dec() => Add(-1);
    }

    internal override void Write(MetricsExposition exposition)
    {
        exposition.Help(Name, Help);
        exposition.Type(Name, "gauge");
        foreach (var series in _series.Values.OrderBy(g => g.SortKey, StringComparer.Ordinal))
            exposition.Sample(Name, LabelNames, series.LabelValues, series.Value);
    }
}
