using System.Collections.Concurrent;
using System.Globalization;

namespace Proxify.Common.Metrics;

/// <summary>
/// Гистограмма Prometheus: распределение наблюдений по фиксированным верхним
/// границам. Экспортируется как набор счётчиков <c>_bucket{le="..."} cumulative</c>
/// (последний — <c>+Inf</c>), сумма <c>_sum</c> и количество <c>_count</c>.
///
/// Сумма копится целыми микро-единицами, поэтому обновление атомарно, а точности
/// хватает и для байтов, и для длительностей.
/// </summary>
public sealed class Histogram : Metric
{
    private const double MicroScale = 1_000_000d;

    private readonly double[] _bounds;
    private readonly ConcurrentDictionary<string, Child> _series = new(StringComparer.Ordinal);
    private Child? _detached;

    internal Histogram(string name, string help, string[] labelNames, double[] bounds)
        : base(name, help, MetricType.Histogram, labelNames)
    {
        _bounds = bounds;
    }

    /// <summary>Верхние границы интервалов (строго возрастающие, без +Inf).</summary>
    public IReadOnlyList<double> Bounds => _bounds;

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
            _ => new Child(key, MetricLabels.Normalize(labelValues, count), _bounds));
    }

    /// <summary>Серия, которая не попадает в экспозицию (см. <see cref="Counter.Detached"/>).</summary>
    public Child Detached => _detached ??= new Child(
        "\u0000detached",
        MetricLabels.Normalize(Array.Empty<string?>(), LabelNames.Count),
        _bounds);

    /// <summary>Серия гистограммы.</summary>
    public sealed class Child
    {
        private readonly long[] _buckets;
        private long _count;
        private long _sumMicro;

        internal Child(string sortKey, string[] labelValues, double[] bounds)
        {
            SortKey = sortKey;
            LabelValues = labelValues;
            Bounds = bounds;
            _buckets = new long[bounds.Length + 1]; // последний счётчик — выше последней границы
        }

        /// <summary>Ключ серии: по нему выстраивается стабильный порядок вывода.</summary>
        internal string SortKey { get; }

        internal string[] LabelValues { get; }

        private double[] Bounds { get; }

        /// <summary>Количество наблюдений.</summary>
        public long Count => Interlocked.Read(ref _count);

        /// <summary>
        /// Накопленное (некумулятивное) число наблюдений, попавших в интервал с
        /// номером <paramref name="index"/>; последний интервал — выше всех границ.
        /// </summary>
        internal long BucketCount(int index) => Interlocked.Read(ref _buckets[index]);

        /// <summary>Число интервалов, включая последний (+Inf).</summary>
        internal int BucketCountTotal => _buckets.Length;

        /// <summary>Сумма наблюдений.</summary>
        public double Sum => Interlocked.Read(ref _sumMicro) / MicroScale;

        /// <summary>Добавляет одно наблюдение.</summary>
        public void Observe(double value)
        {
            Interlocked.Increment(ref _buckets[BucketIndex(value)]);
            Interlocked.Increment(ref _count);
            Interlocked.Add(ref _sumMicro, (long)Math.Round(value * MicroScale, MidpointRounding.AwayFromZero));
        }

        private int BucketIndex(double value)
        {
            // Границ немного, поэтому линейного прохода достаточно.
            for (var i = 0; i < Bounds.Length; i++)
            {
                if (value <= Bounds[i])
                    return i;
            }
            return Bounds.Length; // последний счётчик — +Inf
        }
    }

    internal override void Write(MetricsExposition exposition)
    {
        exposition.Help(Name, Help);
        exposition.Type(Name, "histogram");
        foreach (var series in _series.Values.OrderBy(h => h.SortKey, StringComparer.Ordinal))
            WriteSeries(exposition, series);
    }

    private void WriteSeries(MetricsExposition exposition, Child series)
    {
        var cumulative = 0L;
        for (var i = 0; i < _bounds.Length; i++)
        {
            cumulative += series.BucketCount(i);
            exposition.Bucket(Name, LabelNames, series.LabelValues, _bounds[i], cumulative);
        }
        cumulative += series.BucketCount(series.BucketCountTotal - 1);
        exposition.Bucket(Name, LabelNames, series.LabelValues, double.PositiveInfinity, cumulative);

        exposition.SampleRaw(Name + "_sum", LabelNames, series.LabelValues,
            series.Sum.ToString("R", CultureInfo.InvariantCulture));
        exposition.Sample(Name + "_count", LabelNames, series.LabelValues, series.Count);
    }
}
