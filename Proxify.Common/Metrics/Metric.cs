namespace Proxify.Common.Metrics;

/// <summary>
/// Базовый класс метрики: имя, справка, тип и набор имён меток. Значения хранятся
/// в наследниках (по одному на уникальный набор значений меток — «серия»).
///
/// Имена меток объявляются один раз на семейство; пустой набор означает, что
/// метрика безымянная (одна серия на процесс).
/// </summary>
public abstract class Metric
{
    internal Metric(string name, string help, MetricType type, string[] labelNames)
    {
        Name = name;
        Help = help;
        Type = type;
        LabelNames = labelNames;
    }

    /// <summary>Имя метрики (для счётчиков — вместе с суффиксом <c>_total</c>).</summary>
    public string Name { get; }

    /// <summary>Краткое человекочитаемое описание (строка <c># HELP</c>).</summary>
    public string Help { get; }

    public MetricType Type { get; }

    /// <summary>Имена меток семейства (пусто — метрика безымянная).</summary>
    public IReadOnlyList<string> LabelNames { get; }

    /// <summary>Рендерит семейство (заголовок и все серии) в текст exposition.</summary>
    internal abstract void Write(MetricsExposition exposition);
}
