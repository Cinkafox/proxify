namespace Proxify.Common.Metrics;

/// <summary>
/// Тип метрики Prometheus. Определяет, как значение выводится в текстовом формате
/// exposition и какие операции над ним допустимы.
/// </summary>
public enum MetricType
{
    /// <summary>Монотонный счётчик: значение только растёт.</summary>
    Counter,

    /// <summary>Текущее значение: может расти и падать.</summary>
    Gauge,

    /// <summary>Распределение наблюдений по границам интервалов.</summary>
    Histogram,
}
