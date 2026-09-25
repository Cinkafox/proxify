using System.Globalization;
using System.Text;

namespace Proxify.Common.Metrics;

/// <summary>
/// Пишет метрики в текстовом формате exposition Prometheus
/// (<c>text/plain; version=0.0.4</c>): строки <c># HELP</c>, <c># TYPE</c> и
/// образцы вида <c>имя{метка="значение"} значение</c>.
///
/// Экземпляр предназначен для одного сбора: <see cref="ToString"/> возвращает
/// накопленный текст.
/// </summary>
public sealed class MetricsExposition
{
    /// <summary>Content-Type, который ожидает Prometheus для текстового формата.</summary>
    public const string ContentType = "text/plain; version=0.0.4; charset=utf-8";

    private const string Newline = "\n";

    private readonly StringBuilder _builder = new(16 * 1024);

    /// <summary>Пишет строку справки <c># HELP имя текст</c>.</summary>
    public void Help(string name, string help)
    {
        _builder.Append("# HELP ").Append(name).Append(' ');
        MetricLabels.AppendHelp(_builder, help);
        _builder.Append(Newline);
    }

    /// <summary>Пишет строку типа <c># TYPE имя тип</c>.</summary>
    public void Type(string name, string type)
    {
        _builder.Append("# TYPE ").Append(name).Append(' ').Append(type).Append(Newline);
    }

    /// <summary>Пишет образец с целым значением.</summary>
    public void Sample(string name, IReadOnlyList<string> labelNames, IReadOnlyList<string> labelValues, long value)
    {
        AppendNameAndLabels(name, labelNames, labelValues);
        _builder.Append(' ').Append(value.ToString(CultureInfo.InvariantCulture)).Append(Newline);
    }

    /// <summary>Пишет образец с вещественным значением (NaN и бесконечности — как в Prometheus).</summary>
    public void Sample(string name, IReadOnlyList<string> labelNames, IReadOnlyList<string> labelValues, double value)
    {
        AppendNameAndLabels(name, labelNames, labelValues);
        _builder.Append(' ').Append(FormatValue(value)).Append(Newline);
    }

    /// <summary>Пишет образец с заранее отформатированным значением.</summary>
    public void SampleRaw(string name, IReadOnlyList<string> labelNames, IReadOnlyList<string> labelValues, string value)
    {
        AppendNameAndLabels(name, labelNames, labelValues);
        _builder.Append(' ').Append(value).Append(Newline);
    }

    /// <summary>
    /// Пишет границу гистограммы <c>имя_bucket{...,le="граница"} значение</c>.
    /// </summary>
    public void Bucket(
        string name,
        IReadOnlyList<string> labelNames,
        IReadOnlyList<string> labelValues,
        double bound,
        long cumulativeCount)
    {
        _builder.Append(name).Append("_bucket{");
        AppendLabels(labelNames, labelValues, true);
        _builder.Append("le=\"");
        AppendBound(bound);
        _builder.Append("\"} ")
            .Append(cumulativeCount.ToString(CultureInfo.InvariantCulture))
            .Append(Newline);
    }

    public override string ToString() => _builder.ToString();

    private void AppendNameAndLabels(string name, IReadOnlyList<string> labelNames, IReadOnlyList<string> labelValues)
    {
        _builder.Append(name);
        if (labelNames.Count == 0)
            return;

        _builder.Append('{');
        AppendLabels(labelNames, labelValues, false);
        _builder.Append('}');
    }

    /// <summary>
    /// Пишет пары <c>имя="значение"</c> через запятую. Для границ гистограммы
    /// (<paramref name="withTrailingComma"/>) последняя запятая нужна, чтобы дописать
    /// метку le в конец списка.
    /// </summary>
    private void AppendLabels(IReadOnlyList<string> labelNames, IReadOnlyList<string> labelValues,
        bool withTrailingComma)
    {
        for (var i = 0; i < labelNames.Count; i++)
        {
            if (i > 0)
                _builder.Append(',');
            _builder.Append(labelNames[i]).Append('=');
            MetricLabels.AppendEscaped(_builder, i < labelValues.Count ? labelValues[i] : string.Empty);
        }

        if (withTrailingComma && labelNames.Count > 0)
            _builder.Append(',');
    }

    private void AppendBound(double bound)
    {
        if (double.IsPositiveInfinity(bound))
            _builder.Append("+Inf");
        else
            _builder.Append(FormatValue(bound));
    }

    private static string FormatValue(double value)
    {
        if (double.IsNaN(value))
            return "NaN";
        if (double.IsPositiveInfinity(value))
            return "+Inf";
        if (double.IsNegativeInfinity(value))
            return "-Inf";
        return value.ToString("R", CultureInfo.InvariantCulture);
    }
}
