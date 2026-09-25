using System.Text;

namespace Proxify.Common.Metrics;

/// <summary>
/// Хелперы набора меток: построение ключа серии метрики и экранирование
/// значений для текстового формата exposition.
/// </summary>
internal static class MetricLabels
{
    /// <summary>
    /// Строит однозначный ключ серии метрики по значениям меток. Каждое значение
    /// попадает в ключ с префиксом длины, поэтому разные наборы значений не могут
    /// дать одну и ту же строку (в отличие от склейки разделителем).
    /// Недостающие значения (их меньше <paramref name="count"/>) считаются пустыми,
    /// так же как в <see cref="Normalize"/>.
    /// </summary>
    public static string Key(ReadOnlySpan<string?> values, int count)
    {
        var builder = new StringBuilder(count * 8);
        for (var i = 0; i < count; i++)
        {
            var value = i < values.Length ? values[i] ?? string.Empty : string.Empty;
            builder.Append(value.Length).Append(':').Append(value);
        }
        return builder.ToString();
    }

    /// <summary>
    /// Копирует значения меток в новый массив ровно на <paramref name="count"/>
    /// элементов (лишние переданные значения отбрасываются).
    /// </summary>
    public static string[] Normalize(string?[] values, int count)
    {
        var result = new string[count];
        for (var i = 0; i < count; i++)
            result[i] = i < values.Length ? values[i] ?? string.Empty : string.Empty;
        return result;
    }

    /// <summary>
    /// Пишет значение метки в кавычках, экранируя обратный слеш, двойную кавычку
    /// и перевод строки (требования формата exposition).
    /// </summary>
    public static void AppendEscaped(StringBuilder builder, string value)
    {
        builder.Append('"');
        foreach (var c in value)
        {
            switch (c)
            {
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                default:
                    builder.Append(c);
                    break;
            }
        }
        builder.Append('"');
    }

    /// <summary>
    /// Пишет текст справки для <c># HELP</c>, экранируя обратный слеш и перевод строки.
    /// </summary>
    public static void AppendHelp(StringBuilder builder, string help)
    {
        foreach (var c in help)
        {
            switch (c)
            {
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                default:
                    builder.Append(c);
                    break;
            }
        }
    }

    /// <summary>
    /// Проверяет имя метрики по правилам Prometheus: буква, подчёркивание или
    /// двоеточие в начале, далее буквы, цифры, подчёркивание и двоеточие.
    /// </summary>
    public static bool IsValidName(string name)
    {
        if (string.IsNullOrEmpty(name))
            return false;

        var first = name[0];
        if (!char.IsAsciiLetter(first) && first != '_' && first != ':')
            return false;

        for (var i = 1; i < name.Length; i++)
        {
            var c = name[i];
            if (!char.IsAsciiLetterOrDigit(c) && c != '_' && c != ':')
                return false;
        }
        return true;
    }
}
