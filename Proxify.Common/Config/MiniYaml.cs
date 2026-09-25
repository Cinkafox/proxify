using System.Text;

namespace Proxify.Common.Config;

/// <summary>
/// Минимальный YAML-поднабор для конфигов проекта (без внешних зависимостей).
///
/// Поддерживает то, что нужно конфигу прокси-сервера:
///   - комментарии (# до конца строки, кроме многострочных блоков);
///   - блочные отображения 'ключ: значение' с отступами (пробелами);
///   - скалярные значения: числа, строки, true/false (интерпретирует вызывающий);
///   - одинарные/двойные кавычки;
///   - многострочные блоки '|' (буквально, сохраняет переводы строк) и '>'
///     (схлопывает переводы строк в пробелы) для встроенных PEM-ключей;
///   - маркеры начала/конца документа '---' / '...' (пропускаются).
///
/// Последовательности ('- элемент') не требуются конфигу и не поддерживаются —
/// при встрече выводится понятная ошибка.
/// </summary>
public enum YamlKind
{
    Scalar,
    Mapping,
}

public sealed class YamlValue
{
    public YamlKind Kind { get; internal set; } = YamlKind.Scalar;
    public string Scalar { get; internal set; } = "";
    public List<(string Key, YamlValue Value)> Map { get; } = new();

    public bool IsMapping => Kind == YamlKind.Mapping;
    public bool IsScalar => Kind == YamlKind.Scalar;
}

public static class MiniYaml
{
    private readonly struct Line
    {
        public readonly int Indent;
        public readonly string Text;
        public readonly bool Blank;

        public Line(int indent, string text, bool blank)
        {
            Indent = indent;
            Text = text;
            Blank = blank;
        }
    }

    public static YamlValue Parse(string text)
    {
        var lines = SplitLines(text);
        var pos = 0;

        // Пропускаем маркер начала документа и пустые строки.
        while (pos < lines.Count)
        {
            var line = lines[pos];
            if (!line.Blank && line.Text.TrimStart().StartsWith("---", StringComparison.Ordinal))
            {
                pos++;
                continue;
            }
            break;
        }

        var root = new YamlValue { Kind = YamlKind.Mapping };
        if (pos >= lines.Count || lines[pos].Blank)
            return root;

        if (lines[pos].Indent != 0)
            throw new FormatException($"Неожиданный отступ {lines[pos].Indent} в начале документа.");

        ParseMapping(lines, ref pos, 0, root.Map);
        return root;
    }

    private static List<Line> SplitLines(string text)
    {
        var result = new List<Line>();
        var raw = text.Replace("\r\n", "\n").Replace('\r', '\n');
        var split = raw.Split('\n');

        foreach (var rawLine in split)
        {
            var indent = 0;
            while (indent < rawLine.Length && rawLine[indent] == ' ')
                indent++;
            if (indent < rawLine.Length && rawLine[indent] == '\t')
                throw new FormatException("Табуляция в отступах не допускается — используйте пробелы.");

            var content = rawLine.Substring(indent);
            result.Add(new Line(indent, content, string.IsNullOrWhiteSpace(content)));
        }

        // Отбрасываем хвостовые пустые строки, чтобы блоки не захватывали мусор.
        while (result.Count > 0 && result[^1].Blank)
            result.RemoveAt(result.Count - 1);
        return result;
    }

    /// <summary>
    /// Разбирает блочное отображение на уровне отступа <paramref name="indent"/>.
    /// Останавливается на строке с меньшим отступом или конце документа.
    /// </summary>
    private static void ParseMapping(List<Line> lines, ref int pos, int indent, List<(string, YamlValue)> target)
    {
        while (true)
        {
            while (pos < lines.Count && lines[pos].Blank)
                pos++;
            if (pos >= lines.Count)
                return;

            var line = lines[pos];
            if (line.Indent < indent)
                return;
            if (line.Indent > indent)
                throw new FormatException($"Строка '{line.Text.Trim()}' имеет отступ {line.Indent}, ожидался {indent}.");

            var content = line.Text;

            // Полнострочный комментарий — пропускаем.
            if (content.TrimStart().StartsWith("#"))
            {
                pos++;
                continue;
            }

            if (content.StartsWith("- ", StringComparison.Ordinal) || content == "-")
                throw new FormatException("Последовательности YAML ('- элемент') не поддерживаются конфигом.");

            if (!TrySplitKey(content, out var key, out var rawValue))
                throw new FormatException($"Строка '{content}' не является парой 'ключ: значение'.");

            pos++;
            var value = ParseValue(lines, ref pos, indent, key, rawValue);
            target.Add((key, value));
        }
    }

    private static YamlValue ParseValue(List<Line> lines, ref int pos, int parentIndent, string key, string rawValue)
    {
        // Многострочный блок: '|' (буквально) или '>' (схлопывание).
        if (rawValue.Length > 0 && (rawValue[0] == '|' || rawValue[0] == '>'))
        {
            var style = rawValue[0];
            var chomp = rawValue.Length > 1 && (rawValue[1] == '+' || rawValue[1] == '-') ? rawValue[1] : '\0';
            return ParseBlockScalar(lines, ref pos, parentIndent, style, chomp);
        }

        var raw = StripComment(rawValue.Trim());
        if (raw.Length == 0)
        {
            // Значение пустое: либо вложенное отображение, либо пустой скаляр.
            var j = pos;
            while (j < lines.Count && lines[j].Blank)
                j++;

            if (j < lines.Count && lines[j].Indent > parentIndent)
            {
                var nested = new YamlValue { Kind = YamlKind.Mapping };
                ParseMapping(lines, ref pos, lines[j].Indent, nested.Map);
                return nested;
            }

            return new YamlValue { Kind = YamlKind.Scalar, Scalar = "" };
        }

        return new YamlValue { Kind = YamlKind.Scalar, Scalar = Unquote(raw) };
    }

    private static YamlValue ParseBlockScalar(List<Line> lines, ref int pos, int parentIndent, char style, char chomp)
    {
        var collected = new List<string>();
        int? contentIndent = null;

        while (pos < lines.Count)
        {
            var line = lines[pos];

            if (line.Blank)
            {
                if (contentIndent != null)
                {
                    // Пустые строки внутри блока сохраняются.
                    collected.Add("");
                }
                pos++;
                continue;
            }

            if (contentIndent == null)
            {
                if (line.Indent <= parentIndent)
                    break; // содержания нет
                contentIndent = line.Indent;
            }

            if (line.Indent < contentIndent)
                break;

            // line.Text уже без собственного отступа (см. SplitLines): остаётся снять
            // разницу между фактическим отступом строки и отступом содержимого блока.
            var content = line.Text;
            var cut = line.Indent - contentIndent.Value;
            if (cut > 0)
                content = cut < content.Length ? content.Substring(cut) : "";
            collected.Add(content);
            pos++;
        }

        string result;
        if (style == '|')
        {
            result = string.Join("\n", collected);
        }
        else
        {
            // '>' — схлопываем одинарные переводы строк в пробел, пустые строки — в абзац.
            var sb = new StringBuilder();
            for (var k = 0; k < collected.Count; k++)
            {
                var item = collected[k];
                var isBlank = item.Length == 0;
                if (isBlank)
                {
                    sb.Append('\n');
                    continue;
                }
                sb.Append(item);
                if (k + 1 < collected.Count)
                {
                    var nextBlank = collected[k + 1].Length == 0;
                    sb.Append(nextBlank ? '\n' : ' ');
                }
            }
            result = sb.ToString();
        }

        switch (chomp)
        {
            case '+':
                // Сохраняем завершающие переводы строк как есть.
                break;
            case '-':
                result = result.TrimEnd('\n', ' ', '\t');
                break;
            default:
                // clip: один завершающий перевод строки.
                result = result.TrimEnd(' ', '\t');
                while (result.EndsWith('\n'))
                    result = result[..^1];
                result += "\n";
                break;
        }

        return new YamlValue { Kind = YamlKind.Scalar, Scalar = result };
    }

    /// <summary>
    /// Ищет разделитель 'ключ: значение' — первый двоеточие, после которого идёт пробел
    /// или конец строки. Это соответствует обычным YAML-ключам вида <c>27015:7777</c>
    /// (двоеточие внутри скаляра допустимо, если за ним нет пробела).
    /// </summary>
    private static bool TrySplitKey(string text, out string key, out string rawValue)
    {
        key = "";
        rawValue = "";

        for (var c = 0; c < text.Length; c++)
        {
            if (text[c] != ':')
                continue;
            if (c + 1 < text.Length && text[c + 1] != ' ')
                continue;

            key = text[..c].Trim();
            rawValue = text[(c + 1)..].TrimStart();
            return true;
        }

        return false;
    }

    private static string StripComment(string s)
    {
        // Комментарий — '#' в начале значения или после пробела (внутри скаляра '#' можно).
        var idx = s.IndexOf(" #", StringComparison.Ordinal);
        if (idx >= 0)
            s = s[..idx];
        if (s.Length > 0 && s[0] == '#')
            return "";
        return s.TrimEnd();
    }

    private static string Unquote(string s)
    {
        if (s.Length < 2)
            return s;

        if (s[0] == '"' && s[^1] == '"')
            return s[1..^1].Replace("\\\"", "\"").Replace("\\\\", "\\");

        if (s[0] == '\'' && s[^1] == '\'')
            return s[1..^1].Replace("''", "'");

        return s;
    }
}