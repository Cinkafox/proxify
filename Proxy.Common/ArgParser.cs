namespace Proxify.Common;

/// <summary>
/// Простой разбор аргументов командной строки вида:
///
///   --имя значение      либо   --имя=значение
///   -к имя значение             -к=значение
///   -h / --help                 справка
///
/// Поддерживаются обязательные опции (требуются всегда) и значения по умолчанию.
/// Дублирование опции не допускается, неизвестные опции — ошибка.
/// </summary>
public sealed class ArgParser
{
    private readonly string _program;
    private readonly List<ArgOption> _options = new();
    private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);
    private string? _error;
    private bool _helpRequested;

    public ArgParser(string program) => _program = program;

    public ArgParser Add(
        string longName,
        string help,
        bool required = false,
        string? defaultValue = null,
        char shortName = '\0')
    {
        _options.Add(new ArgOption
        {
            LongName = longName,
            ShortName = shortName,
            Help = help,
            Required = required,
            Default = defaultValue,
        });
        return this;
    }

    /// <summary>
    /// Разбирает аргументы. При неудаче заполняет <see cref="Error"/>
    /// (и, если это опции недоставало значения или была опция --help —
    /// печатает справку). Возвращает false при ошибке.
    /// </summary>
    public bool TryParse(string[] args)
    {
        _error = null;
        _values.Clear();
        _helpRequested = false;

        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];

            if (a is "--help" or "-h")
            {
                _helpRequested = true;
                PrintUsage();
                return true;
            }

            if (a.Length < 2 || !a.StartsWith('-'))
            {
                _error = $"Неожиданный аргумент '{a}'. Используйте --опция значение.";
                return false;
            }

            var body = a.TrimStart('-');
            string name;
            string? inlineValue = null;
            var eq = body.IndexOf('=');
            if (eq >= 0)
            {
                name = body[..eq];
                inlineValue = body[(eq + 1)..];
            }
            else
            {
                name = body;
            }

            var opt = Find(name);
            if (opt == null)
            {
                _error = $"Неизвестный аргумент '--{name}'. Запустите с '--help' для справки.";
                return false;
            }

            if (inlineValue != null)
            {
                if (_values.ContainsKey(opt.LongName))
                {
                    _error = $"Аргумент '--{opt.LongName}' задан несколько раз.";
                    return false;
                }
                _values[opt.LongName] = inlineValue;
                continue;
            }

            if (i + 1 >= args.Length || args[i + 1].StartsWith('-'))
            {
                _error = $"Аргумент '--{opt.LongName}' требует значение. " +
                         (i + 1 < args.Length && args[i + 1].StartsWith('-')
                             ? $"Значения, начинающиеся с '-', задавайте через '=': --{opt.LongName}={args[i + 1].TrimStart('-')}..."
                             : "Например: --" + opt.LongName + " 27015");
                return false;
            }

            if (_values.ContainsKey(opt.LongName))
            {
                _error = $"Аргумент '--{opt.LongName}' задан несколько раз.";
                return false;
            }
            _values[opt.LongName] = args[++i];
        }

        foreach (var opt in _options)
        {
            if (opt.Required && !_values.ContainsKey(opt.LongName))
            {
                _error = $"Обязательный аргумент '--{opt.LongName}' не задан.";
                return false;
            }
            if (!_values.ContainsKey(opt.LongName) && opt.Default != null)
                _values[opt.LongName] = opt.Default;
        }

        return true;
    }

    public string? Error => _error;

    /// <summary>
    /// true, если в аргументах был запрошен --help (справка уже напечатана).
    /// </summary>
    public bool HelpRequested => _helpRequested;

    /// <summary>
    /// Значение опции, либо null, если она не задана и не имеет значения по умолчанию.
    /// </summary>
    public string? Get(string longName)
    {
        _values.TryGetValue(longName, out var value);
        return value;
    }

    public void PrintUsage()
    {
        Console.WriteLine($"Использование: {_program} --опция значение ...");
        Console.WriteLine();
        Console.WriteLine("Опции:");
        foreach (var o in _options)
        {
            var shortPart = o.ShortName != '\0' ? $"-{o.ShortName}, " : "    ";
            var suffix = (o.Required ? " (обязательный)" : "") + (o.Default != null ? $" (по умолч. {o.Default})" : "");
            Console.WriteLine($"  {shortPart}--{o.LongName}{suffix}");
            Console.WriteLine($"      {o.Help}");
        }
        Console.WriteLine("  -h, --help            показать эту справку");
    }

    private ArgOption? Find(string name)
    {
        foreach (var o in _options)
        {
            if (string.Equals(o.LongName, name, StringComparison.OrdinalIgnoreCase))
                return o;
            if (o.ShortName != '\0' && o.ShortName.ToString() == name)
                return o;
        }
        return null;
    }

    private sealed class ArgOption
    {
        public required string LongName { get; init; }
        public char ShortName { get; init; }
        public required string Help { get; init; }
        public bool Required { get; init; }
        public string? Default { get; init; }
    }
}
