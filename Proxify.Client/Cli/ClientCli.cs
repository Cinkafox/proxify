using System.Security.Cryptography;
using Proxify.Common.Cli;
using Proxify.Common.Crypto;
using Proxify.Common.Networking;

namespace Proxify.Client.Cli;

/// <summary>
/// Помощник командной строки прокси-клиента: разбор аргументов (--server,
/// --tunnel-port, --local-port, --key, --keygen, --wire-obfuscation), загрузка
/// ключа и генерация пары ключей. Программа (Program.cs) остаётся тонкой.
/// </summary>
public static class ClientCli
{
    public static ArgParser CreateParser() => new ArgParser("Proxify.Client")
        .Add("server", "Адрес прокси-сервера (машина A): host или host:порт туннеля. Если порт не указан, используется --tunnel-port", shortName: 's')
        .Add("tunnel-port", "UDP-порт туннеля ПРОКСИ-СЕРВЕРА (машины A), если он не указан в --server", shortName: 't')
        .Add("local-port", "Локальный UDP-порт туннеля клиента. Если не задан, ОС выберет свободный (port 0). Полезно для файрволов.", shortName: 'l')
        .Add("key", "Путь к закрытому ключу клиента (PEM, PKCS#8). Создаётся командой --keygen", shortName: 'k')
        .Add("keygen", "Сгенерировать пару ключей в указанном каталоге (client-private.pem, client-public.pem) и выйти", shortName: 'g')
        .Add("wire-obfuscation", "Внешняя маскировка туннеля: on или off (по умолчанию). Должна совпадать с настройкой 'obfuscation' в конфиге сервера", defaultValue: "off");

    /// <summary>
    /// Разбирает аргументы и валидирует их: адрес и порт сервера, локальный порт,
    /// флаг маскировки и закрытый ключ.
    /// </summary>
    public static ClientOptions Parse(string[] args)
    {
        var cli = CreateParser();
        if (!cli.TryParse(args))
            return new ClientOptions { ShowUsage = true, Error = cli.Error };
        if (cli.HelpRequested)
            return new ClientOptions { HelpRequested = true };

        var keygenDir = cli.Get("keygen");
        if (!string.IsNullOrWhiteSpace(keygenDir))
            return new ClientOptions { KeygenDir = keygenDir };

        var serverText = cli.Get("server");
        if (string.IsNullOrWhiteSpace(serverText))
            return new ClientOptions { ShowUsage = true, Error = "'--server' не может быть пустым (ожидается host или host:порт машины A)." };

        // Разбор host[:порт]. Порт может быть указан в --server или отдельным --tunnel-port.
        var (serverHost, inlinePort) = SplitHostPort(serverText);
        var tunnelPortText = inlinePort ?? cli.Get("tunnel-port");

        if (string.IsNullOrWhiteSpace(tunnelPortText) ||
            !NetUtils.TryParsePort(tunnelPortText, out var tunnelPort))
        {
            return new ClientOptions { ShowUsage = true, Error = "Не указан порт туннеля. Добавьте его к --server (host:порт) или задайте --tunnel-port." };
        }

        if (!NetUtils.TryParseEndpoint($"{serverHost}:{tunnelPort}", out var proxyServer))
            return new ClientOptions { ShowUsage = true, Error = $"Не удалось разрешить адрес прокси-сервера '{serverHost}'." };

        int? localPort = null;
        var localPortText = cli.Get("local-port");
        if (!string.IsNullOrWhiteSpace(localPortText))
        {
            if (!NetUtils.TryParsePort(localPortText, out var lp))
                return new ClientOptions { ShowUsage = true, Error = $"Неверный локальный порт '{localPortText}'." };
            localPort = lp;
        }

        if (!TryParseWireObfuscation(cli.Get("wire-obfuscation"), out var wireObfuscation, out var wireError))
            return new ClientOptions { Error = wireError };

        var keyPath = cli.Get("key");
        if (string.IsNullOrWhiteSpace(keyPath) || !File.Exists(keyPath))
            return new ClientOptions { ShowUsage = true, Error = $"Закрытый ключ не найден: '{keyPath}'. Создайте его командой --keygen." };

        if (!TryLoadIdentityKey(keyPath, out var identityKey, out var keyError))
            return new ClientOptions { Error = keyError };

        return new ClientOptions
        {
            ProxyServer = proxyServer,
            KeyPath = keyPath,
            IdentityKey = identityKey,
            LocalPort = localPort,
            WireObfuscation = wireObfuscation,
        };
    }

    /// <summary>
    /// Режим --keygen: генерирует пару ключей (client-private.pem, client-public.pem)
    /// в указанном каталоге. Возвращает текст ошибки или null при успехе.
    /// </summary>
    public static string? GenerateKeys(string keygenDir)
    {
        if (!TunnelKeys.TryGenerateKeyPair(keygenDir, out var privatePath, out var publicPath, out var keygenError))
            return keygenError;

        Console.WriteLine($"Закрытый ключ клиента : {privatePath}");
        Console.WriteLine($"Публичный ключ клиента: {publicPath}");
        Console.WriteLine("Передайте файл client-public.pem на машину A и укажите его в конфиге сервера.");
        Console.WriteLine("На машине A можно сгенерировать шаблон конфига:");
        Console.WriteLine("  Proxify.Server --configgen <каталог с client-public.pem>");
        return null;
    }

    private static bool TryLoadIdentityKey(string keyPath, out ECDsa identityKey, out string? error)
    {
        identityKey = null!;
        error = null;
        try
        {
            identityKey = TunnelKeys.ImportPrivatePem(File.ReadAllText(keyPath));
            Console.WriteLine($"[диагностика] Закрытый ключ загружен: {keyPath}");
            return true;
        }
        catch (Exception ex)
        {
            error = $"Не удалось загрузить закрытый ключ '{keyPath}': {ex.Message}";
            return false;
        }
    }

    private static bool TryParseWireObfuscation(string? text, out bool value, out string? error)
    {
        switch ((text ?? "off").Trim().ToLowerInvariant())
        {
            case "on":
            case "вкл":
            case "true":
            case "1":
                value = true;
                error = null;
                return true;
            case "off":
            case "выкл":
            case "false":
            case "0":
                value = false;
                error = null;
                return true;
            default:
                value = false;
                error = "--wire-obfuscation принимает только on|off.";
                return false;
        }
    }

    /// <summary>
    /// Разделяет "host[:порт]" на хост и порт. Возвращает порт только если он числовой.
    /// </summary>
    private static (string Host, string? Port) SplitHostPort(string text)
    {
        var idx = text.LastIndexOf(':');
        if (idx <= 0)
            return (text, null);

        var port = text[(idx + 1)..];
        if (port.Length > 0 && port.All(char.IsAsciiDigit))
            return (text[..idx], port);

        return (text, null);
    }
}