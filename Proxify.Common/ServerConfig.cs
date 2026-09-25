using System.Net;
using System.Net.Sockets;

namespace Proxify.Common;

/// <summary>
/// Загрузка и проверка конфигурации прокси-сервера (машина A).
///
/// Формат YAML (см. <see cref="TryGenerateTemplate"/>): документ — это отображение,
/// где ключ — правило туннелирования, а значение — конфиг отдельного прокси-клиента.
///
///   <port>              UDP: публичный порт -> игровой UDP-порт (тот же номер)
///   <port>:<gamePort>   UDP: публичный порт -> игровой UDP-порт
///   <port> tcp          TCP: публичный TCP-порт -> игровой TCP-порт (тот же номер)
///   <port>:<gamePort> tcp  TCP: публичный TCP-порт -> игровой TCP-порт
///
///   publicKey  — путь к PEM-файлу (относительно конфига) либо сам PEM-текст
///                (можно многострочным блоком '|').
///   gameIp     — IPv4 игрового сервера на машине B (по умолчанию 127.0.0.1).
///   capture    — перехват ответов игрового сервера (по умолч. true; только UDP).
///   aliases    — loopback-алиасы реальных IP игроков (по умолч. true; только UDP).
///   obfuscation— внешняя маскировка туннеля WireObfuscator (по умолч. false).
///   name       — отображаемое имя клиента (для логов; необязательно).
///
/// Каждое правило — отдельный прокси-клиент: своя пара ключей, своя авторизация
/// (Auth) и свой процесс Proxify.Client на машине B. TCP и UDP разделены: для
/// копии UDP+TCP в конфиге два правила (с разными публичными ключами), а на
/// машине B запускаются два процесса клиента.
/// </summary>
public static class ServerConfig
{
    public static bool TryLoad(string path, out List<ClientConfig> clients, out string? error)
    {
        clients = new List<ClientConfig>();
        error = null;

        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (Exception ex)
        {
            error = $"Не удалось прочитать конфиг '{path}': {ex.Message}";
            return false;
        }

        YamlValue root;
        try
        {
            root = MiniYaml.Parse(text);
        }
        catch (FormatException ex)
        {
            error = $"Ошибка YAML в '{path}': {ex.Message}";
            return false;
        }

        if (!root.IsMapping || root.Map.Count == 0)
        {
            error = $"Конфиг '{path}' пуст — добавьте хотя бы одно правило вида 'порт' / 'порт:игровойПорт' / 'порт tcp'.";
            return false;
        }

        var baseDir = Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".";
        var usedUdpPorts = new HashSet<int>();
        var usedTcpPorts = new HashSet<int>();
        var usedKeys = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (key, node) in root.Map)
        {
            if (!TryParseEndpointKey(key, out var isTcp, out var publicPort, out var gamePort, out var keyError))
            {
                error = $"Конфиг '{path}': правило '{key}' — {keyError}";
                return false;
            }

            if (!node.IsMapping)
            {
                error = $"Конфиг '{path}': правило '{key}' должно содержать конфиг: publicKey и параметры.";
                return false;
            }

            if (!TryParseFields(node, baseDir, path, key, out var client, out var fieldError))
            {
                error = fieldError;
                return false;
            }

            client!.Port = publicPort;
            client.GamePort = (ushort)gamePort;
            client.TcpEnabled = isTcp;

            var collisions = isTcp ? usedTcpPorts : usedUdpPorts;
            if (!collisions.Add(publicPort))
            {
                error = $"Конфиг '{path}': {(isTcp ? "TCP" : "UDP")}-порт {publicPort} уже используется другим правилом.";
                return false;
            }

            if (!usedKeys.Add(client.PublicKeyPem.Trim()))
            {
                error = $"Конфиг '{path}': правило '{key}' повторяет публичный ключ другого правила. " +
                        "Каждое правило — отдельный прокси-клиент со своей парой ключей: на машине B для TCP и UDP запускаются отдельные процессы клиента.";
                return false;
            }

            clients.Add(client);
        }

        return true;
    }

    /// <summary>
    /// Генерирует шаблон server.yml из client-public.pem в указанном каталоге.
    /// </summary>
    public static bool TryGenerateTemplate(string dir, out string path, out string? error)
    {
        path = "";
        error = null;

        var publicKeyPath = Path.Combine(dir, "client-public.pem");
        if (!File.Exists(publicKeyPath))
        {
            error = $"Не найден публичный ключ '{publicKeyPath}'. Сначала сгенерируйте его на машине B:" +
                    Environment.NewLine + "  Proxify.Client --keygen <каталог>";
            return false;
        }

        try
        {
            path = Path.Combine(dir, "server.yml");
            var text =
                "# Конфиг прокси-сервера (машина A) — YAML.\n" +
                "#\n" +
                "# Каждый блок верхнего уровня — отдельный прокси-клиент (своя авторизация Auth,\n" +
                "# свой процесс Proxify.Client на машине B). Ключ задаёт протокол и порты:\n" +
                "#\n" +
                "#   27015           UDP: публичный порт 27015 -> игровой UDP-порт 27015\n" +
                "#   27015:7777      UDP: публичный порт 27015 -> игровой UDP-порт 7777\n" +
                "#   27015 tcp       TCP: публичный TCP-порт 27015 -> игровой TCP-порт 27015\n" +
                "#   27015:7777 tcp  TCP: публичный TCP-порт 27015 -> игровой TCP-порт 7777\n" +
                "#\n" +
                "# Поля: publicKey (обязательно), gameIp (по умолч. 127.0.0.1),\n" +
                "# capture/aliases (по умолч. true, только UDP), obfuscation (по умолч. false),\n" +
                "# name (необязательно). Публичный ключ — путь к PEM-файлу или PEM-текст (блок '|').\n" +
                "27015:7777:\n" +
                "  name: client1\n" +
                "  publicKey: client-public.pem\n" +
                "  gameIp: 127.0.0.1\n" +
                "  capture: true\n" +
                "  aliases: true\n" +
                "  obfuscation: false\n";
            File.WriteAllText(path, text);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Разбирает ключ правила: <c>PORT</c> | <c>PORT:GAMEPORT</c> с необязательным
    /// суффиксом <c>tcp</c> (после пробела или таба).
    /// </summary>
    private static bool TryParseEndpointKey(string raw, out bool isTcp, out int publicPort, out int gamePort, out string? error)
    {
        isTcp = false;
        publicPort = 0;
        gamePort = 0;
        error = null;

        var text = raw.Trim();
        if (text.Length == 0)
        {
            error = "пустой ключ (ожидается 'порт' / 'порт:игровойПорт' / 'порт tcp').";
            return false;
        }

        var ws = -1;
        for (var c = 0; c < text.Length; c++)
        {
            if (text[c] != ' ' && text[c] != '\t')
                continue;
            ws = c;
            break;
        }

        if (ws >= 0)
        {
            var proto = text[(ws + 1)..].Trim();
            if (!proto.Equals("tcp", StringComparison.OrdinalIgnoreCase))
            {
                error = $"неизвестный признак протокола '{proto}' (ожидается 'tcp' после пробела/таба).";
                return false;
            }
            isTcp = true;
            text = text[..ws].Trim();
            if (text.Length == 0)
            {
                error = "не указан порт.";
                return false;
            }
        }

        var parts = text.Split(':');
        if (parts.Length > 2)
        {
            error = "слишком много частей (ожидается 'публичныйПорт[:игровойПорт]').";
            return false;
        }

        if (!TryParsePort(parts[0], out publicPort))
        {
            error = $"порт '{parts[0]}' не является числом от 1 до 65535.";
            return false;
        }

        gamePort = publicPort;
        if (parts.Length == 2)
        {
            if (!TryParsePort(parts[1], out gamePort))
            {
                error = $"игровой порт '{parts[1]}' не является числом от 1 до 65535.";
                return false;
            }
        }

        return true;
    }

    private static bool TryParsePort(string text, out int port)
        => int.TryParse(text, out port) && port is >= 1 and <= 65535;

    private static bool TryParseFields(YamlValue node, string baseDir, string configPath, string ruleKey, out ClientConfig? client, out string? error)
    {
        client = null;
        error = null;

        var result = new ClientConfig
        {
            GameIp = IPAddress.Loopback,
        };

        foreach (var (field, value) in node.Map)
        {
            if (value.Kind != YamlKind.Scalar)
            {
                error = $"Конфиг '{configPath}', правило '{ruleKey}': поле '{field}' должно быть простым значением.";
                return false;
            }

            switch (field)
            {
                case "name":
                    result.Name = value.Scalar;
                    break;

                case "publicKey":
                    var publicKey = value.Scalar.Trim();
                    if (string.IsNullOrEmpty(publicKey))
                    {
                        error = $"Конфиг '{configPath}', правило '{ruleKey}': 'publicKey' не может быть пустым.";
                        return false;
                    }
                    if (publicKey.Contains("-----BEGIN"))
                    {
                        result.PublicKeyPem = publicKey;
                    }
                    else
                    {
                        var keyPath = Path.IsPathRooted(publicKey) ? publicKey : Path.Combine(baseDir, publicKey);
                        if (!File.Exists(keyPath))
                        {
                            error = $"Конфиг '{configPath}', правило '{ruleKey}': файл публичного ключа '{keyPath}' не найден.";
                            return false;
                        }
                        try
                        {
                            result.PublicKeyPem = File.ReadAllText(keyPath);
                        }
                        catch (Exception ex)
                        {
                            error = $"Конфиг '{configPath}', правило '{ruleKey}': не удалось прочитать ключ '{keyPath}': {ex.Message}";
                            return false;
                        }
                    }
                    break;

                case "gameIp":
                    if (!IPAddress.TryParse(value.Scalar, out var gameIp) || gameIp.AddressFamily != AddressFamily.InterNetwork)
                    {
                        error = $"Конфиг '{configPath}', правило '{ruleKey}': 'gameIp' должен быть IPv4-адресом.";
                        return false;
                    }
                    result.GameIp = gameIp;
                    break;

                case "capture":
                    if (!TryBool(value, out var capture))
                    {
                        error = $"Конфиг '{configPath}', правило '{ruleKey}': 'capture' должен быть true или false.";
                        return false;
                    }
                    result.CaptureReplies = capture;
                    break;

                case "aliases":
                    if (!TryBool(value, out var aliases))
                    {
                        error = $"Конфиг '{configPath}', правило '{ruleKey}': 'aliases' должен быть true или false.";
                        return false;
                    }
                    result.LoopbackAliases = aliases;
                    break;

                case "obfuscation":
                    if (!TryBool(value, out var obfuscation))
                    {
                        error = $"Конфиг '{configPath}', правило '{ruleKey}': 'obfuscation' должен быть true или false.";
                        return false;
                    }
                    result.WireObfuscation = obfuscation;
                    break;

                default:
                    error = $"Конфиг '{configPath}', правило '{ruleKey}': неизвестное поле '{field}'.";
                    return false;
            }
        }

        if (string.IsNullOrEmpty(result.PublicKeyPem))
        {
            error = $"Конфиг '{configPath}', правило '{ruleKey}': не задан 'publicKey'.";
            return false;
        }

        // Проверяем, что публичный ключ действительно парсится.
        try
        {
            using var _ = TunnelKeys.ImportPublicPem(result.PublicKeyPem);
        }
        catch (Exception ex)
        {
            error = $"Конфиг '{configPath}', правило '{ruleKey}': публичный ключ не является допустимым PEM-ключом: {ex.Message}";
            return false;
        }

        client = result;
        return true;
    }

    private static bool TryBool(YamlValue value, out bool result)
    {
        result = false;
        if (value.Kind != YamlKind.Scalar)
            return false;

        switch (value.Scalar.Trim().ToLowerInvariant())
        {
            case "true":
            case "yes":
            case "on":
            case "1":
                result = true;
                return true;
            case "false":
            case "no":
            case "off":
            case "0":
                result = false;
                return true;
            default:
                return false;
        }
    }
}