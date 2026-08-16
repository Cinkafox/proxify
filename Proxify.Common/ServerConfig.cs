using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace Proxify.Common;

/// <summary>
/// Загрузка и проверка конфигурации прокси-сервера (машина A).
///
/// Формат JSON:
/// {
///   "clients": [
///     {
///       "name": "client1",                    // необязательно
///       "publicKey": "client-public.pem",     // путь к PEM-файлу (относительно конфига)
///                                             // либо сам PEM-текст с заголовком -----BEGIN
///       "port": 27015,                        // UDP-порт игроков на машине A
///       "gameIp": "127.0.0.1",                // IP игрового сервера (машина B)
///       "gamePort": 7777,                     // UDP-порт игрового сервера
///       "capture": true,                      // перехват ответов (по умолч. true)
///       "aliases": true,                      // loopback-алиасы (по умолч. true)
///       "tcp": false,                         // TCP-проксирование (по умолч. false)
///       "tcpPort": 27015                      // TCP-порт на машине A (по умолч. = port)
///     }
///   ]
/// }
/// </summary>
public static class ServerConfig
{
    public static bool TryLoad(string path, out List<ClientConfig> clients, out string? error)
    {
        clients = new List<ClientConfig>();
        error = null;

        string json;
        try
        {
            json = File.ReadAllText(path);
        }
        catch (Exception ex)
        {
            error = $"Не удалось прочитать конфиг '{path}': {ex.Message}";
            return false;
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(json);
        }
        catch (JsonException ex)
        {
            error = $"Ошибка JSON в '{path}': {ex.Message}";
            return false;
        }

        using (doc)
        {
            if (!doc.RootElement.TryGetProperty("clients", out var clientsElement))
            {
                error = $"Конфиг '{path}' не содержит список 'clients'.";
                return false;
            }

            if (clientsElement.ValueKind != JsonValueKind.Array || clientsElement.GetArrayLength() == 0)
            {
                error = $"Список 'clients' в '{path}' пуст — добавьте хотя бы одного клиента.";
                return false;
            }

            var baseDir = Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".";
            var index = 0;
            foreach (var item in clientsElement.EnumerateArray())
            {
                index++;
                if (!TryParseClient(item, baseDir, path, index, out var client, out var clientError))
                {
                    error = clientError;
                    return false;
                }
                clients.Add(client!);
            }
        }

        var usedUdpPorts = new HashSet<int>();
        var usedTcpPorts = new HashSet<int>();
        foreach (var client in clients)
        {
            if (!usedUdpPorts.Add(client.Port))
            {
                error = $"Два клиента не могут слушать один и тот же UDP-порт игроков {client.Port}.";
                return false;
            }
            if (client.TcpEnabled && !usedTcpPorts.Add(client.TcpPort))
            {
                error = $"TCP-порт {client.TcpPort} уже используется другим клиентом.";
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Генерирует шаблон server.json из client-public.pem в указанном каталоге.
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
            path = Path.Combine(dir, "server.json");
            var json =
                "{\n" +
                "  \"clients\": [\n" +
                "    {\n" +
                "      \"name\": \"client1\",\n" +
                "      \"publicKey\": \"client-public.pem\",\n" +
                "      \"port\": 27015,\n" +
                "      \"gameIp\": \"127.0.0.1\",\n" +
                "      \"gamePort\": 7777,\n" +
                "      \"capture\": true,\n" +
                "      \"aliases\": true,\n" +
                "      \"tcp\": false,\n" +
                "      \"tcpPort\": 27015\n" +
                "    }\n" +
                "  ]\n" +
                "}\n";
            File.WriteAllText(path, json);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool TryParseClient(JsonElement item, string baseDir, string configPath, int index, out ClientConfig? client, out string? error)
    {
        client = null;
        error = null;

        try
        {
            return TryParseClientCore(item, baseDir, configPath, index, out client, out error);
        }
        catch (FormatException ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool TryParseClientCore(JsonElement item, string baseDir, string configPath, int index, out ClientConfig? client, out string? error)
    {
        client = null;
        error = null;

        var result = new ClientConfig();

        if (item.TryGetProperty("name", out var nameElement) && nameElement.ValueKind == JsonValueKind.String)
            result.Name = nameElement.GetString();

        if (!item.TryGetProperty("publicKey", out var pkElement) || pkElement.ValueKind != JsonValueKind.String)
        {
            error = $"Клиент #{index} в '{configPath}': не задан 'publicKey'.";
            return false;
        }
        var publicKey = pkElement.GetString() ?? "";

        if (publicKey.Contains("-----BEGIN"))
        {
            result.PublicKeyPem = publicKey;
        }
        else
        {
            var keyPath = Path.IsPathRooted(publicKey) ? publicKey : Path.Combine(baseDir, publicKey);
            if (!File.Exists(keyPath))
            {
                error = $"Клиент #{index} в '{configPath}': файл публичного ключа '{keyPath}' не найден.";
                return false;
            }
            try
            {
                result.PublicKeyPem = File.ReadAllText(keyPath);
            }
            catch (Exception ex)
            {
                error = $"Клиент #{index} в '{configPath}': не удалось прочитать ключ '{keyPath}': {ex.Message}";
                return false;
            }
        }

        if (!TryGetInt(item, "port", configPath, index, out var port) || !NetUtils.TryParsePort(port.ToString(), out var parsedPort))
        {
            error = $"Клиент #{index} в '{configPath}': 'port' должен быть числом от 1 до 65535.";
            return false;
        }
        result.Port = parsedPort;

        if (!item.TryGetProperty("gameIp", out var gameIpElement) ||
            !IPAddress.TryParse(gameIpElement.GetString(), out var gameIp) ||
            gameIp.AddressFamily != AddressFamily.InterNetwork)
        {
            error = $"Клиент #{index} в '{configPath}': 'gameIp' должен быть IPv4-адресом.";
            return false;
        }
        result.GameIp = gameIp;

        if (!TryGetInt(item, "gamePort", configPath, index, out var gamePort) || gamePort is < 1 or > 65535)
        {
            error = $"Клиент #{index} в '{configPath}': 'gamePort' должен быть числом от 1 до 65535.";
            return false;
        }
        result.GamePort = (ushort)gamePort;

        result.CaptureReplies = GetBool(item, "capture", true);
        result.LoopbackAliases = GetBool(item, "aliases", true);
        result.TcpEnabled = GetBool(item, "tcp", false);

        result.TcpPort = result.Port;
        if (TryGetInt(item, "tcpPort", configPath, index, out var tcpPort))
        {
            if (tcpPort is < 1 or > 65535)
            {
                error = $"Клиент #{index} в '{configPath}': 'tcpPort' должен быть числом от 1 до 65535.";
                return false;
            }
            result.TcpPort = tcpPort;
        }

        // Проверяем, что публичный ключ действительно парсится.
        try
        {
            using var _ = TunnelKeys.ImportPublicPem(result.PublicKeyPem);
        }
        catch (Exception ex)
        {
            error = $"Клиент #{index} в '{configPath}': публичный ключ не является допустимым PEM-ключом: {ex.Message}";
            return false;
        }

        client = result;
        return true;
    }

    private static bool TryGetInt(JsonElement item, string property, string configPath, int index, out int value)
    {
        value = 0;
        if (!item.TryGetProperty(property, out var element))
            return false;
        if (element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out var number))
        {
            value = number;
            return true;
        }
        if (element.ValueKind == JsonValueKind.String && int.TryParse(element.GetString(), out var text))
        {
            value = text;
            return true;
        }
        throw new FormatException($"Клиент #{index} в '{configPath}': '{property}' должен быть целым числом.");
    }

    private static bool GetBool(JsonElement item, string property, bool defaultValue)
    {
        if (!item.TryGetProperty(property, out var element))
            return defaultValue;
        if (element.ValueKind == JsonValueKind.True)
            return true;
        if (element.ValueKind == JsonValueKind.False)
            return false;
        return defaultValue;
    }
}
