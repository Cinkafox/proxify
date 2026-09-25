using Proxify.Common.Cli;
using Proxify.Common.Config;
using Proxify.Common.Networking;

namespace Proxify.Server.Cli;

/// <summary>
/// Помощник командной строки прокси-сервера: разбор аргументов (--config,
/// --tunnel-port, --configgen), проверка конфига и генерация шаблона server.yml.
/// Программа (Program.cs) остаётся тонкой и только выполняет оркестрацию.
/// </summary>
public static class ServerCli
{
    public static ArgParser CreateParser() => new ArgParser("Proxify.Server")
        .Add("config", "Путь к YAML-конфигу с правилами (порт/протокол, публичный ключ, игровые параметры)", shortName: 'c')
        .Add("tunnel-port", "UDP-порт туннеля, на который прокси-клиенты (машина B) шлют кадры", shortName: 't')
        .Add("configgen", "Сгенерировать шаблон server.yml из client-public.pem в указанном каталоге и выйти", shortName: 'g');

    /// <summary>
    /// Разбирает аргументы: валидирует --tunnel-port и --config, загружает конфиг
    /// и проверяет, что порт туннеля не совпадает с портом какого-либо правила.
    /// </summary>
    public static ServerOptions Parse(string[] args)
    {
        var cli = CreateParser();
        if (!cli.TryParse(args))
            return new ServerOptions { ShowUsage = true, Error = cli.Error };
        if (cli.HelpRequested)
            return new ServerOptions { HelpRequested = true };

        var configgenDir = cli.Get("configgen");
        if (!string.IsNullOrWhiteSpace(configgenDir))
            return new ServerOptions { ConfiggenDir = configgenDir };

        if (!NetUtils.TryParsePort(cli.Get("tunnel-port"), out var tunnelPort))
            return new ServerOptions { ShowUsage = true, Error = $"'--tunnel-port {cli.Get("tunnel-port")}' не является допустимым (ожидается число от 1 до 65535)." };

        var configPath = cli.Get("config");
        if (string.IsNullOrWhiteSpace(configPath))
            return new ServerOptions { ShowUsage = true, Error = "Не задан '--config'. Используйте --configgen, чтобы создать шаблон, или укажите путь к конфигу." };

        if (!ServerConfig.TryLoad(configPath, out var clients, out var configError))
            return new ServerOptions { Error = configError };

        foreach (var client in clients)
        {
            if (tunnelPort == client.Port)
            {
                var name = string.IsNullOrWhiteSpace(client.Name) ? "(без имени)" : client.Name;
                return new ServerOptions { Error = $"'--tunnel-port {tunnelPort}' совпадает с портом клиента '{name}' — конфликт." };
            }
        }

        return new ServerOptions { TunnelPort = tunnelPort, ConfigPath = configPath, Clients = clients };
    }

    /// <summary>
    /// Режим --configgen: генерирует шаблон server.yml из client-public.pem.
    /// Возвращает текст ошибки или null при успехе.
    /// </summary>
    public static string? GenerateTemplate(string configgenDir)
    {
        if (!ServerConfig.TryGenerateTemplate(configgenDir, out var path, out var genError))
            return genError;

        Console.WriteLine($"Сгенерирован шаблон конфига: {path}");
        Console.WriteLine("Отредактируйте порт/игровые параметры при необходимости и запустите сервер с --config.");
        return null;
    }
}