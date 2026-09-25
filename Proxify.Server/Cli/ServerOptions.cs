using Proxify.Common.Config;

namespace Proxify.Server.Cli;

/// <summary>
/// Разобранные аргументы командной строки прокси-сервера.
/// При ошибке заполняется <see cref="Error"/> (и <see cref="ShowUsage"/>, если
/// пользователю стоит показать справку); при запуске — остальные поля.
/// </summary>
public sealed record ServerOptions
{
    public bool HelpRequested { get; init; }

    /// <summary>Показывать ли справку по аргументам (при ошибке парсинга/валидации).</summary>
    public bool ShowUsage { get; init; }

    public string? Error { get; init; }

    /// <summary>Режим --configgen: каталог с client-public.pem (иначе null).</summary>
    public string? ConfiggenDir { get; init; }

    public int TunnelPort { get; init; }

    /// <summary>Путь к YAML-конфигу (для диагностики).</summary>
    public string ConfigPath { get; init; } = "";

    /// <summary>Загруженные правила (клиенты) из server.yml.</summary>
    public List<ClientConfig> Clients { get; init; } = new();
}