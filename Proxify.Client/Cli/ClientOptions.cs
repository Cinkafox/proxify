using System.Net;
using System.Security.Cryptography;

namespace Proxify.Client.Cli;

/// <summary>
/// Разобранные аргументы командной строки прокси-клиента.
/// При ошибке заполняется <see cref="Error"/> (и <see cref="ShowUsage"/>, если
/// пользователю стоит показать справку); при запуске — остальные поля.
/// </summary>
public sealed record ClientOptions
{
    public bool HelpRequested { get; init; }

    /// <summary>Показывать ли справку по аргументам (при ошибке парсинга/валидации).</summary>
    public bool ShowUsage { get; init; }

    public string? Error { get; init; }

    /// <summary>Режим --keygen: каталог для пары ключей (иначе null).</summary>
    public string? KeygenDir { get; init; }

    public IPEndPoint ProxyServer { get; init; } = null!;

    public string KeyPath { get; init; } = "";

    /// <summary>Загруженный закрытый ключ клиента. Передаётся в сессию, которая владеет им.</summary>
    public ECDsa IdentityKey { get; init; } = null!;

    public int? LocalPort { get; init; }

    public bool WireObfuscation { get; init; }

    /// <summary>
    /// TCP-порт экспорта метрик Prometheus. null — метрики выключены (опция
    /// --metrics-port не задана), эндпоинт /metrics не поднимается.
    /// </summary>
    public int? MetricsPort { get; init; }
}