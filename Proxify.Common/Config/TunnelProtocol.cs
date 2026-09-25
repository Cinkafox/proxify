namespace Proxify.Common.Config;

/// <summary>
/// Протокол правила проксирования.
///
/// Правила TCP и UDP разделены конфигом: каждое правило server.yml — отдельный
/// прокси-клиент со своей парой ключей, поэтому протокол один на правило.
/// <see cref="Udp"/> — эмуляция UDP с подменой исходного IP игрока;
/// <see cref="Tcp"/> — TCP-релей через туннель (без подмены адреса).
/// </summary>
public enum TunnelProtocol
{
    /// <summary>UDP-проксирование с подменой реального IP игрока.</summary>
    Udp = 0,

    /// <summary>TCP-проксирование через туннель.</summary>
    Tcp = 1,
}