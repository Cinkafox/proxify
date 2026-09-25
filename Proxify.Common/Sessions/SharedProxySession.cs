using System.Net.Sockets;
using Proxify.Common.Config;
using Proxify.Common.Crypto;
using Proxify.Common.Metrics;

namespace Proxify.Common.Sessions;

/// <summary>
/// Общие поля и методы прокси-сессий обеих машин: прокси-сервера (машина A)
/// и прокси-клиента (машина B).
///
/// Обе стороны туннеля держат общий UDP-сокет туннеля, ручки метрик Prometheus,
/// очередь фоновой обработки кадров и внешний слой маскировки датаграмм
/// (WireObfuscator). Сессионный ключ шифрования и конфиг правила доступны
/// только после рукопожатия — наследники выставляют их абстрактными свойствами.
///
/// Конкретный протокол (эмуляция UDP с подменой исходного IP или TCP-релей)
/// живёт в наследниках: на сервере — Udp/TcpProxySession, на клиенте — тоже
/// парные классы. Шифрование и сердцебиение — общие.
/// </summary>
public abstract class SharedProxySession : IDisposable
{
    protected SharedProxySession(UdpClient tunnel, TunnelMetricsHandle metrics, AsyncWorkQueue work, WireObfuscator? wire)
    {
        Tunnel = tunnel;
        Metrics = metrics;
        Work = work;
        Wire = wire;
    }

    /// <summary>UDP-сокет туннеля (на сервере — общий для всех клиентов).</summary>
    protected UdpClient Tunnel { get; }

    /// <summary>Ручка метрик туннеля этой сессии (Prometheus).</summary>
    public TunnelMetricsHandle Metrics { get; }

    /// <summary>Очередь фоновой обработки пакетов/кадров (сериализует работу по сокету).</summary>
    protected AsyncWorkQueue Work { get; }

    /// <summary>
    /// Внешний слой маскировки датаграмм (null — на проводе внутренний формат).
    /// Ключи выводятся из зарегистрированного публичного ключа клиента.
    /// </summary>
    protected WireObfuscator? Wire { get; }

    /// <summary>Сессионный ключ шифрования туннеля (null до авторизации).</summary>
    public virtual TunnelCipher? Cipher { get; protected set; }

    /// <summary>Конфиг правила клиента (null до авторизации / на сервере — сразу из server.yml).</summary>
    public virtual ClientConfig? Config { get; protected set; }

    /// <summary>
    /// Готовит кадр к отправке в туннель: заворачивает во внешнюю маскирующую
    /// оболочку, если она включена, иначе оставляет внутренний формат как есть.
    /// </summary>
    public byte[] SealFrame(byte[] frame) => Wire != null ? Wire.Wrap(frame) : frame;

    /// <summary>
    /// Освобождение ресурсов сессии. Унаследовано от <see cref="IDisposable"/>,
    /// чтобы <c>using</c> в вызывающем коде закрывал и базовые ресурсы тоже.
    /// </summary>
    public abstract void Dispose();
}