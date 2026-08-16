using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace Proxify.Common;

/// <summary>
/// Управление дополнительными IP-адресами на loopback-интерфейсе.
///
/// Windows: отбрасывает «сырые» UDP-пакеты, исходный адрес которых не назначен ни
/// одному интерфейсу машины. Поэтому реальный IP клиента добавляется как /32-алиас
/// на loopback (WinAPI iphlpapi: GetBestInterface / AddIPAddress / DeleteIPAddress).
/// Это же заставляет ответы игрового сервера (на этот IP) уходить в loopback,
/// где их перехватывает сырой сниффер прокси-клиента.
///
/// Linux: для отправки алиасы не нужны, но нужны для возврата ответов сервера:
/// IP клиента добавляется как /32-адрес на lo (`ip addr add <ip>/32 dev lo`), чтобы
/// ответы маршрутизировались в loopback и попадали в сниффер. Выполняется командой
/// `ip` (iproute2), требуются root или CAP_NET_ADMIN.
/// </summary>
public sealed class LoopbackAliasManager : IDisposable
{
    private const uint ErrorObjectAlreadyExists = 5010; // ERROR_OBJECT_ALREADY_EXISTS
    private const uint ErrorNotSupported = 50;          // ERROR_NOT_SUPPORTED

    private readonly object _lock = new();
    private readonly ConcurrentDictionary<IPAddress, uint> _aliases = new();
    private readonly bool _enabled;
    private readonly bool _isWindows = OperatingSystem.IsWindows();

    private uint? _loopbackIfIndex;
    private bool _disposed;

    public LoopbackAliasManager(bool enabled)
    {
        _enabled = enabled;
    }

    /// <summary>
    /// Добавляет IP как /32-адрес на loopback-интерфейс (идемпотентно).
    /// </summary>
    public void Add(IPAddress ip)
    {
        if (!_enabled)
            return;

        lock (_lock)
        {
            if (_disposed || _aliases.ContainsKey(ip))
                return;

            if (_isWindows)
                AddWindows(ip);
            else
                AddLinux(ip);
        }
    }

    /// <summary>
    /// Удаляет IP-адрес с loopback-интерфейса (только добавленные нами).
    /// </summary>
    public void Remove(IPAddress ip)
    {
        if (!_enabled)
            return;

        lock (_lock)
        {
            if (!_aliases.TryRemove(ip, out var context))
                return;

            if (_isWindows)
            {
                var error = DeleteIPAddress(context);
                if (error != 0 && error != ErrorNotSupported)
                    Console.WriteLine($"[alias] Не удалось удалить {ip}: Win32 error {error}");
            }
            else
            {
                var (exitCode, stderr) = RunIp($"addr del {ip}/32 dev lo");
                if (exitCode != 0)
                    Console.WriteLine($"[alias] Не удалось удалить {ip}: {stderr.Trim()} (код {exitCode})");
            }
        }
    }

    private void AddWindows(IPAddress ip)
    {
        var ifIndex = GetLoopbackIfIndex();
        if (ifIndex == null)
            return;

        var address = ToNetworkOrder(ip);
        var error = AddIPAddress(address, 0xFFFFFFFF, ifIndex.Value, out var context, out _);

        if (error == 0)
        {
            _aliases[ip] = context;
            Console.WriteLine($"[alias] Добавлен loopback-алиас {ip}/32");
        }
        else if (error == ErrorObjectAlreadyExists)
        {
            Console.WriteLine($"[alias] Loopback-алиас {ip}/32 уже существует (не удаляется при остановке)");
        }
        else if (error != ErrorNotSupported)
        {
            Console.WriteLine($"[alias] Не удалось добавить {ip} на loopback: Win32 error {error}");
        }
    }

    private void AddLinux(IPAddress ip)
    {
        var (exitCode, stderr) = RunIp($"addr add {ip}/32 dev lo");

        if (exitCode == 0)
        {
            _aliases[ip] = 0;
            Console.WriteLine($"[alias] Добавлен loopback-алиас {ip}/32");
        }
        else if (stderr.Contains("File exists"))
        {
            Console.WriteLine($"[alias] Loopback-алиас {ip}/32 уже существует (не удаляется при остановке)");
        }
        else
        {
            Console.WriteLine($"[alias] Не удалось добавить {ip} на loopback: {stderr.Trim()} (код {exitCode})");
        }
    }

    private static (int ExitCode, string StdErr) RunIp(string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo("ip", arguments)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };

            using var proc = Process.Start(psi);
            if (proc == null)
                return (-1, "не удалось запустить команду 'ip'");

            var stderr = proc.StandardError.ReadToEnd();
            if (!proc.WaitForExit(5000))
            {
                proc.Kill(entireProcessTree: true);
                return (-1, "превышено время ожидания 'ip'");
            }

            return (proc.ExitCode, stderr);
        }
        catch (Exception ex)
        {
            return (-1, ex.Message);
        }
    }

    private uint? GetLoopbackIfIndex()
    {
        if (_loopbackIfIndex.HasValue)
            return _loopbackIfIndex;

        // Интерфейс, на котором находится 127.0.0.1, — это loopback-интерфейс.
        var error = GetBestInterface(0x7F000001, out var ifIndex);
        if (error != 0)
        {
            Console.WriteLine($"[alias] GetBestInterface: Win32 error {error}");
            return null;
        }

        _loopbackIfIndex = ifIndex;
        return ifIndex;
    }

    private static uint ToNetworkOrder(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed)
                return;
            _disposed = true;

            foreach (var (ip, context) in _aliases)
            {
                if (_isWindows)
                {
                    DeleteIPAddress(context);
                }
                else
                {
                    RunIp($"addr del {ip}/32 dev lo");
                }

                Console.WriteLine($"[alias] Удалён loopback-алиас {ip}/32");
            }

            _aliases.Clear();
        }
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetBestInterface(uint dwDestAddr, out uint pdwBestIfIndex);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint AddIPAddress(uint address, uint ipMask, uint ifIndex, out uint nteContext, out uint nteInstance);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint DeleteIPAddress(uint nteContext);
}
