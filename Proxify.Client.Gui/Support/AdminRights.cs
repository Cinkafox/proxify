using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Proxify.Client.Gui.Support;

/// <summary>
/// Проверка повышенных прав: RawSocket-инжекция пакетов в игровой сервер требует
/// запуска процесса с привилегиями. На Windows проверяется роль администратора,
/// на Linux/macOS — euid процесса (root).
/// </summary>
public static class AdminRights
{
    public static bool IsGranted()
    {
        if (OperatingSystem.IsWindows())
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }

        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            return GetEuid() == 0;

        return false;
    }

    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEuid();
}