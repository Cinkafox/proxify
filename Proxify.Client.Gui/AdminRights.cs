using System.Security.Principal;

namespace Proxify.Client.Gui;

/// <summary>
/// Проверка прав администратора: RawSocket-инжекция пакетов в игровой сервер
/// требует запуска процесса с повышенными привилегиями.
/// </summary>
public static class AdminRights
{
    public static bool IsGranted()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
