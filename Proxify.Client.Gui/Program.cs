using System.Diagnostics;
using Avalonia;
using Proxify.Client.Gui;
using Proxify.Client.Gui.Support;

internal static class Program
{
    // Initialization code. Don't use any Avalonia, third-party APIs or any
    // SynchronizationContext-reliant code before AppMain is called.
    [STAThread]
    public static void Main(string[] args)
    {
        // RawSocket-инжекция пакетов требует повышенных прав: на Windows — UAC,
        // на Linux — перезапуск через pkexec. Если элевация недоступна (например,
        // на машине нет pkexec, или пользователь отменил запрос), GUI всё равно
        // запускается: сессия сообщит об отсутствии прав в журнале.
        // Переменная окружения PROXIFY_NO_ELEVATE=1 отключает перезапуск (для
        // автоматизации/CI или запуска в обычной сессии).
        if (!AdminRights.IsGranted() && Environment.GetEnvironmentVariable("PROXIFY_NO_ELEVATE") != "1")
        {
            var exePath = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(exePath) && TryElevate(exePath))
                return;
        }

        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    private static bool TryElevate(string exePath)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = exePath,
                    UseShellExecute = true,
                    Verb = "runas",
                });
                return true;
            }

            // Linux/macOS: polkit-аутентификация через pkexec.
            var psi = new ProcessStartInfo("pkexec", $"\"{exePath}\"") { UseShellExecute = false };
            Process.Start(psi);
            return true;
        }
        catch
        {
            // элевация не удалась — продолжаем без неё
            return false;
        }
    }

    // Avalonia configuration, don't remove; also used by visual designer.
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .LogToTrace();
}