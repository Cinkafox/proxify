using System.Diagnostics;
using Proxify.Client.Gui;

ApplicationConfiguration.Initialize();

// RawSocket-инжекция пакетов требует прав администратора: без них клиент не запускается.
if (!AdminRights.IsGranted())
{
    var exePath = Environment.ProcessPath;
    if (string.IsNullOrEmpty(exePath))
        return;

    try
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = exePath,
            UseShellExecute = true,
            Verb = "runas",
        });
    }
    catch
    {
        // ignored
    }

    return;
}

Application.Run(new MainForm());