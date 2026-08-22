using System.Text.Json;

namespace Proxify.Client.Gui;

/// <summary>
/// Сохраняемые настройки GUI-клиента (%APPDATA%\Proxify\gui-settings.json).
/// Содержимое закрытого ключа не сохраняется — только путь к файлу ключа.
/// </summary>
public sealed class GuiSettings
{
    public string ServerHost { get; set; } = "";
    public string TunnelPort { get; set; } = "";
    public string KeyFilePath { get; set; } = "";

    private static string GetPath()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Proxify");
        return Path.Combine(dir, "gui-settings.json");
    }

    public static GuiSettings Load()
    {
        try
        {
            var path = GetPath();
            if (File.Exists(path))
                return JsonSerializer.Deserialize<GuiSettings>(File.ReadAllText(path)) ?? new GuiSettings();
        }
        catch
        {
            // повреждённый файл настроек не должен мешать запуску
        }

        return new GuiSettings();
    }

    public void Save()
    {
        try
        {
            var path = GetPath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch
        {
            // нет прав на запись — продолжаем без сохранения
        }
    }
}
