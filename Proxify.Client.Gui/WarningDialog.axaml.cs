using Avalonia.Controls;

namespace Proxify.Client.Gui;

/// <summary>
/// Модальное окно предупреждения (разметка — в WarningDialog.axaml).
/// </summary>
public sealed partial class WarningDialog : Window
{
    public WarningDialog()
    {
        InitializeComponent();
        OkButton.Click += (_, _) => Close();
    }

    public static async Task Show(Window owner, string message)
    {
        var dialog = new WarningDialog();
        dialog.MessageText!.Text = message;
        await dialog.ShowDialog(owner);
    }
}