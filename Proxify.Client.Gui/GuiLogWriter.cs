using System.Text;

namespace Proxify.Client.Gui;

/// <summary>
/// Перенаправляет Console.Out в журнал GUI-клиента.
/// ProxySession и вспомогательные классы пишут диагностику в Console из разных
/// потоков; этот writer доставляет каждый фрагмент текста подписчикам.
/// </summary>
public sealed class GuiLogWriter : TextWriter
{
    public override Encoding Encoding => Encoding.UTF8;

    public event Action<string>? TextWritten;

    public override void Write(char value) => Publish(value.ToString());

    public override void Write(string? value)
    {
        if (!string.IsNullOrEmpty(value))
            Publish(value);
    }

    public override void WriteLine() => Publish(Environment.NewLine);

    public override void WriteLine(string? value) => Publish((value ?? "") + Environment.NewLine);

    private void Publish(string text) => TextWritten?.Invoke(text);
}
