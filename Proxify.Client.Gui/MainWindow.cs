using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Proxify.Client.Gui.Support;
using Proxify.Client.Sessions;
using Proxify.Common.Crypto;
using Proxify.Common.Networking;

namespace Proxify.Client.Gui;

/// <summary>
/// Главное окно GUI-клиента (Avalonia, Windows/Linux).
///
/// Вкладка «Клиент»: адрес прокси-сервера (IP/хост и порт туннеля), локальный порт,
/// закрытый ключ в отдельном поле, запуск/остановка сеанса и журнал событий.
/// Вкладка «Генерация ключей»: создание пары ключей P-256 с сохранением в файлы.
///
/// ProxySession и вспомогательные классы пишут диагностику через Console — вывод
/// перенаправляется в журнал на окне (см. GuiLogWriter).
/// </summary>
public sealed class MainWindow : Window
{
    private static readonly FontFamily MonoFont = new("Consolas, DejaVu Sans Mono, monospace");

    // --- Вкладка «Клиент» ---
    private readonly TextBox _hostBox = new();
    private readonly TextBox _tunnelPortBox = new();
    private readonly CheckBox _wireObfuscationBox = new()
    {
        Content = "Внешняя маскировка (совпадать с \"obfuscation\" на сервере)",
        VerticalAlignment = VerticalAlignment.Center,
    };
    private readonly TextBox _privateKeyBox;
    private readonly TextBox _logBox;
    private readonly Button _startButton = new() { Content = "Запустить" };
    private readonly Button _stopButton = new() { Content = "Остановить", IsEnabled = false };
    private readonly Button _loadKeyButton = new() { Content = "Загрузить из файла…" };
    private readonly TextBlock _statusText =
        new() { Text = "Статус: остановлен", VerticalAlignment = VerticalAlignment.Center };

    // --- Вкладка «Генерация ключей» ---
    private readonly TextBox _genPrivateBox;
    private readonly TextBox _genPublicBox;
    private readonly Button _generateButton = new() { Content = "Сгенерировать пару ключей" };
    private readonly Button _savePrivateKeyButton = new() { Content = "Сохранить закрытый…", IsEnabled = false };
    private readonly Button _savePublicKeyButton = new() { Content = "Сохранить открытый…", IsEnabled = false };
    private readonly Button _useKeyButton =
        new() { Content = "Перенести закрытый ключ в поле клиента", IsEnabled = false };

    private readonly GuiLogWriter _logWriter = new();

    private CancellationTokenSource? _runCts;
    private ProxySession? _session;
    private volatile bool _running;
    private string _keyFilePath = "";

    public MainWindow()
    {
        Title = "Proxify Client";
        Width = 880;
        Height = 660;
        MinWidth = 760;
        MinHeight = 560;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;

        _privateKeyBox = CreatePemBox(readOnly: false);
        _logBox = CreatePemBox(readOnly: true);
        _logBox.TextWrapping = TextWrapping.Wrap;
        _genPrivateBox = CreatePemBox(readOnly: true);
        _genPublicBox = CreatePemBox(readOnly: true);

        var tabs = new TabControl();
        tabs.Items.Add(BuildClientTab());
        tabs.Items.Add(BuildKeygenTab());
        Content = tabs;

        _startButton.Click += OnStartClicked;
        _stopButton.Click += OnStopClicked;
        _loadKeyButton.Click += OnLoadKeyClicked;
        _generateButton.Click += OnGenerateClicked;
        _savePrivateKeyButton.Click += (_, _) => SavePem(_genPrivateBox.Text ?? "", "client-private.pem");
        _savePublicKeyButton.Click += (_, _) => SavePem(_genPublicBox.Text ?? "", "client-public.pem");
        _useKeyButton.Click += OnUseKeyClicked;

        // Перенаправляем Console.Out в журнал окна (сессия пишет диагностику в Console).
        _logWriter.TextWritten += AppendLogText;
        Console.SetOut(_logWriter);

        Closing += (_, _) =>
        {
            SaveSettingsFromUi();
            _runCts?.Cancel();
        };
    }

    protected override void OnOpened(EventArgs e)
    {
        base.OnOpened(e);
        LoadSettingsIntoUi();
        AppendLine(AdminRights.IsGranted()
            ? "[gui] Права администратора: есть."
            : "[gui] [!] Запуск без прав администратора.");
    }

    // ---------- Построение интерфейса ----------

    private static TextBox CreatePemBox(bool readOnly) => new()
    {
        AcceptsReturn = true,
        IsReadOnly = readOnly,
        TextWrapping = TextWrapping.NoWrap,
        FontFamily = MonoFont,
        HorizontalAlignment = HorizontalAlignment.Stretch,
        VerticalAlignment = VerticalAlignment.Stretch,
    };

    /// <summary>Группа с заголовком (аналог WinForms GroupBox).</summary>
    private static Border Group(string title, Control content)
    {
        var grid = new Grid { RowDefinitions = new RowDefinitions("Auto,*") };
        grid.Children.Add(new TextBlock
        {
            Text = title,
            FontWeight = FontWeight.SemiBold,
            Margin = new Thickness(0, 0, 0, 6),
        });
        Grid.SetRow(content, 1);
        grid.Children.Add(content);

        return new Border
        {
            BorderBrush = new SolidColorBrush(Color.Parse("#999999")),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(4),
            Padding = new Thickness(8),
            Child = grid,
        };
    }

    private static void AddFieldRow(Grid grid, int row, string caption, Control editor)
    {
        grid.ColumnDefinitions.Add(new ColumnDefinition(GridLength.Auto));
        if (grid.ColumnDefinitions.Count < 2)
            grid.ColumnDefinitions.Add(new ColumnDefinition(GridLength.Star));

        var label = new TextBlock
        {
            Text = caption,
            MinWidth = 190,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 8, 4),
        };
        Grid.SetColumn(label, 0);
        Grid.SetRow(label, row);
        grid.Children.Add(label);

        editor.Margin = new Thickness(0, 0, 0, 4);
        Grid.SetColumn(editor, 1);
        Grid.SetRow(editor, row);
        grid.Children.Add(editor);
    }

    private static void AddButtonGap(Control first, Control second) => second.Margin = new Thickness(6, 0, 0, 0);

    private TabItem BuildClientTab()
    {
        // --- Подключение ---
        var connectionGrid = new Grid { RowDefinitions = new RowDefinitions("Auto,Auto,Auto"), Margin = new Thickness(4) };
        AddFieldRow(connectionGrid, 0, "Адрес сервера (IP или хост):", _hostBox);
        AddFieldRow(connectionGrid, 1, "Порт туннеля UDP:", _tunnelPortBox);
        AddFieldRow(connectionGrid, 2, "Маскировка туннеля:", _wireObfuscationBox);
        var connectionGroup = Group("Подключение к прокси-серверу (машина A)", connectionGrid);

        // --- Закрытый ключ (отдельное поле) ---
        var keyGroupContent = new Grid { RowDefinitions = new RowDefinitions("*,Auto"), Margin = new Thickness(4) };
        keyGroupContent.Children.Add(_privateKeyBox);

        var keyHint = new TextBlock
        {
            Text = "Формат: PEM PKCS#8 (файл client-private.pem)",
            Foreground = Brushes.Gray,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(12, 0, 0, 0),
        };
        var keyButtons = new StackPanel { Orientation = Orientation.Horizontal };
        keyButtons.Children.Add(_loadKeyButton);
        keyButtons.Children.Add(keyHint);
        Grid.SetRow(keyButtons, 1);
        keyGroupContent.Children.Add(keyButtons);
        var keyGroup = Group("Закрытый ключ клиента", keyGroupContent);

        // --- Запуск / остановка ---
        var runFlow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin = new Thickness(4, 8, 4, 8),
        };
        AddButtonGap(_startButton, _stopButton);
        runFlow.Children.Add(_startButton);
        runFlow.Children.Add(_stopButton);
        _statusText.Margin = new Thickness(16, 0, 0, 0);
        runFlow.Children.Add(_statusText);

        // --- Журнал ---
        var logGroup = Group("Журнал", _logBox);

        var root = new Grid { RowDefinitions = new RowDefinitions("Auto,175,Auto,*"), Margin = new Thickness(8) };
        root.Children.Add(connectionGroup);
        Grid.SetRow(keyGroup, 1);
        root.Children.Add(keyGroup);
        Grid.SetRow(runFlow, 2);
        root.Children.Add(runFlow);
        Grid.SetRow(logGroup, 3);
        root.Children.Add(logGroup);

        return new TabItem { Header = "Клиент", Content = root };
    }

    private TabItem BuildKeygenTab()
    {
        var desc = new TextBlock
        {
            Text = "Пара ключей ECDSA P-256 для аутентификации клиента. Отправьте открытый ключ " +
                   "(client-public.pem) администратору машины A — он должен быть указан в конфиге сервера.",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(4, 4, 4, 8),
        };

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6, Margin = new Thickness(4, 0, 4, 8) };
        buttons.Children.Add(_generateButton);
        buttons.Children.Add(_savePrivateKeyButton);
        buttons.Children.Add(_savePublicKeyButton);
        buttons.Children.Add(_useKeyButton);

        var genPrivateGroup = Group("Закрытый ключ (PKCS#8 PEM)", _genPrivateBox);
        var genPublicGroup = Group("Открытый ключ (SPKI PEM)", _genPublicBox);

        var root = new Grid { RowDefinitions = new RowDefinitions("Auto,Auto,*,*"), Margin = new Thickness(8) };
        root.Children.Add(desc);
        Grid.SetRow(buttons, 1);
        root.Children.Add(buttons);
        Grid.SetRow(genPrivateGroup, 2);
        root.Children.Add(genPrivateGroup);
        Grid.SetRow(genPublicGroup, 3);
        root.Children.Add(genPublicGroup);

        return new TabItem { Header = "Генерация ключей", Content = root };
    }

    // ---------- Журнал ----------

    private void AppendLogText(string text)
    {
        if (Dispatcher.UIThread.CheckAccess())
            AppendToLog(text);
        else
            Dispatcher.UIThread.Post(() => AppendToLog(text));
    }

    private void AppendToLog(string text)
    {
        _logBox.Text += text;
        _logBox.CaretIndex = _logBox.Text.Length;
    }

    private void AppendLine(string line) => AppendLogText(line + Environment.NewLine);

    // ---------- Действия ----------

    private void OnStartClicked(object? sender, RoutedEventArgs e)
    {
        if (_running)
            return;

        if (!TryBuildSession(out var proxyServer, out var identityKey, out var localPort, out var wireObfuscation))
            return;

        SaveSettingsFromUi();

        SetRunning(true);
        AppendLine($"[gui] Запуск: сервер {proxyServer}, локальный порт {(localPort?.ToString() ?? "авто")}, " +
                   $"маскировка {(wireObfuscation ? "вкл" : "выкл")}.");

        _runCts = new CancellationTokenSource();
        _ = RunSessionAsync(proxyServer, identityKey, localPort, wireObfuscation, _runCts.Token);
    }

    private bool TryBuildSession(out IPEndPoint proxyServer, out ECDsa identityKey, out int? localPort, out bool wireObfuscation)
    {
        proxyServer = null!;
        identityKey = null!;
        localPort = null;
        wireObfuscation = _wireObfuscationBox.IsChecked ?? false;

        var host = _hostBox.Text?.Trim() ?? "";
        var tunnelPortText = _tunnelPortBox.Text?.Trim() ?? "";

        if (host.Length == 0)
        {
            ShowWarning("Укажите адрес прокси-сервера.");
            return false;
        }

        if (!NetUtils.TryParsePort(tunnelPortText, out var tunnelPort))
        {
            ShowWarning("Неверный порт туннеля (ожидается число от 1 до 65535).");
            return false;
        }

        if (!NetUtils.TryParseEndpoint($"{host}:{tunnelPort}", out var endpoint))
        {
            ShowWarning($"Не удалось разрешить адрес прокси-сервера '{host}'.");
            return false;
        }

        var pem = _privateKeyBox.Text;
        if (string.IsNullOrWhiteSpace(pem))
        {
            ShowWarning("Введите закрытый ключ (PEM, PKCS#8), загрузите его из файла или сгенерируйте на вкладке «Генерация ключей».");
            return false;
        }

        try
        {
            identityKey = TunnelKeys.ImportPrivatePem(pem);
        }
        catch (Exception ex)
        {
            ShowWarning($"Не удалось прочитать закрытый ключ: {ex.Message}");
            return false;
        }

        proxyServer = endpoint;
        return true;
    }

    private async Task RunSessionAsync(IPEndPoint proxyServer, ECDsa identityKey, int? localPort, bool wireObfuscation, CancellationToken token)
    {
        ProxySession? session;
        try
        {
            session = await ProxySession.CreateAsync(proxyServer, identityKey, localPort, wireObfuscation);
        }
        catch (Exception ex)
        {
            AppendLine($"[!] Не удалось создать сессию: {ex.Message}");
            return;
        }

        if (session == null)
        {
            AppendLine("[!] Авторизация не удалась — смотрите лог в консоли.");
            return;
        }

        _session = session;

        try
        {
            await session.RunAsync(token);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
        {
            AppendLine("[!] Недостаточно прав: RawSocket требует запуска от имени администратора.");
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
        {
            // плановая остановка
        }
        catch (Exception ex)
        {
            AppendLine($"[!] Необработанная ошибка: {ex.Message}");
        }
        finally
        {
            session.Dispose();
            _session = null;
            _runCts?.Dispose();
            _runCts = null;
            SetRunning(false);
            AppendLine("[gui] Клиент остановлен.");
        }
    }

    private void OnStopClicked(object? sender, RoutedEventArgs e)
    {
        AppendLine("[gui] Остановка...");
        _runCts?.Cancel();
    }

    private async void OnLoadKeyClicked(object? sender, RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Выберите файл закрытого ключа",
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("PEM-файлы") { Patterns = new[] { "*.pem" } },
                FilePickerFileTypes.All,
            },
        });
        if (files.Count == 0)
            return;

        var path = files[0].TryGetLocalPath() ?? files[0].Name;
        try
        {
            _privateKeyBox.Text = await File.ReadAllTextAsync(path);
            _keyFilePath = path;
        }
        catch (Exception ex)
        {
            ShowWarning($"Не удалось прочитать файл ключа: {ex.Message}");
        }
    }

    private void OnGenerateClicked(object? sender, RoutedEventArgs e)
    {
        try
        {
            var (privatePem, publicPem) = TunnelKeys.GeneratePem();
            _genPrivateBox.Text = privatePem;
            _genPublicBox.Text = publicPem;
            _savePrivateKeyButton.IsEnabled = true;
            _savePublicKeyButton.IsEnabled = true;
            _useKeyButton.IsEnabled = true;
            AppendLine("[gui] Сгенерирована новая пара ключей P-256.");
        }
        catch (Exception ex)
        {
            ShowWarning($"Не удалось сгенерировать ключи: {ex.Message}");
        }
    }

    private void OnUseKeyClicked(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_genPrivateBox.Text))
            return;
        _privateKeyBox.Text = _genPrivateBox.Text;
        _keyFilePath = "";
        AppendLine("[gui] Сгенерированный закрытый ключ перенесён в поле клиента на вкладке «Клиент».");
    }

    private async void SavePem(string pem, string defaultFileName)
    {
        if (string.IsNullOrWhiteSpace(pem))
            return;

        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Сохранить ключ",
            SuggestedFileName = defaultFileName,
            FileTypeChoices = new[]
            {
                new FilePickerFileType("PEM-файлы") { Patterns = new[] { "*.pem" } },
                FilePickerFileTypes.All,
            },
        });
        if (file == null)
            return;

        var path = file.TryGetLocalPath() ?? file.Name;
        try
        {
            await File.WriteAllTextAsync(path, pem);
            AppendLine($"[gui] Ключ сохранён: {path}");
        }
        catch (Exception ex)
        {
            ShowWarning($"Не удалось сохранить файл: {ex.Message}");
        }
    }

    // ---------- Состояние интерфейса ----------

    private void SetRunning(bool running)
    {
        _running = running;
        _startButton.IsEnabled = !running;
        _stopButton.IsEnabled = running;
        _hostBox.IsReadOnly = running;
        _tunnelPortBox.IsReadOnly = running;
        _wireObfuscationBox.IsEnabled = !running;
        _privateKeyBox.IsReadOnly = running || _privateKeyBox.IsReadOnly;
        _loadKeyButton.IsEnabled = !running;
        _statusText.Text = running ? "Статус: работает" : "Статус: остановлен";
    }

    private void ShowWarning(string message)
    {
        var ok = new Button { Content = "OK", Width = 80, HorizontalAlignment = HorizontalAlignment.Right };
        var panel = new StackPanel { Margin = new Thickness(16), Spacing = 16 };
        panel.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(ok);

        var dialog = new Window
        {
            Title = "Proxify Client",
            Width = 460,
            Height = 200,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Content = panel,
        };
        ok.Click += (_, _) => dialog.Close();
        dialog.ShowDialog(this);
    }

    // ---------- Настройки ----------

    private void LoadSettingsIntoUi()
    {
        var settings = GuiSettings.Load();
        _hostBox.Text = settings.ServerHost;
        _tunnelPortBox.Text = settings.TunnelPort;
        _wireObfuscationBox.IsChecked = settings.WireObfuscation;
        _keyFilePath = settings.KeyFilePath;

        if (_keyFilePath.Length > 0 && File.Exists(_keyFilePath))
        {
            try
            {
                _privateKeyBox.Text = File.ReadAllText(_keyFilePath);
            }
            catch
            {
                // файл недоступен — пользователь введёт ключ вручную
            }
        }
    }

    private void SaveSettingsFromUi()
    {
        new GuiSettings
        {
            ServerHost = _hostBox.Text?.Trim() ?? "",
            TunnelPort = _tunnelPortBox.Text?.Trim() ?? "",
            KeyFilePath = _keyFilePath,
            WireObfuscation = _wireObfuscationBox.IsChecked ?? false,
        }.Save();
    }
}