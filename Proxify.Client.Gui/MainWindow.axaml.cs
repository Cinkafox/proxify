using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Proxify.Client.Gui.Support;
using Proxify.Client.Sessions;
using Proxify.Common.Crypto;
using Proxify.Common.Networking;

namespace Proxify.Client.Gui;

/// <summary>
/// Главное окно GUI-клиента (Avalonia, Windows/Linux). Разметка — в MainWindow.axaml;
/// этот код-бихайнд (code-behind) содержит только логику.
///
/// Вкладка «Клиент»: адрес прокси-сервера (IP/хост и порт туннеля), локальный порт,
/// закрытый ключ в отдельном поле, запуск/остановка сеанса и журнал событий.
/// Вкладка «Генерация ключей»: создание пары ключей P-256 с сохранением в файлы.
///
/// ProxySession и вспомогательные классы пишут диагностику через Console — вывод
/// перенаправляется в журнал на окне (см. GuiLogWriter).
/// </summary>
public sealed partial class MainWindow : Window
{
    private readonly GuiLogWriter _logWriter = new();

    private CancellationTokenSource? _runCts;
    private ProxySession? _session;
    private volatile bool _running;
    private string _keyFilePath = "";

    public MainWindow()
    {
        InitializeComponent();

        StartButton.Click += OnStartClicked;
        StopButton.Click += OnStopClicked;
        LoadKeyButton.Click += OnLoadKeyClicked;
        GenerateButton.Click += OnGenerateClicked;
        SavePrivateKeyButton.Click += (_, _) => SavePem(GenPrivateBox.Text ?? "", "client-private.pem");
        SavePublicKeyButton.Click += (_, _) => SavePem(GenPublicBox.Text ?? "", "client-public.pem");
        UseKeyButton.Click += OnUseKeyClicked;

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
        LogBox.Text += text;
        LogBox.CaretIndex = LogBox.Text.Length;
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
        wireObfuscation = WireObfuscationBox.IsChecked ?? false;

        var host = HostBox.Text?.Trim() ?? "";
        var tunnelPortText = TunnelPortBox.Text?.Trim() ?? "";

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

        var pem = PrivateKeyBox.Text;
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
            PrivateKeyBox.Text = await File.ReadAllTextAsync(path);
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
            GenPrivateBox.Text = privatePem;
            GenPublicBox.Text = publicPem;
            SavePrivateKeyButton.IsEnabled = true;
            SavePublicKeyButton.IsEnabled = true;
            UseKeyButton.IsEnabled = true;
            AppendLine("[gui] Сгенерирована новая пара ключей P-256.");
        }
        catch (Exception ex)
        {
            ShowWarning($"Не удалось сгенерировать ключи: {ex.Message}");
        }
    }

    private void OnUseKeyClicked(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(GenPrivateBox.Text))
            return;
        PrivateKeyBox.Text = GenPrivateBox.Text;
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
        StartButton.IsEnabled = !running;
        StopButton.IsEnabled = running;
        HostBox.IsReadOnly = running;
        TunnelPortBox.IsReadOnly = running;
        WireObfuscationBox.IsEnabled = !running;
        PrivateKeyBox.IsReadOnly = running || PrivateKeyBox.IsReadOnly;
        LoadKeyButton.IsEnabled = !running;
        StatusText.Text = running ? "Статус: работает" : "Статус: остановлен";
    }

    private async void ShowWarning(string message)
        => await WarningDialog.Show(this, message);

    // ---------- Настройки ----------

    private void LoadSettingsIntoUi()
    {
        var settings = GuiSettings.Load();
        HostBox.Text = settings.ServerHost;
        TunnelPortBox.Text = settings.TunnelPort;
        WireObfuscationBox.IsChecked = settings.WireObfuscation;
        _keyFilePath = settings.KeyFilePath;

        if (_keyFilePath.Length > 0 && File.Exists(_keyFilePath))
        {
            try
            {
                PrivateKeyBox.Text = File.ReadAllText(_keyFilePath);
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
            ServerHost = HostBox.Text?.Trim() ?? "",
            TunnelPort = TunnelPortBox.Text?.Trim() ?? "",
            KeyFilePath = _keyFilePath,
            WireObfuscation = WireObfuscationBox.IsChecked ?? false,
        }.Save();
    }
}