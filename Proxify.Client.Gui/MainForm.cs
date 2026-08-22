using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Proxify.Client;
using Proxify.Common;

namespace Proxify.Client.Gui;

/// <summary>
/// Главное окно GUI-клиента.
///
/// Вкладка «Клиент»: адрес прокси-сервера (IP/хост и порт туннеля), локальный порт,
/// закрытый ключ в отдельном поле, запуск/остановка сеанса и журнал событий.
/// Вкладка «Генерация ключей»: создание пары ключей P-256 с сохранением в файлы.
///
/// ProxySession и вспомогательные классы пишут диагностику через Console — вывод
/// перенаправляется в журнал на форме (см. GuiLogWriter).
/// </summary>
public sealed class MainForm : Form
{
    private static readonly Font MonoFont = new("Consolas", 9F);

    // --- Вкладка «Клиент» ---
    private readonly TextBox _hostBox = new();
    private readonly TextBox _tunnelPortBox = new();
    private readonly TextBox _privateKeyBox;
    private readonly TextBox _logBox;
    private readonly Button _startButton = new() { Text = "Запустить", AutoSize = true };
    private readonly Button _stopButton = new() { Text = "Остановить", AutoSize = true, Enabled = false };
    private readonly Button _loadKeyButton = new() { Text = "Загрузить из файла…", AutoSize = true };
    private readonly Label _statusLabel =
        new() { Text = "Статус: остановлен", AutoSize = true, TextAlign = ContentAlignment.MiddleLeft };

    // --- Вкладка «Генерация ключей» ---
    private readonly TextBox _genPrivateBox;
    private readonly TextBox _genPublicBox;
    private readonly Button _generateButton = new() { Text = "Сгенерировать пару ключей", AutoSize = true };
    private readonly Button _savePrivateKeyButton = new() { Text = "Сохранить закрытый…", AutoSize = true, Enabled = false };
    private readonly Button _savePublicKeyButton = new() { Text = "Сохранить открытый…", AutoSize = true, Enabled = false };
    private readonly Button _useKeyButton =
        new() { Text = "Перенести закрытый ключ в поле клиента", AutoSize = true, Enabled = false };

    private readonly ConcurrentQueue<string> _pendingLog = new();
    private readonly GuiLogWriter _logWriter = new();

    private CancellationTokenSource? _runCts;
    private ProxySession? _session;
    private volatile bool _running;
    private string _keyFilePath = "";

    public MainForm()
    {
        Text = "Proxify Client";
        Font = new Font("Segoe UI", 9F);
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(760, 560);
        Size = new Size(880, 660);

        _privateKeyBox = CreatePemBox(readOnly: false);
        _logBox = CreatePemBox(readOnly: true);
        _logBox.ScrollBars = ScrollBars.Both;
        _genPrivateBox = CreatePemBox(readOnly: true);
        _genPublicBox = CreatePemBox(readOnly: true);

        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.Add(BuildClientTab());
        tabs.TabPages.Add(BuildKeygenTab());
        Controls.Add(tabs);

        _startButton.Click += OnStartClicked;
        _stopButton.Click += OnStopClicked;
        _loadKeyButton.Click += OnLoadKeyClicked;
        _generateButton.Click += OnGenerateClicked;
        _savePrivateKeyButton.Click += (_, _) => SavePem(_genPrivateBox.Text, "client-private.pem");
        _savePublicKeyButton.Click += (_, _) => SavePem(_genPublicBox.Text, "client-public.pem");
        _useKeyButton.Click += OnUseKeyClicked;

        Shown += (_, _) => DrainPendingLog();
        FormClosing += OnFormClosing;
    }

    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        Console.SetOut(_logWriter);
        _logWriter.TextWritten += AppendLogText;
        LoadSettingsIntoUi();
        AppendLine(AdminRights.IsGranted()
            ? "[gui] Права администратора: есть."
            : "[gui] [!] Запуск без прав администратора.");
    }

    // ---------- Построение интерфейса ----------

    private static TextBox CreatePemBox(bool readOnly) => new()
    {
        Multiline = true,
        ReadOnly = readOnly,
        ScrollBars = ScrollBars.Vertical,
        WordWrap = false,
        Font = MonoFont,
        Dock = DockStyle.Fill,
    };

    private static GroupBox NewGroup(string title, Control content)
    {
        var group = new GroupBox { Text = title, Dock = DockStyle.Fill };
        content.Dock = DockStyle.Fill;
        group.Controls.Add(content);
        return group;
    }

    private static TableLayoutPanel NewFieldGrid(int rows)
    {
        var grid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = rows,
            AutoSize = true,
            Padding = new Padding(4),
        };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 250));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (var i = 0; i < rows; i++)
            grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        return grid;
    }

    private static void AddFieldRow(TableLayoutPanel grid, int row, string caption, Control editor)
    {
        grid.Controls.Add(new Label
        {
            Text = caption,
            AutoSize = true,
            Anchor = AnchorStyles.Left,
            Margin = new Padding(3, 6, 3, 3),
        }, 0, row);

        editor.Dock = DockStyle.Fill;
        editor.Margin = new Padding(3, 3, 3, 6);
        grid.Controls.Add(editor, 1, row);
    }

    private TabPage BuildClientTab()
    {
        var page = new TabPage("Клиент") { Padding = new Padding(8) };

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Margin = new Padding(0) };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 175));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));

        // --- Подключение ---
        var connectionGrid = NewFieldGrid(rows: 3);
        AddFieldRow(connectionGrid, 0, "Адрес сервера (IP или хост):", _hostBox);
        AddFieldRow(connectionGrid, 1, "Порт туннеля UDP:", _tunnelPortBox);
        
        root.Controls.Add(NewGroup("Подключение к прокси-серверу (машина A)", connectionGrid), 0, 0);

        // --- Закрытый ключ (отдельное поле) ---
        var keyGroupContent = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Margin = new Padding(4),
        };
        keyGroupContent.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
        keyGroupContent.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
        keyGroupContent.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        keyGroupContent.Controls.Add(_privateKeyBox, 0, 0);

        var keyButtons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = false };
        keyButtons.Controls.Add(_loadKeyButton);
        keyButtons.Controls.Add(new Label
        {
            Text = "Формат: PEM PKCS#8 (файл client-private.pem)",
            AutoSize = true,
            Margin = new Padding(12, 6, 0, 0),
            ForeColor = SystemColors.GrayText,
        });
        keyGroupContent.Controls.Add(keyButtons, 0, 1);

        var keyGroup = new GroupBox { Text = "Закрытый ключ клиента", Dock = DockStyle.Fill };
        keyGroup.Controls.Add(keyGroupContent);
        root.Controls.Add(keyGroup, 0, 1);

        // --- Запуск / остановка ---
        var runFlow = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = false };
        runFlow.Controls.Add(_startButton);
        runFlow.Controls.Add(_stopButton);
        runFlow.Controls.Add(_statusLabel);
        _statusLabel.Margin = new Padding(16, 8, 0, 0);
        root.Controls.Add(runFlow, 0, 2);

        // --- Журнал ---
        root.Controls.Add(NewGroup("Журнал", _logBox), 0, 3);

        page.Controls.Add(root);
        return page;
    }

    private TabPage BuildKeygenTab()
    {
        var page = new TabPage("Генерация ключей") { Padding = new Padding(8) };

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Margin = new Padding(0) };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));

        root.Controls.Add(new Label
        {
            Text = "Пара ключей ECDSA P-256 для аутентификации клиента. Отправьте открытый ключ " +
                   "(client-public.pem) администратору машины A — он должен быть указан в конфиге сервера.",
            AutoSize = true,
            Margin = new Padding(4),
        }, 0, 0);

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = false };
        buttons.Controls.Add(_generateButton);
        buttons.Controls.Add(_savePrivateKeyButton);
        buttons.Controls.Add(_savePublicKeyButton);
        buttons.Controls.Add(_useKeyButton);
        root.Controls.Add(buttons, 0, 1);

        root.Controls.Add(NewGroup("Закрытый ключ (PKCS#8 PEM)", _genPrivateBox), 0, 2);
        root.Controls.Add(NewGroup("Открытый ключ (SPKI PEM)", _genPublicBox), 0, 3);

        page.Controls.Add(root);
        return page;
    }

    // ---------- Журнал ----------

    private void AppendLogText(string text)
    {
        if (IsHandleCreated && !IsDisposed)
        {
            BeginInvoke(() => _logBox.AppendText(text));
        }
        else
        {
            _pendingLog.Enqueue(text);
        }
    }

    private void DrainPendingLog()
    {
        while (_pendingLog.TryDequeue(out var text))
            _logBox.AppendText(text);
    }

    // ---------- Действия ----------

    private void OnStartClicked(object? sender, EventArgs e)
    {
        if (_running)
            return;

        if (!TryBuildSession(out var proxyServer, out var identityKey, out var localPort))
            return;

        SaveSettingsFromUi();

        SetRunning(true);
        AppendLine($"[gui] Запуск: сервер {proxyServer}, локальный порт {(localPort?.ToString() ?? "авто")}.");

        _runCts = new CancellationTokenSource();
        _ = RunSessionAsync(proxyServer, identityKey, localPort, _runCts.Token);
    }

    private bool TryBuildSession(out IPEndPoint proxyServer, out ECDsa identityKey, out int? localPort)
    {
        proxyServer = null!;
        identityKey = null!;
        localPort = null;

        var host = _hostBox.Text.Trim();
        var tunnelPortText = _tunnelPortBox.Text.Trim();

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

    private async Task RunSessionAsync(IPEndPoint proxyServer, ECDsa identityKey, int? localPort, CancellationToken token)
    {
        var session = new ProxySession(proxyServer, identityKey, localPort);
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

    private void OnStopClicked(object? sender, EventArgs e)
    {
        AppendLine("[gui] Остановка...");
        _runCts?.Cancel();
    }

    private void OnLoadKeyClicked(object? sender, EventArgs e)
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Выберите файл закрытого ключа",
            Filter = "PEM-файлы (*.pem)|*.pem|Все файлы (*.*)|*.*",
        };
        if (dialog.ShowDialog(this) != DialogResult.OK)
            return;

        try
        {
            _privateKeyBox.Text = File.ReadAllText(dialog.FileName);
            _keyFilePath = dialog.FileName;
        }
        catch (Exception ex)
        {
            ShowWarning($"Не удалось прочитать файл ключа: {ex.Message}");
        }
    }

    private void OnGenerateClicked(object? sender, EventArgs e)
    {
        try
        {
            var (privatePem, publicPem) = TunnelKeys.GeneratePem();
            _genPrivateBox.Text = privatePem;
            _genPublicBox.Text = publicPem;
            _savePrivateKeyButton.Enabled = true;
            _savePublicKeyButton.Enabled = true;
            _useKeyButton.Enabled = true;
            AppendLine("[gui] Сгенерирована новая пара ключей P-256.");
        }
        catch (Exception ex)
        {
            ShowWarning($"Не удалось сгенерировать ключи: {ex.Message}");
        }
    }

    private void OnUseKeyClicked(object? sender, EventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_genPrivateBox.Text))
            return;
        _privateKeyBox.Text = _genPrivateBox.Text;
        _keyFilePath = "";
        AppendLine("[gui] Сгенерированный закрытый ключ перенесён в поле клиента на вкладке «Клиент».");
    }

    private void SavePem(string pem, string defaultFileName)
    {
        if (string.IsNullOrWhiteSpace(pem))
            return;

        using var dialog = new SaveFileDialog
        {
            Title = "Сохранить ключ",
            FileName = defaultFileName,
            Filter = "PEM-файлы (*.pem)|*.pem|Все файлы (*.*)|*.*",
        };
        if (dialog.ShowDialog(this) != DialogResult.OK)
            return;

        try
        {
            File.WriteAllText(dialog.FileName, pem);
            AppendLine($"[gui] Ключ сохранён: {dialog.FileName}");
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
        _startButton.Enabled = !running;
        _stopButton.Enabled = running;
        _hostBox.ReadOnly = running;
        _tunnelPortBox.ReadOnly = running;
        _privateKeyBox.ReadOnly = running || _privateKeyBox.ReadOnly;
        _loadKeyButton.Enabled = !running;
        _statusLabel.Text = running ? "Статус: работает" : "Статус: остановлен";
    }

    private void AppendLine(string line) => AppendLogText(line + Environment.NewLine);

    private void ShowWarning(string message) =>
        MessageBox.Show(this, message, "Proxify Client", MessageBoxButtons.OK, MessageBoxIcon.Warning);

    // ---------- Настройки ----------

    private void LoadSettingsIntoUi()
    {
        var settings = GuiSettings.Load();
        _hostBox.Text = settings.ServerHost;
        _tunnelPortBox.Text = settings.TunnelPort;
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
            ServerHost = _hostBox.Text.Trim(),
            TunnelPort = _tunnelPortBox.Text.Trim(),
            KeyFilePath = _keyFilePath,
        }.Save();
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        SaveSettingsFromUi();
        _runCts?.Cancel();
    }
}
