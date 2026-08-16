using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using Proxify.Common;

namespace Proxify.Client;

/// <summary>
/// Признак включённого TCP-проксирования на прокси-сервере.
/// Заполняется из PONG (руководящий сигнал сервера) и может обновляться
/// в процессе работы (например, после перезапуска сервера с другой конфигурацией).
/// </summary>
public sealed class ServerTcpStatus
{
    private int _enabled;

    public bool Enabled => Volatile.Read(ref _enabled) == 1;

    public void Set(bool value) => Volatile.Write(ref _enabled, value ? 1 : 0);
}

/// <summary>
/// Базовое TCP-проксирование через UDP-туннель (без подмены исходного IP).
///
/// Реальный клиент устанавливает TCP-соединение с прокси-сервером (--port);
/// сервер присваивает соединению connId и уведомляет прокси-клиент кадром
/// TcpOpen. Прокси-клиент соединяется с локальным игровым сервером
/// (--game-ip:--game-port) по TCP, данные в обе стороны передаются кадрами
/// TcpData, закрытие — TcpClose.
///
/// Работает только если прокси-сервер включил TCP-проксирование — клиент узнаёт
/// об этом из PONG (см. <see cref="ServerTcpStatus"/>) и не имеет собственного флага.
///
/// Ограничение: игровой сервер видит соединения с адреса машины B, а не с
/// адреса реального клиента (TCP не позволяет подменять source как UDP).
/// </summary>
public sealed class TcpRelay : IDisposable
{
    private readonly IPAddress _gameIp;
    private readonly ushort _gamePort;
    private readonly UdpClient _tunnel;
    private readonly IPEndPoint _proxyServer;
    private readonly TunnelCipher? _cipher;
    private readonly TunnelStats _stats;
    private readonly ServerTcpStatus _serverTcp;
    private readonly ConcurrentDictionary<uint, TcpSession> _sessions = new();
    private int _disabledWarned;

    public TcpRelay(
        IPAddress gameIp,
        ushort gamePort,
        UdpClient tunnel,
        IPEndPoint proxyServer,
        TunnelCipher? cipher,
        TunnelStats stats,
        ServerTcpStatus serverTcp)
    {
        _gameIp = gameIp;
        _gamePort = gamePort;
        _tunnel = tunnel;
        _proxyServer = proxyServer;
        _cipher = cipher;
        _stats = stats;
        _serverTcp = serverTcp;
    }

    /// <summary>
    /// Обрабатывает TCP-кадр (TcpOpen/TcpData/TcpClose), полученный из туннеля.
    /// </summary>
    public void OnFrame(byte[] buffer, int length)
    {
        if (!_serverTcp.Enabled)
        {
            if (Interlocked.Exchange(ref _disabledWarned, 1) == 0)
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Сервер не включил TCP-проксирование (--tcp) — TCP-кадры игнорируются.");
            return;
        }

        switch (Frame.PeekFrameType(buffer, length))
        {
            case Frame.TypeTcpOpen:
                HandleOpen(buffer, length);
                break;
            case Frame.TypeTcpData:
                HandleData(buffer, length);
                break;
            case Frame.TypeTcpClose:
                HandleClose(buffer, length);
                break;
        }
    }

    private void HandleOpen(byte[] buffer, int length)
    {
        if (!Frame.TryDecodeTcpOpen(buffer, length, _cipher, out var clientIp, out var clientPort, out var connId))
        {
            Interlocked.Increment(ref _stats.BadFrames);
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] Не удалось разобрать TcpOpen.");
            return;
        }

        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Открытие соединения от {clientIp}:{clientPort} (connId {connId}).");
        var session = new TcpSession(connId, _gameIp, _gamePort, _tunnel, _proxyServer, _cipher, _stats, this);
        if (_sessions.TryAdd(connId, session))
        {
            _ = Task.Run(session.RunAsync);
        }
        else
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] connId {connId} уже используется.");
            session.Dispose();
        }
    }

    private void HandleData(byte[] buffer, int length)
    {
        if (!Frame.TryDecodeTcpData(buffer, length, _cipher, out var connId, out var payload))
        {
            Interlocked.Increment(ref _stats.BadFrames);
            return;
        }

        Interlocked.Increment(ref _stats.PacketsIn);
        if (_sessions.TryGetValue(connId, out var session))
        {
            session.Forward(payload);
        }
        else
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [!] TcpData для неизвестного connId {connId}.");
        }
    }

    private void HandleClose(byte[] buffer, int length)
    {
        if (!Frame.TryDecodeTcpClose(buffer, length, _cipher, out var connId))
        {
            Interlocked.Increment(ref _stats.BadFrames);
            return;
        }

        if (_sessions.TryRemove(connId, out var session))
            session.CloseFromRemote();
    }

    internal void OnSessionClosed(uint connId) => _sessions.TryRemove(connId, out _);

    public void Dispose()
    {
        foreach (var session in _sessions.Values)
            session.Dispose();
        _sessions.Clear();
    }

    private sealed class TcpSession : IDisposable
    {
        private readonly uint _connId;
        private readonly IPAddress _gameIp;
        private readonly ushort _gamePort;
        private readonly UdpClient _tunnel;
        private readonly IPEndPoint _proxyServer;
        private readonly TunnelCipher? _cipher;
        private readonly TunnelStats _stats;
        private readonly TcpRelay _relay;

        // Данные, полученные из туннеля до/во время соединения с игровым сервером.
        private readonly Channel<byte[]> _toGame = Channel.CreateUnbounded<byte[]>();
        private TcpClient? _client;
        private NetworkStream? _stream;
        private int _closeSent;

        public TcpSession(
            uint connId,
            IPAddress gameIp,
            ushort gamePort,
            UdpClient tunnel,
            IPEndPoint proxyServer,
            TunnelCipher? cipher,
            TunnelStats stats,
            TcpRelay relay)
        {
            _connId = connId;
            _gameIp = gameIp;
            _gamePort = gamePort;
            _tunnel = tunnel;
            _proxyServer = proxyServer;
            _cipher = cipher;
            _stats = stats;
            _relay = relay;
        }

        public async Task RunAsync()
        {
            TcpClient? client = null;
            NetworkStream? stream = null;
            try
            {
                client = new TcpClient();
                using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.ConnectAsync(_gameIp, _gamePort, connectCts.Token);
                stream = client.GetStream();
                _client = client;
                _stream = stream;
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Соединение с игровым сервером установлено (connId {_connId}).");

                var writer = Task.Run(WriterLoopAsync);
                try
                {
                    await ReaderLoopAsync(stream);
                }
                finally
                {
                    _toGame.Writer.TryComplete();
                    await writer;
                }
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Не удалось подключиться к игровому серверу (connId {_connId}): таймаут 10 с.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Ошибка TCP-соединения (connId {_connId}): {ex.Message}");
            }
            finally
            {
                SendClose();
                Close();
                _relay.OnSessionClosed(_connId);
            }
        }

        private async Task WriterLoopAsync()
        {
            try
            {
                await foreach (var data in _toGame.Reader.ReadAllAsync())
                {
                    var stream = _stream;
                    if (stream == null)
                        break;

                    await stream.WriteAsync(data);
                    Interlocked.Increment(ref _stats.Injected);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Ошибка записи в игровой сервер (connId {_connId}): {ex.Message}");
            }
        }

        private async Task ReaderLoopAsync(NetworkStream stream)
        {
            var buffer = new byte[16384];
            while (true)
            {
                int read;
                try
                {
                    read = await stream.ReadAsync(buffer);
                }
                catch (IOException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }

                if (read <= 0)
                    break;

                var frame = Frame.EncodeTcpData(_connId, buffer.AsSpan(0, read), _cipher);
                try
                {
                    await _tunnel.SendAsync(frame, _proxyServer);
                    Interlocked.Increment(ref _stats.PacketsOut);
                    Interlocked.Increment(ref _stats.RepliesRelayed);
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp ответ ->] connId {_connId} ({read} байт)");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Ошибка отправки (connId {_connId}): {ex.Message}");
                    break;
                }
            }
        }

        /// <summary>
        /// Данные из туннеля (от реального клиента) -> в очередь записи игровому серверу.
        /// </summary>
        public void Forward(byte[] data) => _toGame.Writer.TryWrite(data);

        /// <summary>
        /// Закрытие инициировано прокси-сервером (реальный клиент закрыл соединение).
        /// </summary>
        public void CloseFromRemote()
        {
            SendClose();
            Close();
        }

        private void SendClose()
        {
            if (Interlocked.Exchange(ref _closeSent, 1) != 0)
                return;

            try
            {
                _tunnel.Send(Frame.EncodeTcpClose(_connId, _cipher), _proxyServer);
            }
            catch (Exception)
            {
                // сокет туннеля может быть уже закрыт — игнорируем
            }
        }

        private void Close()
        {
            _toGame.Writer.TryComplete();
            _stream?.Dispose();
            _client?.Dispose();
            _stream = null;
            _client = null;
        }

        public void Dispose() => Close();
    }
}
