namespace Proxify.Common;

/// <summary>
/// Собирает фрагменты TCP-потока в кадры TcpData с HTTP-ориентированной политикой
/// отправки. Используется с обеих сторон туннеля в цикле чтения: чем меньше сегментов
/// превращается в отдельные UDP-датаграммы, тем меньше накладных расходов, но при
/// этом потоковые данные (HTTP, chunked, SSE, WebSocket) не должны задерживаться.
///
/// Политика отправки:
///   1. Размер: при накоплении <see cref="MaxFramePayload"/> байт кадр уходит сразу
///      (поток больших ответов не копится). Лимит подобран так, чтобы UDP-датаграмма
///      не фрагментировалась на уровне IP (MTU 1500).
///   2. HTTP-заголовки: как только в накопленном буфере появляется конец заголовков
///      (CRLF CRLF), всё накопленное отправляется немедленно — запрос доходит до
///      сервера / ответ до браузера без задержки (в т.ч. для keep-alive: каждый
///      новый запрос/ответ начинается со своих заголовков).
///   3. Поток после заголовков: если буфер заканчивается на CRLF (граница чанка
///      chunked-кодирования или строка SSE) — отправляется немедленно.
///   4. Во всех остальных случаях данные удерживаются на короткий Nagle-подобный
///      интервал (<see cref="DefaultNagleDelay"/>), чтобы объединить мелкие сегменты
///      TCP в один кадр; таймер продлевается по мере поступления новых данных.
///
/// Класс потоконебезопасен для Append: ожидается вызов из одного цикла чтения
/// (или поочерёдно с таймерным сбросом, который защищён внутренней блокировкой).
/// </summary>
public sealed class TcpFrameBatcher : IDisposable
{
    /// <summary>
    /// Максимальный размер полезной нагрузки одного кадра TcpData. При 1400 байтах
    /// полная UDP-датаграмма (3 magic + 1 тип + 12 nonce + 16 tag + 4 connId + 1400)
    /// не превышает 1500-байтовый MTU и не фрагментируется на уровне IP.
    /// </summary>
    public const int MaxFramePayload = 1400;

    /// <summary>До скольких байт сканировать буфер в поисках конца HTTP-заголовков.</summary>
    public const int HeaderEndScanLimit = 8192;

    /// <summary>Nagle-подобная задержка перед отправкой мелкого фрагмента (по умолчанию).</summary>
    public static readonly TimeSpan DefaultNagleDelay = TimeSpan.FromMilliseconds(2);

    private readonly object _sync = new();
    private readonly Action<byte[]> _sendFrame;
    private readonly int _maxFramePayload;
    private readonly TimeSpan _nagleDelay;
    private byte[] _buffer;
    private int _count;
    private int _scanPos;
    private bool _httpStreaming;
    private int _timerActive;
    private volatile bool _disposed;

    /// <param name="sendFrame">Вызывается на каждый готовый кадр (однократно, вне блокировки).</param>
    /// <param name="maxFramePayload">Максимальный размер полезной нагрузки кадра.</param>
    /// <param name="nagleDelay">Задержка объединения мелких фрагментов; null — значение по умолчанию.</param>
    public TcpFrameBatcher(
        Action<byte[]> sendFrame,
        int maxFramePayload = MaxFramePayload,
        TimeSpan? nagleDelay = null)
    {
        _sendFrame = sendFrame;
        _maxFramePayload = maxFramePayload;
        _nagleDelay = nagleDelay ?? DefaultNagleDelay;
        _buffer = new byte[maxFramePayload * 2];
    }

    /// <summary>
    /// Добавляет порцию данных из TCP-потока. При необходимости накопленное
    /// отправляется сразу или запускается таймер отложенной отправки.
    /// </summary>
    public void Append(ReadOnlySpan<byte> data)
    {
        if (_disposed || data.IsEmpty)
            return;

        while (!data.IsEmpty)
        {
            byte[] toSend = Array.Empty<byte>();

            lock (_sync)
            {
                if (_disposed)
                    return;

                var space = _buffer.Length - _count;
                if (space == 0)
                {
                    Array.Resize(ref _buffer, _buffer.Length + _maxFramePayload);
                    space = _buffer.Length - _count;
                }

                var take = Math.Min(space, data.Length);
                data[..take].CopyTo(_buffer.AsSpan(_count));
                _count += take;
                data = data[take..];

                if (_count >= _maxFramePayload)
                {
                    toSend = GrabFrame();
                }
                else if (TryScanHeaderEnd())
                {
                    _httpStreaming = true;
                    toSend = GrabAll();
                }
                else if (_httpStreaming && EndsWithCrLf())
                {
                    // граница чанка chunked-кодирования / строка SSE — отправляем поток сразу
                    toSend = GrabAll();
                }
            }

            if (toSend.Length > 0)
                _sendFrame(toSend);
        }

        // Остаток меньше размера кадра (после дробления больших порций или тихий
        // поток мелких сегментов) — гарантированно планируем отложенную отправку.
        var startTimer = false;
        lock (_sync)
        {
            if (!_disposed && _count > 0 && _timerActive == 0)
            {
                _timerActive = 1;
                startTimer = true;
            }
        }
        if (startTimer)
            StartTimer();
    }

    /// <summary>
    /// Немедленно отправляет всё накопленное. Безопасно вызывать из любого потока
    /// (например, перед закрытием соединения или в таймерном сбросе).
    /// </summary>
    public void Flush()
    {
        byte[] toSend = Array.Empty<byte>();
        lock (_sync)
        {
            _timerActive = 0;
            if (_count > 0)
                toSend = GrabAll();
        }
        if (toSend.Length > 0)
            _sendFrame(toSend);
    }

    /// <summary>
    /// Отправляет остаток накопленного и помечает экземпляр завершённым
    /// (дальнейшие Append игнорируются). Вызывается при закрытии TCP-соединения.
    /// </summary>
    public void Complete()
    {
        byte[] toSend = Array.Empty<byte>();
        lock (_sync)
        {
            _disposed = true;
            if (_count > 0)
                toSend = GrabAll();
        }
        if (toSend.Length > 0)
            _sendFrame(toSend);
    }

    public void Dispose() => Complete();

    private void StartTimer()
    {
        Task.Run(async () =>
        {
            try
            {
                await Task.Delay(_nagleDelay);
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            Flush();
        });
    }

    private bool TryScanHeaderEnd()
    {
        var to = Math.Min(_count, HeaderEndScanLimit);
        for (var i = _scanPos; i < to - 3; i++)
        {
            if (_buffer[i] == (byte)'\r' &&
                _buffer[i + 1] == (byte)'\n' &&
                _buffer[i + 2] == (byte)'\r' &&
                _buffer[i + 3] == (byte)'\n')
            {
                _scanPos = 0;
                return true;
            }
        }
        _scanPos = Math.Max(_scanPos, Math.Max(to - 3, 0));
        return false;
    }

    private bool EndsWithCrLf() =>
        _count >= 2 && _buffer[_count - 2] == (byte)'\r' && _buffer[_count - 1] == (byte)'\n';

    private byte[] GrabFrame()
    {
        var frame = new byte[_maxFramePayload];
        Array.Copy(_buffer, frame, _maxFramePayload);
        var rest = _count - _maxFramePayload;
        if (rest > 0)
            Buffer.BlockCopy(_buffer, _maxFramePayload, _buffer, 0, rest);
        _count = rest;
        _scanPos = 0;
        return frame;
    }

    private byte[] GrabAll()
    {
        var frame = new byte[_count];
        Array.Copy(_buffer, frame, _count);
        _count = 0;
        _scanPos = 0;
        return frame;
    }
}
