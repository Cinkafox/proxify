namespace Proxify.Common;

/// <summary>
/// Надёжная передача TCP-данных через UDP-туннель: каждый блок данных получает
/// порядковый номер (seq), буферизуется до подтверждения (TcpAck) и повторяется
/// по таймеру, пока принимающая сторона не подтвердит приём.
///
/// Гарантирует порядок отправки (seq присваивается в порядке вызова
/// <see cref="Send"/>) и добавляет ограничение потока: если накопилось более
/// <see cref="MaxBufferedFrames"/> неподтверждённых блоков, <see cref="Send"/>
/// блокируется до получения подтверждений.
///
/// Потокобезопасен: <see cref="Send"/> и <see cref="OnAck"/> могут вызываться
/// из разных потоков.
/// </summary>
public sealed class TcpReliableSender : IDisposable
{
    private readonly uint _connId;
    private readonly Action<byte[], uint, long> _sendFrame;
    private readonly TimeSpan _retransmitInterval;

    private readonly object _sync = new();
    private readonly LinkedList<(long Seq, byte[] Payload)> _unacked = new();
    private long _nextSeq;
    private Timer? _timer;
    private bool _closed;

    /// <summary>Максимум неподтверждённых блоков, после которого передача приостанавливается.</summary>
    public int MaxBufferedFrames { get; }

    /// <param name="sendFrame">Отправка кадра данных (payload, connId, seq) в туннель.</param>
    public TcpReliableSender(
        uint connId,
        Action<byte[], uint, long> sendFrame,
        int maxBufferedFrames = 512,
        TimeSpan? retransmitInterval = null)
    {
        _connId = connId;
        _sendFrame = sendFrame;
        MaxBufferedFrames = maxBufferedFrames;
        _retransmitInterval = retransmitInterval ?? TimeSpan.FromMilliseconds(50);
    }

    /// <summary>
    /// Ставит блок данных на передачу с гарантией доставки. При переполнении
    /// окна неподтверждённых блоков блокируется до освобождения места.
    /// </summary>
    public void Send(byte[] payload)
    {
        lock (_sync)
        {
            while (_unacked.Count >= MaxBufferedFrames)
            {
                if (_closed)
                    return;
                Monitor.Wait(_sync, 100);
            }

            if (_closed)
                return;

            var seq = _nextSeq++;
            _unacked.AddLast((seq, payload));
            SendFrameLocked(seq, payload);
            ArmTimerLocked();
        }
    }

    private void ArmTimerLocked()
    {
        if (_timer == null)
            _timer = new Timer(_ => Retransmit(), null, _retransmitInterval, _retransmitInterval);
        else
            _timer.Change(_retransmitInterval, _retransmitInterval);
    }

    /// <summary>
    /// Обрабатывает подтверждение: все блоки с seq &lt; ackSeq считаются доставленными.
    /// </summary>
    public void OnAck(long ackSeq)
    {
        lock (_sync)
        {
            if (_closed)
                return;

            while (_unacked.Count > 0 && _unacked.First!.Value.Seq < ackSeq)
                _unacked.RemoveFirst();

            if (_unacked.Count > 0 && _timer != null)
                _timer.Change(_retransmitInterval, _retransmitInterval);
            else if (_timer != null)
                _timer.Change(Timeout.Infinite, Timeout.Infinite);

            Monitor.PulseAll(_sync);
        }
    }

    /// <summary>
    /// Ожидает, пока все отправленные блоки будут подтверждены, но не дольше
    /// заданного таймаута. Используется при закрытии соединения, чтобы данные,
    /// отправленные «в последний момент», не потерялись.
    /// </summary>
    public bool WaitDrained(TimeSpan timeout)
    {
        var deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
        lock (_sync)
        {
            while (_unacked.Count > 0)
            {
                if (_closed)
                    return false;

                var remaining = deadline - Environment.TickCount64;
                if (remaining <= 0)
                    return false;

                Monitor.Wait(_sync, (int)Math.Min(remaining, 100));
            }
            return true;
        }
    }

    /// <summary>Есть ли ещё неподтверждённые блоки.</summary>
    public bool HasUnacked
    {
        get
        {
            lock (_sync)
                return _unacked.Count > 0;
        }
    }

    private void Retransmit()
    {
        lock (_sync)
        {
            if (_closed || _unacked.Count == 0)
                return;

            foreach (var item in _unacked)
                SendFrameLocked(item.Seq, item.Payload);
        }
    }

    private void SendFrameLocked(long seq, byte[] payload)
    {
        try
        {
            _sendFrame(payload, _connId, seq);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Ошибка отправки кадра (connId {_connId}, seq {seq}): {ex.Message}");
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_closed)
                return;
            _closed = true;
            _timer?.Dispose();
            _timer = null;
            _unacked.Clear();
            Monitor.PulseAll(_sync);
        }
    }
}
