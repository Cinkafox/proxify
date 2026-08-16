namespace Proxify.Common;

/// <summary>
/// Надёжный приём TCP-данных через UDP-туннель: восстанавливает порядок по
/// порядковым номерам (seq), отбрасывает повторы (из-за потерянного TcpAck
/// передающая сторона может прислать кадр повторно) и подтверждает каждый кадр
/// кадром TcpAck.
///
/// Данные доставляются строго по порядку (в том числе после заполнения пропуска
/// буферизованными кадрами) через <see cref="Action{T}"/> вызов <see cref="Receive"/>
/// в порядке последовательности. <see cref="Receive"/> блокируется, пока доставка
/// очередного блока не завершится.
///
/// Потокобезопасен.
/// </summary>
public sealed class TcpReliableReceiver
{
    private readonly uint _connId;
    private readonly Action<byte[]> _deliver;
    private readonly Action<uint, long> _sendAck;
    private readonly int _maxOutOfOrder;

    private readonly object _sync = new();
    private readonly SortedDictionary<long, byte[]> _outOfOrder = new();
    private long _expected;
    private bool _closed;

    /// <param name="deliver">Доставка упорядоченного блока данных дальше по стеку.</param>
    /// <param name="sendAck">Отправка подтверждения (connId, ackSeq).</param>
    public TcpReliableReceiver(
        uint connId,
        Action<byte[]> deliver,
        Action<uint, long> sendAck,
        int maxOutOfOrder = 512)
    {
        _connId = connId;
        _deliver = deliver;
        _sendAck = sendAck;
        _maxOutOfOrder = maxOutOfOrder;
    }

    /// <summary>
    /// Принимает кадр данных с порядковым номером <paramref name="seq"/>.
    /// Повторы отбрасываются, порядок восстанавливается, подтверждение
    /// отправляется после каждого приёма.
    /// </summary>
    public void Receive(byte[] payload, long seq)
    {
        lock (_sync)
        {
            if (_closed)
                return;

            if (seq < _expected)
            {
                // Повтор уже доставленного кадра (потерялся наш TcpAck) —
                // просто подтверждаем ещё раз.
                Ack();
                return;
            }

            if (seq == _expected)
            {
                _expected++;
                DeliverLocked(payload);
                DrainLocked();
                Ack();
                return;
            }

            if (seq - _expected <= _maxOutOfOrder)
                _outOfOrder[seq] = payload;

            Ack();
        }
    }

    private void DrainLocked()
    {
        while (_outOfOrder.TryGetValue(_expected, out var payload))
        {
            _outOfOrder.Remove(_expected);
            _expected++;
            DeliverLocked(payload);
        }
    }

    private void DeliverLocked(byte[] payload)
    {
        try
        {
            _deliver(payload);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Ошибка доставки данных (connId {_connId}): {ex.Message}");
        }
    }

    private void Ack()
    {
        try
        {
            _sendAck(_connId, _expected);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [tcp] Ошибка отправки TcpAck (connId {_connId}): {ex.Message}");
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            _closed = true;
            _outOfOrder.Clear();
            Monitor.PulseAll(_sync);
        }
    }
}
