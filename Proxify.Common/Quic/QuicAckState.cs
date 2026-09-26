namespace Proxify.Common.Quic;

/// <summary>
/// Учёт принятых пакетов для формирования кадров ACK.
///
/// Настоящий клиент подтверждает пакеты пакетами ACK: примерно каждый второй
/// «побуждающий к подтверждению» пакет, с задержкой и объединением близких
/// номеров в диапазоны. Здесь ведётся тот же учёт: диапазоны принятых номеров и
/// признак того, что накоплены неподтверждённые пакеты. Данные передаются внутри
/// AEAD, но сам факт и форма подтверждений видны по размеру и ритму датаграмм, а
/// для наблюдателя это выглядит как обычная работа QUIC.
///
/// Кадры ACK собираются не чаще, чем требуется, и содержат до
/// <see cref="MaxRanges"/> диапазонов — как и в настоящих реализациях.
/// </summary>
public sealed class QuicAckState
{
    /// <summary>Сколько диапазонов включать в один кадр ACK.</summary>
    private const int MaxRanges = 4;

    /// <summary>Сколько неподтверждённых пакетов достаточно, чтобы отправить ACK.</summary>
    private const int AckElicitingThreshold = 2;

    /// <summary>Экспонента задержки подтверждения, объявленная в параметрах транспорта.</summary>
    private const int AckDelayExponent = 3;

    private readonly List<(ulong Low, ulong High)> _ranges = new();

    private bool _hasPending;
    private int _pendingSinceLastAck;
    private long _largestReceivedTicks;
    private ulong _largestSeen;

    /// <summary>Число пакетов, принятых с момента последнего отправленного ACK.</summary>
    public int PendingCount => _pendingSinceLastAck;

    /// <summary>Есть ли что подтверждать.</summary>
    public bool HasPending => _hasPending;

    /// <summary>
    /// Забывает накопленное: используется при переходе на новое рукопожатие, где у
    /// пакетов уровня Initial/Handshake своё пространство номеров.
    /// </summary>
    public void Reset()
    {
        _ranges.Clear();
        _hasPending = false;
        _pendingSinceLastAck = 0;
        _largestReceivedTicks = 0;
        _largestSeen = 0;
    }

    /// <summary>Отмечает приём пакета. ackEliciting — требовал ли он ответа ACK.</summary>
    public void RecordPacket(ulong packetNumber, bool ackEliciting)
    {
        Add(packetNumber);

        // Метка времени нужна для задержки подтверждения: она отсчитывается от
        // прихода пакета с наибольшим номером, который будет подтверждён.
        if (packetNumber >= _largestSeen)
        {
            _largestSeen = packetNumber;
            _largestReceivedTicks = DateTime.UtcNow.Ticks;
        }

        if (ackEliciting)
        {
            _hasPending = true;
            _pendingSinceLastAck++;
        }
    }

    /// <summary>
    /// Стоит ли включать ACK в следующий исходящий пакет: по достижении порога
    /// неподтверждённых пакетов либо по истечении задержки подтверждения.
    /// </summary>
    public bool ShouldAcknowledge(TimeSpan ackDelay)
    {
        if (!_hasPending)
            return false;
        if (_pendingSinceLastAck >= AckElicitingThreshold)
            return true;

        var elapsed = DateTime.UtcNow.Ticks - _largestReceivedTicks;
        return elapsed >= ackDelay.Ticks;
    }

    /// <summary>
    /// Размер кадра ACK, который получился бы при записи сейчас. Состояние не
    /// меняется: нужно, чтобы выбрать размер датаграммы до того, как пакет собран.
    /// </summary>
    public int MeasureAck(TimeSpan ackDelay)
    {
        if (!_hasPending || _ranges.Count == 0)
            return 0;

        var probe = new QuicWriter(32);
        return WriteAckFrame(probe, ackDelay) ? probe.Length : 0;
    }

    /// <summary>
    /// Пишет кадр ACK в буфер и сбрасывает накопленное состояние. Возвращает false,
    /// если подтверждать нечего.
    /// </summary>
    public bool TryWriteAck(QuicWriter writer, TimeSpan ackDelay)
    {
        if (!WriteAckFrame(writer, ackDelay))
            return false;

        _hasPending = false;
        _pendingSinceLastAck = 0;
        return true;
    }

    private bool WriteAckFrame(QuicWriter writer, TimeSpan ackDelay)
    {
        if (!_hasPending || _ranges.Count == 0)
            return false;

        var largest = _ranges[0].High;
        var firstRange = largest - _ranges[0].Low;
        var elapsed = Math.Max(0, DateTime.UtcNow.Ticks - _largestReceivedTicks);

        // Задержка кодируется в единицах 2^ack_delay_exponent микросекунд.
        var delayUnits = (ulong)(elapsed / TimeSpan.TicksPerMillisecond * 1000 >> AckDelayExponent);

        var ranges = new List<(ulong, ulong)>(Math.Min(MaxRanges, _ranges.Count - 1));
        var previousLow = _ranges[0].Low;
        for (var i = 1; i < _ranges.Count && i <= MaxRanges; i++)
        {
            // Пропуск между диапазонами: сколько номеров не подтверждено перед
            // началом следующего диапазона, минус единица.
            var gap = previousLow - _ranges[i].High - 2;
            ranges.Add((gap, _ranges[i].High - _ranges[i].Low));
            previousLow = _ranges[i].Low;
        }

        QuicFrame.WriteAck(writer, new QuicAck
        {
            LargestAcknowledged = largest,
            AckDelay = delayUnits,
            RangeCount = (ulong)ranges.Count,
            FirstAckRange = firstRange,
            Ranges = ranges,
        });

        return true;
    }

    private void Add(ulong packetNumber)
    {
        // Диапазоны хранятся по убыванию номеров: первый — самый свежий.
        for (var i = 0; i < _ranges.Count; i++)
        {
            var (low, high) = _ranges[i];
            if (packetNumber >= low && packetNumber <= high)
                return;

            if (packetNumber == high + 1)
            {
                _ranges[i] = (low, high + 1);
                Merge(i);
                return;
            }

            if (packetNumber + 1 == low)
            {
                _ranges[i] = (low - 1, high);
                Merge(i);
                return;
            }

            if (packetNumber > high)
            {
                _ranges.Insert(i, (packetNumber, packetNumber));
                return;
            }
        }

        _ranges.Add((packetNumber, packetNumber));
    }

    /// <summary>Сливает соседние диапазоны, если между ними не более двух номеров.</summary>
    private void Merge(int index)
    {
        while (index + 1 < _ranges.Count && _ranges[index].Low - _ranges[index + 1].High <= 2)
        {
            _ranges[index] = (_ranges[index + 1].Low, _ranges[index].High);
            _ranges.RemoveAt(index + 1);
        }

        while (index > 0 && _ranges[index - 1].Low - _ranges[index].High <= 2)
        {
            _ranges[index - 1] = (_ranges[index].Low, _ranges[index - 1].High);
            _ranges.RemoveAt(index);
            index--;
        }
    }
}
