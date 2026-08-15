namespace Proxify.Common;

/// <summary>
/// Счётчики трафика для диагностики. Обновляются потокобезопасно
/// (Interlocked), один раз в минуту выводятся одной строкой.
///
/// На сервере:   PacketsIn — пакеты игроков,  PacketsOut — кадры прокси-клиенту,
///               RepliesRelayed — ответы, доставленные игроку.
/// На клиенте:   PacketsIn — кадры от сервера, PacketsOut — кадры прокси-серверу,
///               Injected — впрыснуто в игру, RepliesCaptured — ответов перехвачено.
/// BadFrames — кадры, которые не удалось разобрать (например, несовпадение ключа).
/// </summary>
public sealed class TunnelStats
{
    public long PacketsIn;
    public long PacketsOut;
    public long Injected;
    public long RepliesCaptured;
    public long RepliesRelayed;
    public long BadFrames;

    public void Print(string who)
    {
        try
        {
            Console.WriteLine(
                $"[{DateTime.Now:HH:mm:ss.fff}] [stats] {who}: " +
                $"вход={PacketsIn} отпр={PacketsOut} впрыск={Injected} " +
                $"перехв={RepliesCaptured} доставлено={RepliesRelayed} плохие={BadFrames}");
        }
        catch
        {
            // печать статистики не должна ронять процесс
        }
    }
}
