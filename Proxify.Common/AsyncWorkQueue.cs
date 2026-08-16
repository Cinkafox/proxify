using System.Threading.Channels;

namespace Proxify.Common;

/// <summary>
/// Ограниченная очередь асинхронных задач с фиксированным числом параллельных
/// воркеров.
///
/// Позволяет разгрузить циклы приёма сети: приём и обработка пакетов разводятся
/// по нескольким потокам, поэтому медленная отправка вниз по потоку не стопорит
/// приём новых пакетов, а отдельные пакеты обрабатываются параллельно.
///
/// Переполнение канала создаёт обратное давление (backpressure): EnqueueAsync
/// ждёт места, не позволяя очереди разрастись до бесконечности.
/// Очередь не гарантирует порядок обработки элементов.
/// </summary>
public sealed class AsyncWorkQueue : IDisposable
{
    private readonly Channel<Func<Task>> _channel;
    private readonly Task[] _workers;

    /// <summary>Число задач, ожидающих обработки.</summary>
    public int PendingCount => _channel.Reader.Count;

    public AsyncWorkQueue(int degreeOfParallelism, int capacity = 1024)
    {
        var workers = Math.Clamp(degreeOfParallelism, 1, 64);

        _channel = Channel.CreateBounded<Func<Task>>(new BoundedChannelOptions(capacity)
        {
            SingleReader = false,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait,
            AllowSynchronousContinuations = false,
        });

        _workers = new Task[workers];
        for (var i = 0; i < _workers.Length; i++)
            _workers[i] = Task.Run(WorkerAsync);
    }

    /// <summary>
    /// Ставит задачу в очередь. При переполнении ожидает, пока появится место
    /// (обратное давление). После вызова Dispose бросает ChannelClosedException.
    /// </summary>
    public ValueTask EnqueueAsync(Func<Task> item) => _channel.Writer.WriteAsync(item);

    /// <summary>
    /// Пытается поставить задачу без ожидания; при переполнении возвращает false.
    /// </summary>
    public bool TryEnqueue(Func<Task> item) => _channel.Writer.TryWrite(item);

    /// <summary>
    /// Завершает очередь и дожидается обработки всех поставленных задач.
    /// </summary>
    public async Task WaitForDrainAsync()
    {
        _channel.Writer.TryComplete();
        await Task.WhenAll(_workers);
    }

    private async Task WorkerAsync()
    {
        await foreach (var item in _channel.Reader.ReadAllAsync())
        {
            try
            {
                await item();
            }
            catch
            {
                // Ошибка внутри конкретной задачи уже прологгирована её обработчиком;
                // воркер продолжает разбирать очередь.
            }
        }
    }

    public void Dispose()
    {
        _channel.Writer.TryComplete();
    }
}
