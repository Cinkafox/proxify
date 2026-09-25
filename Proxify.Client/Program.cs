using System.Net.Sockets;
using System.Text;
using Proxify.Client.Cli;
using Proxify.Client.Sessions;

Console.OutputEncoding = Encoding.UTF8;

var options = ClientCli.Parse(args);
if (options.Error != null)
{
    Console.WriteLine($"[ошибка конфигурации] {options.Error}");
    if (options.ShowUsage)
        ClientCli.CreateParser().PrintUsage();
    return 1;
}
if (options.HelpRequested)
    return 0;

// --- Режим генерации ключей ---
if (options.KeygenDir != null)
{
    var keygenError = ClientCli.GenerateKeys(options.KeygenDir);
    if (keygenError != null)
    {
        Console.WriteLine($"[ошибка конфигурации] {keygenError}");
        return 1;
    }
    return 0;
}

var session = await ProxySession.CreateAsync(options.ProxyServer, options.IdentityKey, options.LocalPort, options.WireObfuscation);
if (session == null)
    return 1;

using (session)
{
    try
    {
        await session.RunAsync();
    }
    catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
    {
        Console.WriteLine($"[!] Недостаточно прав: {ex.Message}");
        if (OperatingSystem.IsWindows())
        {
            Console.WriteLine("[!] Создание RawSocket требует прав администратора.");
            Console.WriteLine("[!] Запустите консоль от имени администратора и повторите попытку.");
        }
        else
        {
            Console.WriteLine("[!] Создание RawSocket требует прав root или CAP_NET_RAW.");
            Console.WriteLine("[!] Запустите: sudo Proxify.Client ...");
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[!] Необработанная ошибка: {ex.Message}");
        Console.WriteLine(ex);
    }
}

return 0;