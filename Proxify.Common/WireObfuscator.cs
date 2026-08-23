using System.Security.Cryptography;

namespace Proxify.Common;

/// <summary>
/// Внешний слой маскировки туннеля.
///
/// Каждый UDP-датаграмм между прокси-сервером (машина A) и прокси-клиентом
/// (машина B) целиком шифруется AES-256-GCM ещё ДО внутреннего протокола кадров:
///
///   датаграмма = [12]nonce [16]tag [N]AES-GCM(wireKey, внутренний кадр)
///
/// На проводе не остаётся ни одного постоянного байта: ни магии 0xC0DE, ни типов
/// кадров, ни открытого рукопожатия Auth/AuthAck — датаграммы выглядят как
/// равномерно случайные байты, без сигнатуры протокола и факта рукопожатия.
///
/// Wire-ключи выводятся из зарегистрированной пары ключей клиента
/// (HKDF-SHA256 от SPKI-байт публичного ключа, отдельный ключ на направление:
/// клиент→сервер и сервер→клиент). Публичный ключ нигде не передаётся по проводу,
/// поэтому вывести ключ из перехваченного трафика нельзя.
///
/// Граница угроз: слой защищает от классификации по сигнатурам и эвристикам
/// содержимого. Атакующий, которому известен client-public.pem (файл конфига),
/// может вычислить wire-ключи — конфиденциальность полезной нагрузки при этом
/// по-прежнему обеспечивает внутренний сессионный шифр (см. TunnelCipher).
/// </summary>
public sealed class WireObfuscator
{
    private readonly TunnelCipher _send;
    private readonly TunnelCipher _receive;

    private WireObfuscator(TunnelCipher send, TunnelCipher receive)
    {
        _send = send;
        _receive = receive;
    }

    /// <param name="identityKey">Ключ зарегистрированной пары клиента:
    /// на машине B — загруженный закрытый ключ, на машине A — публичный ключ
    /// из конфига сервера.</param>
    /// <param name="weAreClient">true для прокси-клиента (машина B).</param>
    public static WireObfuscator Create(ECDsa identityKey, bool weAreClient)
    {
        var spki = TunnelKeys.ExportSpkiDer(identityKey);
        var kC2s = TunnelKeys.DeriveWireKey(spki, TunnelKeys.WireInfoClientToServer);
        var kS2c = TunnelKeys.DeriveWireKey(spki, TunnelKeys.WireInfoServerToClient);

        return weAreClient
            ? new WireObfuscator(new TunnelCipher(kC2s), new TunnelCipher(kS2c))
            : new WireObfuscator(new TunnelCipher(kS2c), new TunnelCipher(kC2s));
    }

    /// <summary>Шифрует внутренний кадр для передачи по проводу.</summary>
    public byte[] Wrap(byte[] innerFrame) => _send.Wrap(innerFrame);

    /// <summary>
    /// Пытается расшифровать принятую датаграмму. Возвращает false для чужого или
    /// повреждённого пакета (проверка AEAD-тега): это заменяет прежнюю проверку magic.
    /// </summary>
    public bool TryUnwrap(byte[] buffer, int length, out byte[] innerFrame)
        => _receive.TryUnwrap(buffer.AsSpan(0, length), out innerFrame);
}
