using System.Security.Cryptography;
using System.Text;

namespace Proxify.Common;

/// <summary>
/// Асимметричная аутентификация и вывод сессионного ключа туннеля.
///
/// Каждый прокси-клиент имеет пару ключей P-256:
///   * закрытый ключ (PKCS#8 PEM) хранится на машине B (прокси-клиент) —
///     используется для подписи кадра Auth (доказывает личность);
///   * открытый ключ (SPKI PEM) регистрируется в конфиге сервера (машина A) —
///     по нему сервер проверяет подпись Auth и опознаёт клиента.
///
/// Рукопожатие (кадр Auth, без шифрования):
///   [1] версия = 1
///   [32] X эфемерного ключа ECDH клиента
///   [32] Y эфемерного ключа ECDH клиента
///   [16] nonce (случайный, для привязки ответа)
///   [64] подпись ECDSA (IEEE P1363) по "proxify-auth-v1"||X||Y||nonce
///
/// Сервер проверяет подпись зарегистрированным публичным ключом, генерирует
/// свой эфемерный ключ ECDH и отвечает AuthAck. Обе стороны вычисляют один и тот же
/// сессионный ключ: HKDF-SHA256(ECDH(приватный_эфемерный, публичный_эфемерный),
/// salt=null, info="proxify-session-v1", 32 байта). Salt не используется, чтобы
/// порядок точек у обеих сторон не влиял на результат.
/// </summary>
public static class TunnelKeys
{
    public const string AuthInfo = "proxify-auth-v1";
    public const string SessionInfo = "proxify-session-v1";

    public const byte AuthVersion = 1;

    public const int PointSize = 32;
    public const int NonceSize = 16;
    public const int SignatureSize = 64;
    public const int SessionKeySize = 32;

    private static readonly byte[] AuthInfoBytes = Encoding.UTF8.GetBytes(AuthInfo);

    /// <summary>
    /// Генерирует пару ключей P-256 и возвращает их в PEM (PKCS#8 / SPKI).
    /// </summary>
    public static (string PrivatePem, string PublicPem) GeneratePem()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (key.ExportPkcs8PrivateKeyPem(), key.ExportSubjectPublicKeyInfoPem());
    }

    /// <summary>
    /// Генерирует пару ключей в указанный каталог: client-private.pem, client-public.pem.
    /// </summary>
    public static bool TryGenerateKeyPair(string dir, out string privatePath, out string publicPath, out string? error)
    {
        privatePath = "";
        publicPath = "";
        error = null;

        try
        {
            Directory.CreateDirectory(dir);
            var (privatePem, publicPem) = GeneratePem();
            privatePath = Path.Combine(dir, "client-private.pem");
            publicPath = Path.Combine(dir, "client-public.pem");
            File.WriteAllText(privatePath, privatePem);
            File.WriteAllText(publicPath, publicPem);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Загружает закрытый ключ из PEM (PKCS#8 или другой поддерживаемый формат).
    /// </summary>
    public static ECDsa ImportPrivatePem(string pem)
    {
        var key = ECDsa.Create();
        try
        {
            key.ImportFromPem(pem);
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Загружает публичный ключ из PEM (SPKI).
    /// </summary>
    public static ECDsa ImportPublicPem(string pem)
    {
        var key = ECDsa.Create();
        try
        {
            key.ImportFromPem(pem);
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    public static byte[] Sign(ECDsa key, ReadOnlySpan<byte> payload)
        => key.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    public static bool Verify(ECDsa key, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature)
        => key.VerifyData(payload, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    /// <summary>
    /// Данные, которые подписываются в кадре Auth: "proxify-auth-v1"||X||Y||nonce.
    /// </summary>
    public static byte[] BuildAuthPayload(ReadOnlySpan<byte> ephX, ReadOnlySpan<byte> ephY, ReadOnlySpan<byte> nonce)
    {
        var payload = new byte[AuthInfoBytes.Length + ephX.Length + ephY.Length + nonce.Length];
        var o = 0;
        AuthInfoBytes.CopyTo(payload, 0);
        o += AuthInfoBytes.Length;
        ephX.CopyTo(payload.AsSpan(o));
        o += ephX.Length;
        ephY.CopyTo(payload.AsSpan(o));
        o += ephY.Length;
        nonce.CopyTo(payload.AsSpan(o));
        return payload;
    }

    /// <summary>
    /// Создаёт новый эфемерный ключ ECDH на кривой P-256 (на одну попытку рукопожатия).
    /// </summary>
    public static ECDiffieHellman CreateEphemeral() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>
    /// Экспортирует координаты публичной точки эфемерного ключа ECDH.
    /// </summary>
    public static (byte[] X, byte[] Y) ExportPoint(ECDiffieHellman key)
    {
        var parameters = key.ExportParameters(false);
        return (parameters.Q.X!, parameters.Q.Y!);
    }

    /// <summary>
    /// Выводит сессионный ключ: HKDF-SHA256(ECDH(собственный приватный, чужой публичный),
    /// salt=null, info="proxify-session-v1"). У обеих сторон результат одинаковый.
    /// </summary>
    public static byte[] DeriveSessionKey(ECDiffieHellman ecdh, byte[] peerX, byte[] peerY)
    {
        using var peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        peer.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = peerX, Y = peerY },
        });

        using var peerPublic = peer.PublicKey;
        var secret = ecdh.DeriveRawSecretAgreement(peerPublic);
        try
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, SessionKeySize, Encoding.UTF8.GetBytes(SessionInfo));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }
}
