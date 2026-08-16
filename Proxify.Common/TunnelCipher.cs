using System.Security.Cryptography;
using System.Text;

namespace Proxify.Common;

/// <summary>
/// Шифрование туннельных кадров AES-GCM.
///
/// Ключ выводится из парольной фразы через PBKDF2-HMACSHA256 (100000 итераций).
/// Каждый кадр шифруется отдельным случайным nonce (12 байт) и защищён
/// аутентификационной меткой (16 байт): формат [nonce][tag][ciphertext].
/// </summary>
public sealed class TunnelCipher
{
    private const int Iterations = 100_000;
    private const int SaltSize = 16;

    public const int KeySize = 32;
    public const int NonceSize = 12;
    public const int TagSize = 16;

    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

    private readonly byte[] _key;

    public TunnelCipher(byte[] key)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"Ключ должен быть {KeySize} байт.", nameof(key));

        _key = (byte[])key.Clone();
    }

    /// <summary>
    /// Выводит ключ из парольной фразы (одинаковой у прокси-сервера и прокси-клиента).
    /// </summary>
    public static TunnelCipher FromPassphrase(string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase))
            throw new ArgumentException("Парольная фраза не должна быть пустой.", nameof(passphrase));

        var passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
        var salt = SHA256.HashData(passphraseBytes).AsSpan(0, SaltSize).ToArray();
        var key = Rfc2898DeriveBytes.Pbkdf2(passphraseBytes, salt, Iterations, HashAlgorithmName.SHA256, KeySize);
        return new TunnelCipher(key);
    }

    /// <summary>
    /// Шифрует данные: возвращает [nonce][tag][ciphertext].
    /// </summary>
    public byte[] Wrap(ReadOnlySpan<byte> plaintext)
    {
        var nonce = new byte[NonceSize];
        Rng.GetBytes(nonce);

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using (var gcm = new AesGcm(_key, TagSize))
        {
            gcm.Encrypt(nonce, plaintext, ciphertext, tag);
        }

        var result = new byte[NonceSize + TagSize + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
        Buffer.BlockCopy(tag, 0, result, NonceSize, TagSize);
        Buffer.BlockCopy(ciphertext, 0, result, NonceSize + TagSize, ciphertext.Length);
        return result;
    }

    /// <summary>
    /// Расшифровывает данные из [nonce][tag][ciphertext]. Возвращает false,
    /// если длина неверна или не прошла проверка аутентификации.
    /// </summary>
    public bool TryUnwrap(ReadOnlySpan<byte> input, out byte[] plaintext)
    {
        plaintext = Array.Empty<byte>();

        if (input.Length < NonceSize + TagSize)
            return false;

        var nonce = input[..NonceSize];
        var tag = input.Slice(NonceSize, TagSize);
        var ciphertext = input[(NonceSize + TagSize)..];

        plaintext = new byte[ciphertext.Length];
        try
        {
            using (var gcm = new AesGcm(_key, TagSize))
            {
                gcm.Decrypt(nonce, ciphertext, tag, plaintext);
            }
            return true;
        }
        catch (CryptographicException)
        {
            plaintext = Array.Empty<byte>();
            return false;
        }
    }
}
