using System.Security.Cryptography;
using System.Text;

namespace Security.SecretProtector;

/// <summary>
/// AES-256-GCM <see cref="ISecretProtector"/> keyed by a single 32-byte key supplied
/// from configuration. Consolidates the two previously-duplicated copies (AML's
/// <c>AesGcmCredentialCipher</c> and Kefi's <c>ConfigAesGcmSecretProtector</c>) behind
/// one audited implementation.
/// </summary>
/// <remarks>
/// <para>
/// The key must decode (base64 <b>or</b> hex) to exactly 32 bytes. In fail-fast mode a
/// missing / wrong-length / malformed key is a FATAL misconfiguration and throws at
/// construction, so the service fails at startup rather than silently storing
/// un-recoverable or weakly-encrypted secrets. In soft mode the same conditions leave
/// the protector un-configured (<see cref="IsConfigured"/> is false) and
/// <see cref="Protect"/> / <see cref="Unprotect"/> throw only if actually called — so an
/// optional-secret caller can survive an unset key.
/// </para>
/// <para>
/// Token layout (then base64): <c>[12-byte nonce][16-byte tag][ciphertext]</c>. This
/// on-disk format is fixed and MUST remain byte-for-byte stable so already-stored
/// ciphertext keeps decrypting after upgrades. GCM authenticates the ciphertext, so a
/// tampered or wrong-key token throws on <see cref="Unprotect"/> rather than returning
/// garbage.
/// </para>
/// </remarks>
public sealed class ConfigAesGcmSecretProtector : ISecretProtector
{
  private const int NonceBytes = 12; // GCM standard nonce (AesGcm.NonceByteSizes max)
  private const int TagBytes = 16;   // GCM standard tag (AesGcm.TagByteSizes max)

  private readonly byte[]? _key;

  /// <summary>
  /// Creates the protector from a configured key value.
  /// </summary>
  /// <param name="configuredKey">
  /// The key value read from configuration — 32 bytes encoded in base64 or hex. May be
  /// null/blank; behaviour then depends on <paramref name="failFast"/>.
  /// </param>
  /// <param name="failFast">
  /// When true (the default), a missing / malformed / wrong-length key throws an
  /// <see cref="InvalidOperationException"/> at construction. When false, such a key
  /// leaves the protector un-configured (<see cref="IsConfigured"/> is false).
  /// </param>
  public ConfigAesGcmSecretProtector(string? configuredKey, bool failFast = true)
  {
    if (SecretKeyDecoder.TryDecode(configuredKey, out var key))
    {
      _key = key;
    }
    else if (failFast)
    {
      throw new InvalidOperationException(
          "The secret-encryption key is not configured or is invalid. Set it via the "
          + "environment (a .env file for local development, a Kubernetes secret on "
          + "staging / production) as 32 bytes encoded in base64 or hex. Generate one "
          + "with e.g. `openssl rand -base64 32`.");
    }
  }

  /// <inheritdoc />
  public bool IsConfigured => _key is not null;

  /// <inheritdoc />
  public string Protect(string plaintext)
  {
    var key = RequireKey();
    ArgumentNullException.ThrowIfNull(plaintext);

    var plain = Encoding.UTF8.GetBytes(plaintext);
    var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
    var cipher = new byte[plain.Length];
    var tag = new byte[TagBytes];

    using var aes = new AesGcm(key, TagBytes);
    aes.Encrypt(nonce, plain, cipher, tag);

    var token = new byte[NonceBytes + TagBytes + cipher.Length];
    Buffer.BlockCopy(nonce, 0, token, 0, NonceBytes);
    Buffer.BlockCopy(tag, 0, token, NonceBytes, TagBytes);
    Buffer.BlockCopy(cipher, 0, token, NonceBytes + TagBytes, cipher.Length);
    return Convert.ToBase64String(token);
  }

  /// <inheritdoc />
  public string Unprotect(string token)
  {
    var key = RequireKey();
    ArgumentException.ThrowIfNullOrWhiteSpace(token);

    var raw = Convert.FromBase64String(token);
    if (raw.Length < NonceBytes + TagBytes)
    {
      throw new CryptographicException("Secret token is too short to be valid.");
    }

    var nonce = raw.AsSpan(0, NonceBytes);
    var tag = raw.AsSpan(NonceBytes, TagBytes);
    var cipher = raw.AsSpan(NonceBytes + TagBytes);
    var plain = new byte[cipher.Length];

    using var aes = new AesGcm(key, TagBytes);
    aes.Decrypt(nonce, cipher, tag, plain);
    return Encoding.UTF8.GetString(plain);
  }

  private byte[] RequireKey() => _key
      ?? throw new InvalidOperationException(
          "The secret protector is not configured; cannot protect/unprotect secrets.");
}
