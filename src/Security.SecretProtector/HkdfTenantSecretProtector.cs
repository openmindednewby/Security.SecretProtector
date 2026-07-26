using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Security.SecretProtector;

/// <summary>
/// Per-tenant <see cref="ITenantSecretProtector"/>: AES-256-GCM keyed by a per-tenant key
/// <b>derived</b> from a versioned master keyring via HKDF-SHA256. Two tenants sharing one master
/// key get cryptographically independent keys, so a credential protected for one cannot be
/// decrypted under another's identity.
/// </summary>
/// <remarks>
/// <para>
/// Per-tenant key = <c>HKDF-SHA256(ikm = masterKey_v, salt = UTF8(tenantId), info = "finreg-tenant-credential-v1")</c>,
/// 32 bytes. The derived key is zeroed immediately after each operation; only the master keyring
/// persists in memory, and it only ever comes from a secrets manager.
/// </para>
/// <para>
/// Token layout (then base64): <c>[2-byte keyVersion BE][12-byte nonce][16-byte tag][ciphertext]</c>.
/// GCM authenticates the ciphertext, so a tampered token, a wrong master key, an unknown key
/// version, OR a mismatched tenant id all throw on <see cref="Unprotect"/> rather than returning
/// garbage.
/// </para>
/// </remarks>
public sealed class HkdfTenantSecretProtector : ITenantSecretProtector
{
  private const int VersionBytes = 2;    // big-endian ushort key version
  private const int NonceBytes = 12;     // GCM standard nonce
  private const int TagBytes = 16;       // GCM standard tag
  private const int DerivedKeyBytes = 32; // AES-256
  private const int HeaderBytes = VersionBytes + NonceBytes + TagBytes;

  /// <summary>HKDF <c>info</c> — domain-separates this derivation from any other use of the master key.</summary>
  private static readonly byte[] DerivationInfo = Encoding.UTF8.GetBytes("finreg-tenant-credential-v1");

  private readonly TenantSecretKeyring? _keyring;

  /// <summary>
  /// Creates the protector from a keyring. A null or un-configured keyring leaves the protector
  /// un-configured (<see cref="IsConfigured"/> false) so optional-secret callers can gate on it.
  /// </summary>
  public HkdfTenantSecretProtector(TenantSecretKeyring? keyring)
      => _keyring = keyring is { IsConfigured: true } ? keyring : null;

  /// <inheritdoc />
  public bool IsConfigured => _keyring is not null;

  /// <inheritdoc />
  public string Protect(string tenantId, string plaintext)
  {
    var keyring = RequireKeyring();
    ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
    ArgumentNullException.ThrowIfNull(plaintext);

    var version = keyring.CurrentVersion;
    var derived = DeriveKey(keyring.KeyForVersion(version), tenantId);
    try
    {
      var plain = Encoding.UTF8.GetBytes(plaintext);
      var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
      var cipher = new byte[plain.Length];
      var tag = new byte[TagBytes];

      using var aes = new AesGcm(derived, TagBytes);
      aes.Encrypt(nonce, plain, cipher, tag);

      var token = new byte[HeaderBytes + cipher.Length];
      BinaryPrimitives.WriteUInt16BigEndian(token.AsSpan(0, VersionBytes), (ushort)version);
      Buffer.BlockCopy(nonce, 0, token, VersionBytes, NonceBytes);
      Buffer.BlockCopy(tag, 0, token, VersionBytes + NonceBytes, TagBytes);
      Buffer.BlockCopy(cipher, 0, token, HeaderBytes, cipher.Length);
      return Convert.ToBase64String(token);
    }
    finally
    {
      CryptographicOperations.ZeroMemory(derived);
    }
  }

  /// <inheritdoc />
  public string Unprotect(string tenantId, string token)
  {
    var keyring = RequireKeyring();
    ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
    ArgumentException.ThrowIfNullOrWhiteSpace(token);

    var raw = Convert.FromBase64String(token);
    if (raw.Length < HeaderBytes)
    {
      throw new CryptographicException("Secret token is too short to be valid.");
    }

    var version = BinaryPrimitives.ReadUInt16BigEndian(raw.AsSpan(0, VersionBytes));
    var derived = DeriveKey(keyring.KeyForVersion(version), tenantId);
    try
    {
      var nonce = raw.AsSpan(VersionBytes, NonceBytes);
      var tag = raw.AsSpan(VersionBytes + NonceBytes, TagBytes);
      var cipher = raw.AsSpan(HeaderBytes);
      var plain = new byte[cipher.Length];

      using var aes = new AesGcm(derived, TagBytes);
      aes.Decrypt(nonce, cipher, tag, plain); // throws on wrong tenant / tamper / wrong key
      return Encoding.UTF8.GetString(plain);
    }
    finally
    {
      CryptographicOperations.ZeroMemory(derived);
    }
  }

  /// <summary>
  /// Derives the per-tenant AES key. The tenant id is the HKDF salt, so distinct tenants yield
  /// independent keys — this is the whole isolation guarantee, and dropping it would let one
  /// tenant decrypt another's credentials.
  /// </summary>
  private static byte[] DeriveKey(byte[] masterKey, string tenantId)
  {
    var salt = Encoding.UTF8.GetBytes(tenantId);
    return HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, DerivedKeyBytes, salt, DerivationInfo);
  }

  private TenantSecretKeyring RequireKeyring() => _keyring
      ?? throw new InvalidOperationException(
          "The tenant secret protector is not configured; cannot protect/unprotect secrets.");
}
