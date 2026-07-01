using System.Security.Cryptography;
using System.Text;
using Security.SecretProtector;
using Shouldly;

namespace Security.SecretProtector.Tests;

/// <summary>
/// Tests for <see cref="ConfigAesGcmSecretProtector"/> — the consolidated AES-256-GCM
/// at-rest protector. Covers round-trip, tamper / wrong-key rejection, both fail-fast
/// and soft (<c>IsConfigured</c>) modes, base64 + hex key decoding, and — critically —
/// that it decrypts a token produced by the ORIGINAL on-disk format so existing stored
/// secrets keep decrypting after the swap.
/// </summary>
public class ConfigAesGcmSecretProtectorTests
{
  private const int NonceBytes = 12;
  private const int TagBytes = 16;

  // A valid, deterministic 32-byte key, base64-encoded.
  private static string Key32() => Convert.ToBase64String(new byte[32]
  {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
  });

  private static ConfigAesGcmSecretProtector NewProtector(string? key = null, bool failFast = true) =>
      new(key ?? Key32(), failFast);

  [Fact]
  public void Protect_ThenUnprotect_RoundTrips()
  {
    var protector = NewProtector();
    const string secret = "sk_test_51AbcDEFghIJklmNOpqrSTuvwx";

    var token = protector.Protect(secret);

    token.ShouldNotBe(secret);
    protector.Unprotect(token).ShouldBe(secret);
  }

  [Fact]
  public void IsConfigured_True_WhenValidKeyPresent()
  {
    NewProtector().IsConfigured.ShouldBeTrue();
  }

  [Fact]
  public void Protect_ProducesDistinctTokensForSameInput()
  {
    var protector = NewProtector();

    // Random nonce per call → ciphertext must differ even for identical input.
    protector.Protect("whsec_same").ShouldNotBe(protector.Protect("whsec_same"));
  }

  [Fact]
  public void Unprotect_TamperedToken_Throws()
  {
    var protector = NewProtector();
    var raw = Convert.FromBase64String(protector.Protect("sk_live_secret"));
    raw[^1] ^= 0xFF; // flip a ciphertext bit → GCM tag mismatch
    var tampered = Convert.ToBase64String(raw);

    Should.Throw<CryptographicException>(() => protector.Unprotect(tampered));
  }

  [Fact]
  public void Unprotect_WithDifferentKey_Throws()
  {
    var token = NewProtector().Protect("sk_test_value");
    var otherKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    Should.Throw<CryptographicException>(() => NewProtector(otherKey).Unprotect(token));
  }

  [Fact]
  public void Unprotect_TooShortToken_Throws()
  {
    Should.Throw<CryptographicException>(
        () => NewProtector().Unprotect(Convert.ToBase64String(new byte[4])));
  }

  [Fact]
  public void Constructor_AcceptsHexEncodedKey()
  {
    var hexKey = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    var protector = NewProtector(hexKey);

    protector.Unprotect(protector.Protect("ok")).ShouldBe("ok");
  }

  [Theory]
  [InlineData(null)]
  [InlineData("")]
  [InlineData("   ")]
  public void Constructor_MissingKey_FailFast_Throws(string? missing)
  {
    Should.Throw<InvalidOperationException>(() => new ConfigAesGcmSecretProtector(missing, failFast: true));
  }

  [Fact]
  public void Constructor_WrongLengthKey_FailFast_Throws()
  {
    var shortKey = Convert.ToBase64String(new byte[16]);

    Should.Throw<InvalidOperationException>(
        () => new ConfigAesGcmSecretProtector(shortKey, failFast: true));
  }

  [Fact]
  public void Constructor_MalformedKey_FailFast_Throws()
  {
    Should.Throw<InvalidOperationException>(
        () => new ConfigAesGcmSecretProtector("not-base64!!", failFast: true));
  }

  [Theory]
  [InlineData(null)]
  [InlineData("")]
  [InlineData("not-base64!!")]
  public void Constructor_SoftMode_LeavesUnconfigured(string? key)
  {
    var protector = new ConfigAesGcmSecretProtector(key, failFast: false);

    protector.IsConfigured.ShouldBeFalse();
  }

  [Fact]
  public void SoftMode_Unconfigured_ProtectThrows()
  {
    var protector = new ConfigAesGcmSecretProtector(null, failFast: false);

    Should.Throw<InvalidOperationException>(() => protector.Protect("x"));
  }

  [Fact]
  public void SoftMode_Unconfigured_UnprotectThrows()
  {
    var protector = new ConfigAesGcmSecretProtector(null, failFast: false);

    Should.Throw<InvalidOperationException>(() => protector.Unprotect("x"));
  }

  /// <summary>
  /// CRITICAL invariant: the consolidated protector must decrypt a token produced by the
  /// ORIGINAL implementations (AML's <c>AesGcmCredentialCipher</c> / Kefi's
  /// <c>ConfigAesGcmSecretProtector</c>), whose on-disk layout is
  /// <c>base64( nonce(12) ‖ tag(16) ‖ ciphertext )</c>. This reproduces that exact
  /// encryption inline (independent of the class under test) and asserts a clean
  /// round-trip — proving already-stored ciphertext survives the swap byte-for-byte.
  /// </summary>
  [Fact]
  public void Unprotect_DecryptsTokenFromOriginalOnDiskFormat()
  {
    var key = new byte[32]
    {
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    };
    const string secret = "os_live_abc123-XYZ_456";
    var legacyToken = EncryptLikeOriginal(key, secret);

    var protector = new ConfigAesGcmSecretProtector(Convert.ToBase64String(key), failFast: true);

    protector.Unprotect(legacyToken).ShouldBe(secret);
  }

  /// <summary>
  /// Byte-for-byte reproduction of the ORIGINAL cipher's Encrypt: AES-256-GCM with a
  /// 12-byte nonce and 16-byte tag, packed as nonce ‖ tag ‖ ciphertext then base64.
  /// </summary>
  private static string EncryptLikeOriginal(byte[] key, string plaintext)
  {
    var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
    var plainBytes = Encoding.UTF8.GetBytes(plaintext);
    var cipherBytes = new byte[plainBytes.Length];
    var tag = new byte[TagBytes];

    using var aes = new AesGcm(key, TagBytes);
    aes.Encrypt(nonce, plainBytes, cipherBytes, tag);

    var packed = new byte[NonceBytes + TagBytes + cipherBytes.Length];
    Buffer.BlockCopy(nonce, 0, packed, 0, NonceBytes);
    Buffer.BlockCopy(tag, 0, packed, NonceBytes, TagBytes);
    Buffer.BlockCopy(cipherBytes, 0, packed, NonceBytes + TagBytes, cipherBytes.Length);
    return Convert.ToBase64String(packed);
  }
}
