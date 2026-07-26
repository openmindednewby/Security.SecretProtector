using System.Security.Cryptography;
using Security.SecretProtector;
using Shouldly;

namespace Security.SecretProtector.Tests;

/// <summary>
/// Tests for <see cref="HkdfTenantSecretProtector"/> — the per-tenant, versioned AES-256-GCM
/// protector behind FINREG's credential vault (F-10). Covers round-trip, the central
/// <b>cross-tenant isolation</b> guarantee (a key protected for one tenant cannot decrypt under
/// another), tamper rejection, versioned zero-downtime rotation, unknown-version rejection, and
/// fail-fast vs soft keyring construction.
/// </summary>
public class HkdfTenantSecretProtectorTests
{
  private const string TenantA = "tenant-aaaa-1111";
  private const string TenantB = "tenant-bbbb-2222";

  private static string Key(byte seed) => Convert.ToBase64String(Enumerable.Range(0, 32)
      .Select(i => (byte)(seed + i))
      .ToArray());

  private static TenantSecretKeyring Keyring(int current, params (int version, byte seed)[] keys) =>
      TenantSecretKeyring.Create(
          current,
          keys.ToDictionary(k => k.version, k => (string?)Key(k.seed)),
          failFast: true);

  private static HkdfTenantSecretProtector Protector(int current = 1) =>
      new(Keyring(current, (1, 10)));

  [Fact]
  public void Protect_ThenUnprotect_SameTenant_RoundTrips()
  {
    var protector = Protector();
    const string credential = "emi_live_client_secret_ABC123";

    var token = protector.Protect(TenantA, credential);

    token.ShouldNotContain(credential);
    protector.Unprotect(TenantA, token).ShouldBe(credential);
  }

  /// <summary>
  /// THE F-10 isolation proof: one tenant's key cannot decrypt another's credential. This test
  /// goes RED the instant the tenant id stops being the HKDF salt (both tenants would then derive
  /// the same key and the decrypt would succeed) — which is exactly the regression it guards.
  /// </summary>
  [Fact]
  public void Unprotect_ForDifferentTenant_Throws()
  {
    var protector = Protector();
    var tokenForA = protector.Protect(TenantA, "emi_live_secret_for_A");

    Should.Throw<CryptographicException>(() => protector.Unprotect(TenantB, tokenForA));
  }

  [Fact]
  public void Protect_ProducesDistinctTokensForSameInput()
  {
    var protector = Protector();

    // Random nonce per call → ciphertext must differ even for identical (tenant, plaintext).
    protector.Protect(TenantA, "same").ShouldNotBe(protector.Protect(TenantA, "same"));
  }

  [Fact]
  public void Unprotect_TamperedToken_Throws()
  {
    var protector = Protector();
    var raw = Convert.FromBase64String(protector.Protect(TenantA, "emi_live_secret"));
    raw[^1] ^= 0xFF; // flip a ciphertext bit → GCM tag mismatch
    var tampered = Convert.ToBase64String(raw);

    Should.Throw<CryptographicException>(() => protector.Unprotect(TenantA, tampered));
  }

  [Fact]
  public void Unprotect_TooShortToken_Throws()
  {
    Should.Throw<CryptographicException>(
        () => Protector().Unprotect(TenantA, Convert.ToBase64String(new byte[4])));
  }

  // --- Zero-downtime key rotation ------------------------------------------------------------

  /// <summary>
  /// A token written under version 1 must still decrypt after the keyring rotates its current
  /// version to 2 while retaining v1 — this is what "rotation without downtime" means: no stored
  /// credential becomes un-decryptable at the moment of rotation.
  /// </summary>
  [Fact]
  public void Unprotect_DecryptsOlderVersionAfterRotation()
  {
    var v1Only = new HkdfTenantSecretProtector(Keyring(current: 1, (1, 10)));
    var legacyToken = v1Only.Protect(TenantA, "emi_secret_written_under_v1");

    // Operator adds v2 and makes it current, but keeps v1 around.
    var rotated = new HkdfTenantSecretProtector(Keyring(current: 2, (1, 10), (2, 99)));

    rotated.Unprotect(TenantA, legacyToken).ShouldBe("emi_secret_written_under_v1");
  }

  [Fact]
  public void Protect_UsesCurrentVersion_AfterRotation()
  {
    // current = 2, but v1 is absent → a token that decrypts proves v2 (not v1) was used.
    var v2Only = new HkdfTenantSecretProtector(Keyring(current: 2, (2, 99)));

    var token = v2Only.Protect(TenantA, "written_now");

    v2Only.Unprotect(TenantA, token).ShouldBe("written_now");
  }

  [Fact]
  public void Unprotect_UnknownKeyVersion_Throws()
  {
    // Token written under v2, then v2 is retired (keyring only has v1) → must fail closed.
    var withV2 = new HkdfTenantSecretProtector(Keyring(current: 2, (1, 10), (2, 99)));
    var tokenV2 = withV2.Protect(TenantA, "secret");

    var afterRetiringV2 = new HkdfTenantSecretProtector(Keyring(current: 1, (1, 10)));

    Should.Throw<CryptographicException>(() => afterRetiringV2.Unprotect(TenantA, tokenV2));
  }

  // --- Argument guards -----------------------------------------------------------------------

  [Theory]
  [InlineData(null)]
  [InlineData("")]
  [InlineData("   ")]
  public void Protect_BlankTenant_Throws(string? tenant)
  {
    Should.Throw<ArgumentException>(() => Protector().Protect(tenant!, "x"));
  }

  [Fact]
  public void Protect_NullPlaintext_Throws()
  {
    Should.Throw<ArgumentNullException>(() => Protector().Protect(TenantA, null!));
  }

  // --- Keyring fail-fast vs soft -------------------------------------------------------------

  [Fact]
  public void Keyring_FailFast_NoKeyForCurrentVersion_Throws()
  {
    Should.Throw<InvalidOperationException>(
        () => TenantSecretKeyring.Create(2, new Dictionary<int, string?> { [1] = Key(10) }, failFast: true));
  }

  [Fact]
  public void Keyring_FailFast_MalformedKey_Throws()
  {
    Should.Throw<InvalidOperationException>(
        () => TenantSecretKeyring.Create(1, new Dictionary<int, string?> { [1] = "not-base64!!" }, failFast: true));
  }

  [Fact]
  public void Keyring_FailFast_NonPositiveCurrentVersion_Throws()
  {
    Should.Throw<InvalidOperationException>(
        () => TenantSecretKeyring.Create(0, new Dictionary<int, string?> { [1] = Key(10) }, failFast: true));
  }

  [Fact]
  public void Keyring_SoftMode_Empty_LeavesUnconfigured()
  {
    var keyring = TenantSecretKeyring.Create(1, new Dictionary<int, string?>(), failFast: false);

    keyring.IsConfigured.ShouldBeFalse();
  }

  [Fact]
  public void Protector_Unconfigured_ProtectThrows()
  {
    var protector = new HkdfTenantSecretProtector(
        TenantSecretKeyring.Create(1, new Dictionary<int, string?>(), failFast: false));

    protector.IsConfigured.ShouldBeFalse();
    Should.Throw<InvalidOperationException>(() => protector.Protect(TenantA, "x"));
  }

  [Fact]
  public void Protector_NullKeyring_Unconfigured()
  {
    new HkdfTenantSecretProtector(null).IsConfigured.ShouldBeFalse();
  }
}
