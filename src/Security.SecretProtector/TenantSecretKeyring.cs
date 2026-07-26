using System.Security.Cryptography;

namespace Security.SecretProtector;

/// <summary>
/// A versioned set of master keys for <see cref="HkdfTenantSecretProtector"/>. Exactly one
/// version is <see cref="CurrentVersion">current</see> (used to protect new secrets); older
/// versions are retained only to decrypt already-stored tokens, which is what enables
/// zero-downtime key rotation.
/// </summary>
/// <remarks>
/// The keys themselves live only in the app's runtime configuration / secret (a Kubernetes
/// Secret on staging / production) — never in this package or any committed file. Each key must
/// decode (base64 or hex) to exactly 32 bytes.
/// </remarks>
public sealed class TenantSecretKeyring
{
  private readonly IReadOnlyDictionary<int, byte[]> _keys;

  private TenantSecretKeyring(IReadOnlyDictionary<int, byte[]> keys, int currentVersion)
  {
    _keys = keys;
    CurrentVersion = currentVersion;
  }

  /// <summary>The key version used to protect newly-written secrets.</summary>
  public int CurrentVersion { get; }

  /// <summary>True when at least the current version has a valid key.</summary>
  public bool IsConfigured => _keys.ContainsKey(CurrentVersion);

  /// <summary>
  /// Returns the master key for <paramref name="version"/>, or throws a
  /// <see cref="CryptographicException"/> when that version is unknown or retired — so a token
  /// bearing an out-of-range version fails like any other decrypt failure rather than leaking a
  /// distinguishable "bad argument".
  /// </summary>
  public byte[] KeyForVersion(int version) => _keys.TryGetValue(version, out var key)
      ? key
      : throw new CryptographicException(
          $"No master key is configured for version {version}; the token's key version is "
          + "unknown or has been retired.");

  /// <summary>
  /// Builds a keyring from raw configured key values.
  /// </summary>
  /// <param name="currentVersion">The version new secrets are protected with (must be &gt; 0).</param>
  /// <param name="rawKeys">Version → raw key string (base64 or hex, 32 bytes each).</param>
  /// <param name="failFast">
  /// When true (the default), a malformed key, a non-positive current version, or a missing key
  /// for the current version throws at construction — so the service fails at startup rather than
  /// silently storing un-recoverable secrets. When false, malformed keys are dropped and the
  /// keyring may be left un-configured (<see cref="IsConfigured"/> false).
  /// </param>
  public static TenantSecretKeyring Create(
      int currentVersion,
      IReadOnlyDictionary<int, string?> rawKeys,
      bool failFast = true)
  {
    ArgumentNullException.ThrowIfNull(rawKeys);

    var decoded = new Dictionary<int, byte[]>();
    foreach (var (version, raw) in rawKeys)
    {
      if (SecretKeyDecoder.TryDecode(raw, out var key))
      {
        decoded[version] = key;
      }
      else if (failFast)
      {
        throw new InvalidOperationException(
            $"The tenant secret key for version {version} is missing or invalid. Configure it as "
            + "32 bytes encoded in base64 or hex (e.g. `openssl rand -base64 32`), sourced from a "
            + "secrets manager — never an inline manifest value.");
      }
    }

    if (failFast)
    {
      if (currentVersion <= 0)
      {
        throw new InvalidOperationException(
            "The tenant secret keyring's CurrentVersion must be a positive integer.");
      }

      if (!decoded.ContainsKey(currentVersion))
      {
        throw new InvalidOperationException(
            $"The tenant secret keyring has no key for its current version {currentVersion}. "
            + "New secrets cannot be protected without it.");
      }
    }

    return new TenantSecretKeyring(decoded, currentVersion);
  }
}
