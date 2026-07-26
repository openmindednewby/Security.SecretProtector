namespace Security.SecretProtector;

/// <summary>
/// Shared decoding of a configured 32-byte AES-256 key from base64 <b>or</b> hex.
/// Extracted so the single-key <see cref="ConfigAesGcmSecretProtector"/> and the
/// per-tenant <see cref="HkdfTenantSecretProtector"/> keyring decode key material
/// identically — one operator convention, one place to audit.
/// </summary>
internal static class SecretKeyDecoder
{
  /// <summary>The required decoded key length in bytes (AES-256).</summary>
  public const int KeyBytes = 32;

  /// <summary>
  /// Decodes <paramref name="raw"/> (base64 or hex) into a 32-byte key. Returns
  /// <c>false</c> — rather than throwing — for any missing / malformed / wrong-length
  /// value, so soft-mode callers can leave a protector un-configured.
  /// </summary>
  public static bool TryDecode(string? raw, out byte[] key)
  {
    key = [];
    if (string.IsNullOrWhiteSpace(raw))
    {
      return false;
    }

    var trimmed = raw.Trim();
    byte[] decoded;
    try
    {
      // Check hex FIRST: a 64-char hex string (32 bytes) is also valid base64 —
      // base64 would decode it to 48 bytes and mask the operator's intent.
      if (trimmed.Length == KeyBytes * 2 && trimmed.All(Uri.IsHexDigit))
      {
        decoded = Convert.FromHexString(trimmed);
      }
      else
      {
        try
        {
          decoded = Convert.FromBase64String(trimmed);
        }
        catch (FormatException)
        {
          decoded = Convert.FromHexString(trimmed);
        }
      }
    }
    catch (FormatException)
    {
      return false;
    }

    if (decoded.Length != KeyBytes)
    {
      return false;
    }

    key = decoded;
    return true;
  }
}
