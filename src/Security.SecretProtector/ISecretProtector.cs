namespace Security.SecretProtector;

/// <summary>
/// Symmetric authenticated encryption for sensitive secrets stored at rest — e.g.
/// per-tenant payment credentials, external-provider API keys, and webhook signing
/// secrets. A protected secret is never stored in plaintext and is never returned to
/// a client; only the server unprotects it to use it.
/// </summary>
/// <remarks>
/// <para>
/// The canonical implementation (<see cref="ConfigAesGcmSecretProtector"/>) is
/// AES-256-GCM keyed by a single platform-supplied key read from configuration. The
/// stored token layout is <c>base64( nonce(12) ‖ tag(16) ‖ ciphertext )</c>. GCM
/// authenticates the ciphertext, so a tampered or wrong-key token throws on
/// <see cref="Unprotect"/> rather than returning garbage.
/// </para>
/// <para>
/// Rotating the key invalidates every stored ciphertext, so the key is
/// catastrophic-if-lost. Each consuming service supplies its own key value under its
/// own configuration name; the package owns the crypto, the app owns key sourcing.
/// </para>
/// </remarks>
public interface ISecretProtector
{
  /// <summary>
  /// True when an encryption key is configured and the protector can protect/unprotect.
  /// Always true when the protector was registered in fail-fast mode (a missing key
  /// throws at construction). In soft mode this is false when the key is absent or
  /// malformed, so optional-secret callers can survive an unset key.
  /// </summary>
  bool IsConfigured { get; }

  /// <summary>
  /// Encrypts <paramref name="plaintext"/> and returns an opaque, self-describing
  /// base64 token (nonce + tag + ciphertext). Throws if the protector is not configured.
  /// </summary>
  string Protect(string plaintext);

  /// <summary>
  /// Decrypts a token produced by <see cref="Protect"/>. Throws if the protector is not
  /// configured, or if the token is malformed or fails authentication (tamper / wrong key).
  /// </summary>
  string Unprotect(string token);
}
