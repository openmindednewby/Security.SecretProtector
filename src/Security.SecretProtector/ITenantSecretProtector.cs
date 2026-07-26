namespace Security.SecretProtector;

/// <summary>
/// Per-tenant authenticated encryption for credentials stored at rest — e.g. a client's
/// EMI / bank API credentials in FINREG. Extends the single-key <see cref="ISecretProtector"/>
/// model with a per-tenant key <b>derived on demand</b>, so a token protected for one tenant
/// cannot be decrypted under another tenant's identity even though both share one master key.
/// </summary>
/// <remarks>
/// <para>
/// The canonical implementation (<see cref="HkdfTenantSecretProtector"/>) keeps a <b>versioned</b>
/// master keyring — a small set of 32-byte keys that only ever live in a secrets manager — and
/// derives the per-tenant encryption key as
/// <c>HKDF-SHA256(masterKey_v, salt = UTF8(tenantId), info = "finreg-tenant-credential-v1")</c>.
/// No per-tenant key material is ever stored: it is recomputed for each protect / unprotect and
/// zeroed immediately after use.
/// </para>
/// <para>
/// Token layout (then base64): <c>[2-byte keyVersion BE][12-byte nonce][16-byte tag][ciphertext]</c>.
/// The embedded version selects the master key at unprotect time, which is what makes zero-downtime
/// key rotation possible: introduce a new current version, keep older versions available to decrypt
/// already-stored tokens, and re-encrypt lazily. This versioned layout is a <b>distinct token type</b>
/// from the single-key protector's <c>nonce ‖ tag ‖ ciphertext</c> — the two are never interchanged.
/// </para>
/// <para>
/// A protected value is NEVER returned to a client — only the server unprotects it, immediately
/// before use, on the payment path. "Write-only" is an API-surface property the consuming service
/// enforces, not this type.
/// </para>
/// </remarks>
public interface ITenantSecretProtector
{
  /// <summary>
  /// True when a current master key is configured and the protector can protect / unprotect.
  /// Always true under fail-fast registration (a missing keyring throws at startup); false in
  /// soft mode when no keyring is configured.
  /// </summary>
  bool IsConfigured { get; }

  /// <summary>
  /// Encrypts <paramref name="plaintext"/> for <paramref name="tenantId"/> under the CURRENT
  /// master key version and returns an opaque, self-describing base64 token. Throws if the
  /// protector is not configured, or either argument is null / blank.
  /// </summary>
  string Protect(string tenantId, string plaintext);

  /// <summary>
  /// Decrypts a token produced by <see cref="Protect"/> for the SAME <paramref name="tenantId"/>.
  /// Throws if the protector is not configured, the token is malformed, its key version is
  /// unknown (retired), or it fails authentication — which <b>includes</b> the case where
  /// <paramref name="tenantId"/> differs from the one it was protected for.
  /// </summary>
  string Unprotect(string tenantId, string token);
}
