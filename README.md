# Security.SecretProtector

AES-256-GCM at-rest secret protection for multi-tenant SaaS services. One audited
implementation, shared across services, with a **fixed on-disk format** so stored
secrets keep decrypting across upgrades.

Consolidates two previously-duplicated copies:
- AML's `AesGcmCredentialCipher` (external-provider API keys, webhook signing secrets)
- Kefi's `ConfigAesGcmSecretProtector` (per-tenant Stripe credentials)

## Surface

```csharp
public interface ISecretProtector
{
    string Protect(string plaintext);   // → base64( nonce(12) ‖ tag(16) ‖ ciphertext )
    string Unprotect(string token);     // throws on tamper / wrong key / not configured
    bool IsConfigured { get; }          // false in soft mode when the key is unset
}
```

## On-disk format (stable — do not change)

A protected token is `base64( nonce(12 bytes) ‖ tag(16 bytes) ‖ ciphertext )`. AES-256-GCM
authenticated encryption: a tampered or wrong-key token throws on `Unprotect` rather than
returning garbage. The key is a 32-byte value decoded from **base64 or hex** (hex is
detected first for 64-char all-hex strings). Rotating the key invalidates every stored
ciphertext, so the key is catastrophic-if-lost.

## Quick start

Register the protector, pointing it at the configuration key that holds your 32-byte key:

```csharp
using Security.SecretProtector.Extensions;

// Mandatory secret → fail fast at startup if the key is missing/invalid (Kefi style):
builder.Services.AddConfigSecretProtector("KEFI_SECRETS_ENC_KEY", failFast: true);

// Optional secret → soft mode; ISecretProtector.IsConfigured gates callers (AML style):
builder.Services.AddConfigSecretProtector("Providers:CredentialKey", failFast: false);
```

Then consume it:

```csharp
public sealed class MyService(ISecretProtector protector)
{
    public string Store(string apiKey) => protector.Protect(apiKey);
    public string? Use(string ciphertext)
        => protector.IsConfigured ? protector.Unprotect(ciphertext) : null;
}
```

The key **value** lives only in the app's runtime configuration / secret (env var in dev,
Kubernetes secret in prod) — never in this package or any committed file. Generate one with
`openssl rand -base64 32`.

## Modes

| Mode | `failFast` | Missing / invalid key | Use when |
|------|-----------|-----------------------|----------|
| Fail-fast | `true` (default) | throws at construction/startup | the secret is mandatory |
| Soft | `false` | `IsConfigured == false`; `Protect`/`Unprotect` throw only if called | the secret is optional |

## License

MIT
