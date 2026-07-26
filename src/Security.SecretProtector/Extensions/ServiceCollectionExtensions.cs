using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Security.SecretProtector.Extensions;

/// <summary>
/// Registration helpers for the shared <see cref="ISecretProtector"/>.
/// </summary>
public static class ServiceCollectionExtensions
{
  /// <summary>
  /// Registers <see cref="ConfigAesGcmSecretProtector"/> as the singleton
  /// <see cref="ISecretProtector"/>, keyed from the configuration value named
  /// <paramref name="configKeyName"/>.
  /// </summary>
  /// <param name="services">The service collection.</param>
  /// <param name="configKeyName">
  /// The configuration key the 32-byte encryption key is read from (e.g.
  /// <c>Providers:CredentialKey</c> or <c>KEFI_SECRETS_ENC_KEY</c>).
  /// </param>
  /// <param name="failFast">
  /// When true (the default), a missing / malformed / wrong-length key throws at
  /// startup — use this when the secret is mandatory. When false, an unset key leaves
  /// the protector un-configured (<see cref="ISecretProtector.IsConfigured"/> is false)
  /// so optional-secret callers can gate on it instead of crashing.
  /// </param>
  /// <remarks>
  /// Registered with <c>TryAddSingleton</c> so a test host (or an alternative key
  /// source) can register its own <see cref="ISecretProtector"/> first without this
  /// call clobbering it. The key value itself lives only in the app's runtime
  /// configuration / secret — never in this package or any committed file.
  /// </remarks>
  public static IServiceCollection AddConfigSecretProtector(
      this IServiceCollection services,
      string configKeyName,
      bool failFast = true)
  {
    ArgumentException.ThrowIfNullOrWhiteSpace(configKeyName);

    services.TryAddSingleton<ISecretProtector>(sp =>
    {
      var configuration = sp.GetRequiredService<IConfiguration>();
      return new ConfigAesGcmSecretProtector(configuration[configKeyName], failFast);
    });

    return services;
  }

  /// <summary>
  /// Registers <see cref="HkdfTenantSecretProtector"/> as the singleton
  /// <see cref="ITenantSecretProtector"/>, built from a versioned keyring under
  /// <paramref name="sectionName"/>. Expected configuration shape:
  /// <code>
  ///   {sectionName}:CurrentVersion = 1
  ///   {sectionName}:Keys:1         = &lt;base64/hex 32-byte key&gt;
  ///   {sectionName}:Keys:2         = &lt;base64/hex 32-byte key&gt;   // present only mid-rotation
  /// </code>
  /// </summary>
  /// <param name="services">The service collection.</param>
  /// <param name="configuration">
  /// The application configuration. Passed explicitly (rather than resolved lazily inside a
  /// factory) so the keyring is built — and validated — <b>eagerly at registration time</b>. That
  /// is the whole point: <paramref name="failFast"/> genuinely fails at <i>startup</i>, unlike the
  /// deferred-until-first-resolution behaviour of <see cref="AddConfigSecretProtector"/>.
  /// </param>
  /// <param name="sectionName">
  /// The configuration section the keyring is read from (e.g. <c>Providers:CredentialKeyring</c>).
  /// </param>
  /// <param name="failFast">
  /// When true (the default), a missing / malformed key or a current version without a key throws
  /// here — use this when the credential vault is mandatory. When false, an unset keyring leaves
  /// the protector un-configured (<see cref="ITenantSecretProtector.IsConfigured"/> false).
  /// </param>
  public static IServiceCollection AddTenantSecretProtector(
      this IServiceCollection services,
      IConfiguration configuration,
      string sectionName,
      bool failFast = true)
  {
    ArgumentNullException.ThrowIfNull(configuration);
    ArgumentException.ThrowIfNullOrWhiteSpace(sectionName);

    var section = configuration.GetSection(sectionName);
    _ = int.TryParse(section["CurrentVersion"], out var currentVersion);
    var rawKeys = section.GetSection("Keys").GetChildren()
        .Where(child => int.TryParse(child.Key, out _))
        .ToDictionary(child => int.Parse(child.Key), child => child.Value);

    // Eager: build + validate NOW, so fail-fast throws during application startup rather than on
    // the first request that happens to resolve the protector.
    var keyring = TenantSecretKeyring.Create(currentVersion, rawKeys, failFast);
    var protector = new HkdfTenantSecretProtector(keyring);

    services.TryAddSingleton<ITenantSecretProtector>(protector);
    return services;
  }
}
