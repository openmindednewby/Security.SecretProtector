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
}
