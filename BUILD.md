# Build & Publish — Security.SecretProtector

## Build + test locally

```bash
cd NuGetPackages/Security.SecretProtector
dotnet restore Security.SecretProtector.sln
dotnet build Security.SecretProtector.sln -c Release --no-restore
dotnet test  Security.SecretProtector.sln -c Release --no-build
```

## Pack

```bash
dotnet pack src/Security.SecretProtector/Security.SecretProtector.csproj -c Release -o artifacts
```

## Publish to nuget.org

```powershell
cd NuGetPackages/Security.SecretProtector
.\publish.ps1 -Bump patch -ApiKey YOUR_NUGET_API_KEY
```

`publish.ps1` bumps the version in `Directory.Build.props`, cleans, restores, builds,
packs, and pushes (`--skip-duplicate`), rolling the version back on failure.

## Notes

- The on-disk token format (`base64( nonce(12) ‖ tag(16) ‖ ciphertext )`) is a stable
  compatibility contract. Never change nonce/tag sizes, ordering, or the base64 scheme —
  doing so silently breaks decryption of every already-stored secret.
- No secrets/keys belong in this repo. The 32-byte key value is supplied by each consuming
  service via its own runtime configuration / Kubernetes secret.
