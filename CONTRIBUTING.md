# Contributing to SlimIdentity

Thanks for your interest! Bug reports, documentation fixes and pull requests are welcome.

**Security issues:** never open a public issue – please follow [SECURITY.md](SECURITY.md).

## Before you start

- For anything bigger than a small fix, please open an issue first so we can agree on the approach.
- SlimIdentity follows a few hard rules (see the [architecture document](docs/architecture-manifest.md)):
  no database or ORM dependency in the core package, no generics on the public API, framework-native building
  blocks only, opt-in capabilities, secure defaults, Native AOT compatibility.

## Building and testing

Requirements: the .NET 10 SDK (or newer).

```bash
dotnet build SlimIdentity.slnx
dotnet test SlimIdentity.slnx
```

The solution contains:

| Project | Purpose |
| :--- | :--- |
| `src/SlimIdentity` | the main NuGet package |
| `src/SlimIdentity.Testing` | NuGet package: conformance checks for store implementations |
| `tests/SlimIdentity.Tests` | unit and integration tests (in-memory host, `FakeTimeProvider`), conformance of the test stores |
| `tests/SlimIdentity.Samples.Tests` | compiles the copy-paste templates in `samples/` and runs the conformance checks against the EF Core stores (SQLite) |
| `samples/SlimIdentity.Demo` | runnable demo (`dotnet run --project samples/SlimIdentity.Demo`, see the `.http` file) |

All packages in `src/` share their metadata (`src/Directory.Build.props`) and get the same version from the git tag.
A change to a store contract needs a matching check in `SlimIdentity.Testing`.

Native AOT check (needs the platform's native toolchain, see the
[.NET docs](https://learn.microsoft.com/dotnet/core/deploying/native-aot/#prerequisites)):

```bash
dotnet publish samples/SlimIdentity.Demo -c Release -r linux-x64   # or win-x64 / osx-arm64
```

CI builds with warnings as errors, runs all tests and publishes the demo as Native AOT.

Optional local runs:

```bash
# templates against real database servers (CI uses service containers); databases are dropped and recreated
docker run -d --rm --name slim-pg -e POSTGRES_PASSWORD=slimidentity -e POSTGRES_DB=conformance -p 55432:5432 postgres:17
docker run -d --rm --name slim-mssql -e ACCEPT_EULA=Y -e "MSSQL_SA_PASSWORD=Slim-Identity-2026!" -p 51433:1433 mcr.microsoft.com/mssql/server:2022-latest
SLIMIDENTITY_TEST_POSTGRES="Host=localhost;Port=55432;Database=conformance;Username=postgres;Password=slimidentity" \
SLIMIDENTITY_TEST_SQLSERVER="Server=localhost,51433;User Id=sa;Password=Slim-Identity-2026!;TrustServerCertificate=true" \
  dotnet test tests/SlimIdentity.Samples.Tests
# timing measurement of attack scenario A3 (before a release, ~30 s)
SLIMIDENTITY_TIMING=1 dotnet test tests/SlimIdentity.Tests --filter TimingTests
```

## Pull requests

- Keep changes focused; one topic per pull request.
- Add or update tests – especially for anything security-related. Code that parses outside input (URLs, tokens,
  claims, headers) gets a property-based test in `tests/SlimIdentity.Tests/Unit/PropertyTests.cs` (FsCheck).
- Analyzer warnings fail the CI build; the selected rules and the deliberately disabled ones (with reasons) are in
  `.editorconfig`.
- Every public type and member needs an XML doc comment (missing docs fail the CI build).
- Update the documentation in `docs/` and the README if behaviour or options change.
- Add a line to the `Unreleased` section of [CHANGELOG.md](CHANGELOG.md).
- Code style is defined in `.editorconfig`; your IDE picks it up automatically.

## Releases

Maintainers release by pushing a tag `vX.Y.Z`; the release workflow tests, packs and publishes every package in `src/`
to nuget.org with the same version.

One-time setup before the first release (repository settings, not code):

- [ ] Repository public; **Settings → Code security**: private vulnerability reporting, Dependabot alerts and security
      updates, secret scanning **with push protection** (code scanning then runs via `codeql.yml` on its own).
- [ ] Branch protection for `main`: CI and CodeQL must pass.
- [ ] nuget.org: Trusted Publishing policy (owner `timmkautz`, repository `slimidentity`, workflow `release.yml`,
      environment `nuget`) and reserved ID prefix `SlimIdentity.*`.
- [ ] GitHub environment `nuget` with the variable `NUGET_USER`.
- [ ] After the first release: `PackageValidationBaselineVersion` in `src/Directory.Build.props`.
