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
| `src/SlimIdentity` | the NuGet package |
| `tests/SlimIdentity.Tests` | unit and integration tests (in-memory host, `FakeTimeProvider`) |
| `samples/SlimIdentity.Demo` | runnable demo (`dotnet run --project samples/SlimIdentity.Demo`, see the `.http` file) |
| `samples/SamplesCheck` | compiles the copy-paste templates in `samples/` against the current API |

Native AOT check (needs the platform's native toolchain, see the
[.NET docs](https://learn.microsoft.com/dotnet/core/deploying/native-aot/#prerequisites)):

```bash
dotnet publish samples/SlimIdentity.Demo -c Release -r linux-x64   # or win-x64 / osx-arm64
```

CI builds with warnings as errors, runs all tests and publishes the demo as Native AOT.

## Pull requests

- Keep changes focused; one topic per pull request.
- Add or update tests – especially for anything security-related.
- Every public type and member needs an XML doc comment (missing docs fail the CI build).
- Update the documentation in `docs/` and the README if behaviour or options change.
- Add a line to the `Unreleased` section of [CHANGELOG.md](CHANGELOG.md).
- Code style is defined in `.editorconfig`; your IDE picks it up automatically.

## Releases

Maintainers release by pushing a tag `vX.Y.Z`; the release workflow tests, packs and publishes to nuget.org.
