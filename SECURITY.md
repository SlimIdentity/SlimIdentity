# Security Policy

SlimIdentity is an authentication library, so security reports are taken seriously and handled with priority.

## Supported versions

Security fixes are made for the **latest released version** only.
Please upgrade before reporting an issue that may already be fixed.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for security problems.**

Report vulnerabilities privately through GitHub:
**[Report a vulnerability](https://github.com/SlimIdentity/SlimIdentity/security/advisories/new)**
(repository → *Security* → *Advisories* → *Report a vulnerability*).

Please include as much as you can:

- affected version / commit and configuration (cookie or JWT mode, enabled capability stores, relevant options),
- a description of the issue and its impact,
- steps or a minimal proof of concept to reproduce it.

## What to expect

- Acknowledgement within **5 working days**.
- An initial assessment (accepted / needs more information / not a vulnerability) within **14 days**.
- For accepted reports: a fix and a coordinated release, published together with a GitHub security advisory
  (and a CVE where appropriate). You will be credited unless you prefer not to be.

## Verifying a package

Every package on nuget.org is built by the release workflow of this repository, which attests its build provenance.
Check that a package you downloaded comes from this repository and commit:

```bash
gh attestation verify SlimIdentity.0.9.0.nupkg --owner SlimIdentity
```

## Scope

In scope: the packages in `src/` (`SlimIdentity`, `SlimIdentity.EntityFrameworkCore`, `SlimIdentity.Passkeys`, `SlimIdentity.Testing`). Findings
made with the local [Breakme playground](BREAKME.md) that affect these packages are very welcome – a failing test is
the ideal proof of concept.

Out of scope: the copy-paste samples in `samples/` and the demo application in `samples/SlimIdentity.Demo`
(they are examples, not production code – reports about them are still welcome as regular issues if they
teach insecure patterns), vulnerabilities in ASP.NET Core or other third-party dependencies (please report those
upstream), and issues that require a misconfiguration explicitly warned against in the documentation.
