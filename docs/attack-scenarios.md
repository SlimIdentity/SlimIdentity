# Attack scenarios

A checklist for reviews – by people and by AI agents – and the current state of each scenario.

**Rule:** a finding is real only once a failing test demonstrates it. Every confirmed defence gets a permanent
regression test.

Status: **covered** – a test proves the defence · **design** – deliberate behaviour, documented · **host** – the
responsibility of the application (only our templates are reviewed) · **open** – not yet proven by a test.

The tests live in `tests/SlimIdentity.Tests` and in the conformance kit `SlimIdentity.Testing` (run against the test
stores and the EF Core templates).

## A. Login, lockout, enumeration

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
| A9 | `/register` timing (write only for new addresses) | design – with mail `/register` writes nothing (the account is created after the mailbox is proven); without mail a known limitation in the [security model](security.md#known-limitations), only measurable against the real database of a deployment, not in-process |
|  |  | covered |
|  |  | covered |
|  |  | covered |

## B. Cookies and CSRF

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |

## C. JWT, refresh tokens, sessions

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
|  |  | covered |
|  |  | covered |
|  |  | covered |
| C4 | Two parallel refreshes with the same token | design – exactly one wins, the other is treated as theft (no grace window); clients serialize, across tabs with Web Locks ([guide](guides/mobile-bearer.md#refreshing-correctly)); conformance proves single use |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |

## D. Two-factor authentication

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |

## E. Workflow tokens (reset, verification, invitation, e-mail change)

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
| E5 | Host-header injection into mail links | design – links come from `Links.BaseUrl`, never from request headers |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
| E9 | HTML / header injection in mails via address or display name | host – mail templates must encode user data ([security model](security.md#host-responsibilities)) |

## F. External login

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
| F5 | Missing or forged `state` / correlation (OAuth CSRF) | design – handled by the ASP.NET Core remote handlers; with `UseSlimErrorRedirects()` it ends at the default page with `external_login_failed`, never at a `returnUrl` from the forged request (tested) |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |

## G. Admin, impersonation, API keys

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| G1 | Impersonation without admin rights | host – authorization of the host endpoint; template `Enterprise/AdminEndpoints.cs` |
|  |  | covered |
|  |  | covered |
|  |  | covered |
| G5 | Impersonating a more privileged user | host – rules belong in the host endpoint (documented in the template) |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |

## H. Stores and infrastructure

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
| H4 | Data Protection key ring lost / changed | design – documented failure modes ([guide](guides/data-protection.md)); TOTP secrets: recovery codes |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |
|  |  | covered |

## Prompt template for one scenario

> You are the attacker. Goal: *&lt;scenario&gt;*. Read *&lt;files&gt;*. Describe a concrete attack with requests. Name the
> line of code that prevents it, or explain why nothing does. Write an xUnit integration test in the style of
> `tests/SlimIdentity.Tests/Integration` that performs the attack and fails if the attack succeeds.

No scenario is open at the moment. New scenarios start as **open** and are closed by a test – never by a comment.
