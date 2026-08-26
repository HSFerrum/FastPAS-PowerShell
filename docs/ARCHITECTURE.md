# Architecture

```text
FastPAS.ps1
  -> command catalog (config/commands.psd1)
  -> operator guidance (config/operator-help.psd1)
  -> FastPAS.PowerShell shared module
       -> metadata-only profile JSON
       -> Identity authentication + platform-token session
       -> Vault API client, paging, retry, audit, reports
  -> Commands/<area>/*.ps1
       -> FastPAS.CommandResult
```

The launcher supports a guided hierarchical console and command mode. Startup lists every
saved profile and a create-profile option; `-Profile` selects a saved profile by
name or UUID without showing that menu. The catalog assigns each command to one
or more menu sections, allowing the same script to be referenced from Safe,
Bulk, Reporting, or Troubleshooting views without duplication. The catalog owns
routing and safety metadata; `operator-help.psd1` owns plain-language
descriptions, required inputs, defaults, templates, and parameter guidance.
Subscripts run in the module process so they share one
authenticated context; tokens are never serialized or passed through command
lines.

Each subscript accepts `Context`, `Arguments`, `OutputPath`, `NonInteractive`,
and `Force`, supports `ShouldProcess`, and returns one object with these fields:

- `Success`, `Summary`, and structured `Data`
- `Warnings` for partial but usable results
- `Artifacts` containing report paths
- `AuditEvents` describing material actions without secrets

This uniform contract is intentional. Some parameters are unused by a given
script, but retaining the same signature keeps orchestration, testing, and new
command development predictable. Read-only and change commands are separated
at menu-render time using the descriptor's risk level.

OAuth profiles validate the Identity token endpoint and request a PAM SaaS
platform token. Interactive profiles use `StartAuthentication` and
`AdvanceAuthentication`, including challenge selection and push polling. The
API layer renews credentials once after a 401/403 and proactively renews shortly
before known expiry.

Federated profiles send `OobIdPAuth: true` to `StartAuthentication`. When
CyberArk returns `IdpRedirectShortUrl` and `IdpLoginSessionId`, FastPAS opens the
validated HTTPS redirect in the system browser and completes the exchange with
the `OOBAUTHPIN` mechanism. Entra, Okta, Ping, or another upstream IdP handles
all external credentials and conditional-access controls; FastPAS receives only
the CyberArk PIN and resulting platform token. Native interactive profiles also
auto-detect this response and switch to the federated adapter.

Profile configuration uses a versioned JSON document and atomic replacement.
It stores connection metadata only and supports multiple independently named
profiles. Native passwords and OAuth client secrets are collected at connection
time and never written to disk. The schema-v1 migration deletes legacy FastPAS
Windows Credential Manager entries before rewriting the metadata as schema v2.
