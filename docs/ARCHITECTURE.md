# Architecture

```text
FastPAS.ps1
  -> command catalog (config/commands.psd1)
  -> operator guidance (config/operator-help.psd1)
  -> FastPAS.PowerShell shared module
       -> metadata-only profile JSON
       -> ISPSS Identity or direct PVWA authentication session
       -> Vault API client, paging, retry, audit, reports
  -> Commands/<area>/*.ps1
       -> FastPAS.CommandResult
```

The launcher supports a Windows Forms profile builder, a text wizard, a guided
hierarchical console, and command mode. Startup lists every saved profile and a
create-profile option; `-Profile` selects a saved profile by
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
either `OOBAUTHPIN` or CyberArk approval-status polling. Entra, Okta, Ping, or
another upstream IdP handles all external credentials and conditional-access
controls; FastPAS receives only CyberArk continuation state and the resulting
platform token. Identity pod redirects are honored before challenge requests,
and every native MFA request retains the returned tenant ID. Native interactive
profiles also auto-detect this response and switch to the federated adapter.

Profile configuration uses a versioned JSON document and atomic replacement.
It stores connection metadata only and supports multiple independently named
profiles. Native passwords and OAuth client secrets are collected at connection
time and never written to disk. The schema-v1 migration deletes legacy FastPAS
Windows Credential Manager entries. Schema v3 adds deployment, normalized PVWA,
RADIUS delimiter, and TLS metadata without adding credentials.

ISPSS profiles exchange an Identity flow for a bearer platform token. On-prem
and standalone profiles POST runtime credentials to
`/PasswordVault/API/Auth/<provider>/Logon` and use the returned raw PVWA session
token. All command scripts then call relative Vault API paths through the same
client. Catalog deployment metadata blocks product-specific commands before an
unsupported request is sent.

For flows that can renew without another human challenge, the session keeps a
read-only `SecureString` copy only in process memory. It is used for same-run
token renewal and disposed by `Disconnect-FastPAS`. RADIUS never persists or
reuses an OTP; unattended renewal requires a new connection with a fresh OTP.
