# FastPAS PowerShell

[![PowerShell quality](https://github.com/HSFerrum/FastPAS-PowerShell/actions/workflows/test.yml/badge.svg)](https://github.com/HSFerrum/FastPAS-PowerShell/actions/workflows/test.yml)

FastPAS PowerShell is a Windows PowerShell 7 operator toolkit for Idira/CyberArk
Privileged Access Manager across ISPSS, self-hosted/on-premises PAM, and
standalone/legacy Privilege Cloud. A single launcher authenticates once and
orchestrates focused PowerShell subscripts for safe management, account
management, telemetry, reports, and guarded remediation.

## The spirit of FastPAS

Privileged-access administration should be understandable, reviewable, and
safe even when the operator is not a PowerShell developer. FastPAS is built
around five ideas:

- **One front door:** authenticate once, choose a plain-language workflow, and
  let the launcher orchestrate the focused scripts.
- **Read before write:** exports, reports, plans, and baselines sit beside their
  matching change actions.
- **Safe by default:** passwords are never saved, CSVs never contain secrets,
  changes support `-WhatIf`, and unattended writes require multiple explicit
  safety signals.
- **Evidence over mystery:** commands return structured results, artifacts,
  warnings, and redacted audit events instead of hiding work behind a success
  message.
- **Useful across real tenants:** optional APIs degrade to visible warnings so
  one unavailable service does not erase the data that can still be collected.

FastPAS is an independent community project and is not an official CyberArk
product. CyberArk and related product names are trademarks of their respective
owners.

## Documentation

- [Quick start](#quick-start)
- [Operator guide](docs/OPERATOR-GUIDE.md)
- [Launcher, module, and command flags](docs/CLI-REFERENCE.md)
- [Deployment and profile guide](docs/DEPLOYMENTS.md)
- [All 47 commands](docs/COMMAND-REFERENCE.md)
- [Menus and workflows](docs/MENU.md)
- [CSV templates](templates/csv/README.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security model](SECURITY.md)
- [Support and safe issue reporting](SUPPORT.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## Requirements

- Windows 10/11 or Windows Server with PowerShell 7+
- An ISPSS tenant, an HTTPS PVWA for self-hosted PAM, or a standalone/legacy
  Privilege Cloud PVWA
- An authentication method enabled by that deployment: ISPSS OAuth, native
  Identity, or federated eIDP; or direct PVWA CyberArk, LDAP, RADIUS, or Windows
- Appropriate Vault permissions for each selected workflow

No PowerShell Gallery module is required at runtime. Pester 5 and
PSScriptAnalyzer are development-only dependencies.

## Quick start

```powershell
pwsh ./FastPAS.ps1
```

At every interactive startup, FastPAS lists all saved profiles followed by
`Create a new profile`. On Windows, the profile builder is a popup form with
deployment and authentication dropdowns; the text wizard remains available.
Pass `-Profile <name-or-id>` to skip that menu and
target a saved profile directly. Profiles contain connection metadata only and
you can save as many as needed. The Vault API base URL is derived from the
tenant subdomain. The Identity host is discovered by following the tenant's
shared-services, user-portal, and Privilege Cloud redirects and inspecting the
returned page for an `.id.cyberark.cloud` or `.my.idaptive.app` host. An explicit
`New-FastPASProfile -IdentityHost` remains available when discovery is blocked.
Connection metadata is stored beneath `%LOCALAPPDATA%\FastPAS.PowerShell`.
Passwords and OAuth client secrets are never persisted: FastPAS requests them
again when a profile connects. Access tokens exist only in the PowerShell
process. Upgrading an older configuration removes legacy FastPAS credentials
from Windows Credential Manager during the schema migration.

Profile creation begins by selecting one deployment type:

- **ISPSS** asks for the tenant subdomain and ISPSS authentication details.
  Identity and Privilege Cloud endpoints are discovered or derived.
- **On-premises** asks for the PVWA URL, direct PVWA authentication method, and
  Vault username. The runtime password and optional RADIUS OTP are never saved.
- **Standalone** means legacy/standard Privilege Cloud without the ISPSS
  Identity flow. It asks for the Privilege Cloud PVWA URL and direct PVWA
  authentication details.

Federated profiles do not request or store the external identity provider's
password. FastPAS asks CyberArk for an out-of-band IdP redirect, validates that
it is an absolute non-local HTTPS URL, opens it in the default system browser,
and completes the CyberArk continuation using either the displayed PIN or
approval-status polling, as directed by the tenant.

Run a report without the menu:

```powershell
$secret = Read-Host 'Password or OAuth client secret' -AsSecureString
& ./FastPAS.ps1 `
  -Profile serviceslab `
  -Command account.inventory `
  -ArgumentsJson '{"SafeName":"Production"}' `
  -Secret $secret `
  -NonInteractive `
  -OutputPath ./output
```

`-Profile` accepts either the saved profile name or its UUID. Federated and
native interactive profiles require an interactive session for browser/MFA
challenges. OAuth and native interactive profiles require a fresh runtime
secret. Direct PVWA profiles also require their password every run. RADIUS can
receive a separate runtime-only `-OneTimePassword`. Command mode can receive a
newly obtained `SecureString` using
`-Secret $secret`; scripts that import the module can use
`Connect-FastPAS -ProfileId <id> -Secret $secret`. The secret exists only for
that authentication attempt and is never written to the profile.

Preview a write:

```powershell
& ./FastPAS.ps1 `
  -Profile serviceslab `
  -Command resolution.account-failures `
  -ArgumentsJson '{"AccountIds":["12_3","12_4"]}' `
  -Secret $secret -NonInteractive -WhatIf
```

An unattended write requires all three explicit signals:

```powershell
& ./FastPAS.ps1 `
  -Profile serviceslab `
  -Command resolution.account-failures `
  -ArgumentsJson '{"AccountIds":["12_3"]}' `
  -Secret $secret -NonInteractive -Force -Confirm:$false
```

Interactive writes display their arguments and require typing `APPLY` exactly.

## Main menu

The interactive launcher presents six sections. Each section first separates
**Read-only reports and inspection** from **Changes and repair actions**, and
every command is labeled `[READ]` or `[CHANGE]`. A command may appear in more
than one section when it belongs to more than one workflow.

- **Telemetry and Reports**: the complete original FastPAS telemetry set—Most
  Used Components, Identity User Activity, and Account Failures—plus account,
  safe-member, safe, platform, PSM-user, and Privilege Cloud license-capacity
  reports. Dashboards return console tables and export both CSV and styled HTML.
- **Bulk Actions**: safe, safe-member, account, platform-move, local-to-domain,
  and repair workflows. Current-state exports appear here beside the matching
  update actions.
- **Safe Management**: safe queries, creation, members, inventory, and bulk CSV
  actions.
- **Account Management**: account search/detail/inventory, bulk metadata
  changes, platform moves, conversion, and failure repair.
- **Platform Management**: target-platform queries/reports, bulk account
  migration, and a read-only PMTerminal CPM plug-in audit.
- **Troubleshooting and Tools**: dependency checks, CyberArk/SIA connectivity,
  CPM/PSM failure analysis, local-to-domain conversion, and bulk repair.

Every interactive page ends with **Previous page**. From a command list it
returns to the read/change choice, from there to the main menu, and from the
main menu to profile selection so another tenant can be chosen without
restarting FastPAS. Before execution, FastPAS explains the command, identifies
required and optional inputs, supplies conservative defaults, suggests the
correct CSV template, verifies input files exist, and pauses so the result can
be read.

The expanded operations suite also includes a compliance command center,
discovered-account onboarding workbench, linked/dependent-account reporting,
effective-access governance, system health and capacity, platform drift,
live/historical PSM session operations, Application ID exposure, dual-control
requests, and verified safe-to-safe account migration. Report/plan commands are
separate from apply/action commands so read-only assessment never requires
mutation approval. See [Expanded operations](docs/EXPANDED-OPERATIONS.md).

Editable CSV templates and instructions are under [`templates/csv`](templates/csv).
Export the current state first, copy the appropriate template, run the write
command with `-WhatIf`, and then apply it. Bulk result files contain per-row
success/failure details. Passwords are intentionally unsupported in CSV files.

The `account.safe-transfer` workflow is the deliberate exception that handles
a secret in memory. It supports high-volume runs with bounded parallel
sessions, proactive token renewal, per-worker checkpoints, safe resume, and
final source/destination reconciliation. Its CSV contains only
`OldSafe,NewSafe`; no secret is written to a plan or result. It does not move
password history, audit history, recordings, requests, account links, or group
membership. Follow the [high-volume transfer runbook](docs/HIGH-VOLUME-ACCOUNT-TRANSFER.md).
Set `RelationshipMode=FullFidelity` for fail-closed discovery and verified
preservation of supported direct Logon/Reconcile links. This mode requires an
explicit `CpmOperationalState=Paused` attestation. It also recreates and
verifies dependent accounts—including Windows Services, Scheduled Tasks, and
IIS application pools—with their complete platform-property bags, management
settings, and links. Account groups, unresolved objects, and linked targets in
the same run remain fail-closed.

The operational menu items from the earlier CyberArk API Runner are included
with corrected endpoint selection, strict permission parsing, stable
safe-member export columns, and conflict-safe resumable CPM updates. See the
[API Runner port notes](docs/API-RUNNER-PORT.md).

Reports are written to `./output` by default. Operational audit events are
written as redacted JSON Lines under the application data directory. Generated
reports can contain sensitive tenant metadata and are excluded from Git.

See the [operator guide](docs/OPERATOR-GUIDE.md), [command reference](docs/COMMAND-REFERENCE.md), [menu and workflows](docs/MENU.md), [API Runner port notes](docs/API-RUNNER-PORT.md), [architecture](docs/ARCHITECTURE.md), [security guidance](SECURITY.md), and [contributing guide](CONTRIBUTING.md).
