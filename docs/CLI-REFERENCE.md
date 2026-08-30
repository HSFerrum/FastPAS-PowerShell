# Launcher, module, and command flags

[Home](../README.md) · [Operator guide](OPERATOR-GUIDE.md) · [Commands](COMMAND-REFERENCE.md) · [Security](../SECURITY.md)

This page is the complete command-line reference. The interactive menu asks for
the same values in plain language and remains the recommended starting point.

## Launcher flags

```powershell
pwsh ./FastPAS.ps1 [-Profile <name-or-id>] [-Command <id>]
  [-ArgumentsJson <json-object>] [-OutputPath <path>] [-Secret <SecureString>]
  [-OneTimePassword <SecureString>]
  [-NonInteractive] [-Force] [-WhatIf] [-Confirm:<boolean>]
```

| Flag | Meaning |
|---|---|
| `-Profile` | Saved profile name or UUID. Aliases: `-TargetProfile`, `-ProfileName`. Required with `-Command`. |
| `-Command` | Stable catalog ID, such as `account.inventory`. Omitting it opens the menu. |
| `-ArgumentsJson` | JSON object containing command-specific arguments. Use `{}` when none are needed. |
| `-OutputPath` | Report/result directory. Default: `./output` from the current directory. |
| `-Secret` | Runtime-only `SecureString` for OAuth, Identity, or direct PVWA authentication. It is never persisted. |
| `-OneTimePassword` | Optional runtime-only RADIUS OTP/push keyword. It is never persisted. |
| `-NonInteractive` | Disables prompts and browser/challenge interaction. Requires `-Profile` and `-Command`. |
| `-Force` | One of the required safety signals for an unattended change. It does not bypass `ShouldProcess`. |
| `-WhatIf` | Previews every protected mutation without sending it. |
| `-Confirm:$false` | Disables PowerShell's confirmation prompt. Unattended writes require this together with `-Force`. |

`FastPAS.ps1` also accepts PowerShell common parameters such as `-Verbose`,
`-Debug`, `-ErrorAction`, `-WarningAction`, `-InformationAction`,
`-ProgressAction`, `-ErrorVariable`, `-WarningVariable`, `-InformationVariable`,
`-OutVariable`, `-OutBuffer`, and `-PipelineVariable`.

### Runtime secret examples

Start PowerShell 7, prompt once, and run a direct command:

```powershell
pwsh
$secret = Read-Host 'Password or OAuth client secret' -AsSecureString
& ./FastPAS.ps1 -Profile serviceslab -Command account.inventory -Secret $secret
```

Federated profiles must normally remain interactive because the system-browser
and MFA challenge cannot be completed under `-NonInteractive`.

### Change examples

Preview:

```powershell
& ./FastPAS.ps1 -Profile serviceslab `
  -Command bulk.safes.apply `
  -ArgumentsJson '{"CsvPath":"C:\\Work\\bulk-safes-reviewed.csv"}' `
  -WhatIf
```

Unattended apply:

```powershell
& ./FastPAS.ps1 -Profile serviceslab `
  -Command bulk.safes.apply `
  -ArgumentsJson '{"CsvPath":"C:\\Work\\bulk-safes-reviewed.csv"}' `
  -Secret $secret -NonInteractive -Force -Confirm:$false
```

## Command arguments

Pass these names as properties in `-ArgumentsJson`. A dash means that the
command has no value in that column. Template names live in `templates/csv`.

| Command ID | Accepted arguments | Required | Interactive default | Suggested template |
|---|---|---|---|---|
| `telemetry.components` | LookbackDays | — | LookbackDays=7 | — |
| `telemetry.active-users` | — | — | — | — |
| `telemetry.account-failures` | LookbackDays | — | LookbackDays=7 | — |
| `telemetry.psm-users` | LookbackDays | — | LookbackDays=90 | — |
| `account.inventory` | Search, SafeName | — | — | — |
| `safe.members.report` | SafeName | — | — | — |
| `safe.inventory` | Search | — | — | — |
| `bulk.safes.apply` | CsvPath | CsvPath | — | bulk-safes.csv |
| `bulk.safe-members.apply` | CsvPath | CsvPath | — | bulk-safe-members.csv |
| `bulk.safe-members.import-compatible` | CsvPath | CsvPath | — | safe-member-permissions.csv |
| `bulk.accounts.apply` | CsvPath | CsvPath | — | bulk-accounts.csv |
| `platform.accounts.move` | CsvPath | CsvPath | — | platform-account-moves.csv |
| `resolution.account-failures` | AccountIds | AccountIds | — | — |
| `safe.list` | Search | — | — | — |
| `safe.detail` | SafeName | SafeName | — | — |
| `safe.create` | SafeName, Description, ManagingCPM | SafeName | — | — |
| `safe.members.list` | SafeName | SafeName | — | — |
| `safe.members.add` | SafeName, MemberName, MemberType, Role | SafeName, MemberName | MemberType=user; Role=Viewer | — |
| `safe.cpm.export` | — | — | — | — |
| `safe.cpm.apply` | CsvPath | CsvPath | — | safe-cpm-assignments.csv |
| `account.search` | Search, SafeName | — | — | — |
| `account.detail` | AccountId | AccountId | — | — |
| `platform.list` | Search | — | — | — |
| `platform.accounts.report` | PlatformId | — | — | — |
| `platform.pmterminal.audit` | — | — | — | — |
| `troubleshooting.dependencies` | — | — | — | — |
| `troubleshooting.connectivity` | EndpointCsvPath | — | — | outbound-endpoints.csv |
| `troubleshooting.local-to-domain` | CsvPath | CsvPath | — | local-to-domain-accounts.csv |
| `compliance.posture` | PasswordAgeDays, InactiveDays | — | both 90 | — |
| `onboarding.discovered` | Search, PlatformType | — | — | — |
| `onboarding.discovered.apply` | CsvPath | CsvPath | — | discovered-account-decisions.csv |
| `relationships.report` | SafeName, MaxAccounts | — | MaxAccounts=500 | — |
| `relationships.apply` | CsvPath | CsvPath | — | account-links.csv |
| `governance.entitlements` | Principal, SafeName | — | — | — |
| `telemetry.system-health` | — | — | — | — |
| `platform.drift` | BaselinePath, PlatformId | — | — | — |
| `platform.drift.apply` | CsvPath | CsvPath | — | platform-changes.csv |
| `psm.sessions` | LookbackDays, UserName | — | LookbackDays=7 | — |
| `psm.sessions.action` | CsvPath | CsvPath | — | psm-session-actions.csv |
| `aam.exposure` | ApplicationId | — | — | — |
| `aam.exposure.apply` | CsvPath | CsvPath | — | application-authentication-changes.csv |
| `request.queue` | Status, OnlyWaiting | — | OnlyWaiting=true | — |
| `request.action` | CsvPath | CsvPath | — | access-request-actions.csv |
| `safe.migration.plan` | CsvPath | CsvPath | — | safe-account-migrations.csv |
| `safe.migration.apply` | CsvPath | CsvPath | — | generated migration plan |
| `account.safe-transfer` | CsvPath | CsvPath | — | account-safe-transfers.csv |

### Argument meanings

| Name | Accepted value |
|---|---|
| `AccountId` | One exact CyberArk account ID. |
| `AccountIds` | JSON array of account IDs; the interactive menu accepts comma-separated IDs. |
| `ApplicationId` | Exact Application ID filter. |
| `BaselinePath` | Existing platform-baseline JSON file. |
| `CsvPath` | Existing reviewed CSV file appropriate to the command. |
| `Description` | Optional safe description. |
| `EndpointCsvPath` | Existing CSV of exact additional HTTPS endpoints. |
| `InactiveDays` | Whole number from 1 through 3650. |
| `LookbackDays` | Whole number of days included by a report. |
| `ManagingCPM` | CPM name assigned to a new safe. |
| `MaxAccounts` | Relationship-report limit; maximum 500. |
| `MemberName` | Exact CyberArk user or group name. |
| `MemberType` | `user` or `group`. |
| `OnlyWaiting` | Boolean limiting request results to waiting requests. |
| `PasswordAgeDays` | Whole number from 1 through 3650. |
| `PlatformId` | Exact target platform ID. |
| `PlatformType` | Optional discovered-account platform-type filter. |
| `Principal` | User/group text used by the entitlement report. |
| `Role` | `Viewer`, `Operator`, or `Owner` safe permission preset. |
| `SafeName` | Exact safe name unless the command describes it as a filter. |
| `Search` | Free-text server-side search value. |
| `Status` | Optional dual-control request status. |
| `UserName` | Optional exact PSM/Vault username filter. |

## Exported module functions

Import the module with `Import-Module ./FastPAS.PowerShell.psd1`.

- `Resolve-FastPASTenant -Subdomain <string>`
- `Get-FastPASProfile [-Active]`, `-Id <string>`, or `-Name <string>`
- `New-FastPASProfile -Name <string> -DeploymentType <ispss|onprem|standalone> -AuthType <oauth|interactive|federated|cyberark|ldap|radius|windows> [deployment-specific fields] [-SetActive]`
- `Set-FastPASActiveProfile -ProfileId <string>`
- `Remove-FastPASProfile -ProfileId <string> [-WhatIf] [-Confirm]`
- `Connect-FastPAS [-ProfileId <string>] [-Secret <SecureString>] [-OneTimePassword <SecureString>] [-NonInteractive]`
- `Disconnect-FastPAS -Context <session>`
- `Invoke-FastPASApiRequest -Context <session> -Method <verb> -Path <relative-path> [-Query <hashtable>] [-Body <object>] [-NoRetry]`
- `Get-FastPASCommand [-Id <string>]`
- `Get-FastPASMenuSection`
- `Invoke-FastPASCommand -Id <string> -Context <session> [-Arguments <hashtable>] [-OutputPath <path>] [-NonInteractive] [-Force] [-WhatIf] [-Confirm]`

Use `Get-Help <function> -Full` for locally installed parameter and common-flag
details.

## Profile fields by deployment

| Deployment | Required profile metadata | Authentication |
|---|---|---|
| ISPSS | `Subdomain`; `Username` for user flows, or `ApplicationId` and `ClientId` for OAuth. `IdentityHost` and `VaultApiBaseUrl` may be overridden when discovery is blocked. | `oauth`, `interactive`, `federated` |
| On-premises | `PVWAUrl`, `Username`; optional `RadiusOtpDelimiter` and emergency `SkipCertificateCheck`. | `cyberark`, `ldap`, `radius`, `windows` |
| Standalone | `PVWAUrl`, `Username`; optional `RadiusOtpDelimiter`. | `cyberark`, `ldap`, `radius`, `windows` |

`PVWAUrl` may be the HTTPS server root, `/PasswordVault`, or
`/PasswordVault/API`; FastPAS normalizes it to the API base. Profiles never
contain the password, OAuth secret, OTP, session token, or account content.
