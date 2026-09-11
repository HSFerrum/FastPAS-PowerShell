# Testing and compatibility

[Home](../README.md) · [Architecture](ARCHITECTURE.md) · [Support](../SUPPORT.md)

FastPAS uses layered tests so compatibility means more than successfully
importing the module.

| Layer | What it verifies |
|---|---|
| Windows PowerShell 5.1 compatibility | Parses every runtime file, imports all 47 commands, creates a profile, exports a report, and exercises JSON, hashing, and secret-comparison helpers. |
| Catalog runtime smoke | Invokes all 29 read commands and all 18 write commands in both PowerShell editions. Commands are run for every deployment type declared in the catalog. Write commands use `WhatIf`, and the API mock rejects any attempted mutation. |
| Pester unit/integration suite | Exercises authentication challenges, eIDP continuation, token handling, URL and pagination behavior, safe reports, profile migration, deployment guards, account transfers, retries, relationship preservation, secret verification, and empty API results. The same suite runs in Windows PowerShell 5.1 and PowerShell 7. |
| Static quality checks | Parses the project, validates command/menu/help/template contracts, runs PSScriptAnalyzer, and rejects unreachable command scripts. |
| Credential scan | Rejects credential-like values and prohibited generated or profile data before publication. |

The catalog smoke uses synthetic CyberArk response objects. This proves that
the orchestration, validation, response-shape handling, report generation, and
safety paths execute in each supported PowerShell/deployment combination. It
does not replace testing against the exact CyberArk release, licensed services,
roles, and endpoint permissions used by a customer. Optional endpoints are
designed to return explicit warnings when a deployment or role does not expose
them.

Run the full local checks with:

```powershell
pwsh ./tools/Test-NoCommittedSecrets.ps1
pwsh ./tools/Test-CommandCatalogRuntime.ps1
pwsh ./tools/Test-Project.ps1

& "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -File ./tools/Test-PowerShell51.ps1
& "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -File ./tools/Test-CommandCatalogRuntime.ps1
& "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -File ./tools/Test-PesterSuite.ps1
```

GitHub Actions runs the same dual-runtime catalog and unit coverage on every
push and pull request.
