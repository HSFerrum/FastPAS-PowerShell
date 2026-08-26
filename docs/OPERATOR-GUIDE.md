# FastPAS operator guide

This guide assumes only basic PowerShell and CyberArk experience. FastPAS does
not save passwords or client secrets, and it does not export account passwords.

## Start FastPAS

Double-click `Run-FastPAS.cmd`, or open the project folder in a terminal and run:

```powershell
pwsh ./FastPAS.ps1
```

Choose a saved profile or create one. A profile stores only tenant and login
metadata. Enter the password or client secret again each time you connect. For
federated accounts, complete the external identity-provider flow in the system
browser and return to the terminal when prompted.

## Choose an operation

1. Choose the subject area from the main menu.
2. Choose **Read-only reports and inspection** or **Changes and repair actions**.
3. Choose a command. `[READ]` means no CyberArk mutation is sent. `[CHANGE]`
   means the command can change CyberArk and will require confirmation.
4. Read the command description and enter the requested values. Press Enter to
   accept a displayed default or skip an optional value.
5. Review the console summary. Large results show the first 50 rows and give the
   full CSV or HTML artifact path.

Use **Previous page** at any level to go back without reconnecting. FastPAS
catches command errors, explains that no later step was attempted, and returns
to the menu after you press Enter.

## Safest way to make a bulk change

1. Run the matching `[READ]` export or plan command first.
2. Copy the matching file from `templates/csv`; never edit the original
   template. Some guarded workflows use the export itself because it contains
   snapshot hashes needed to detect stale data.
3. Edit only the intended rows. Keep the header names unchanged. Do not put
   passwords, client secrets, or access tokens in a CSV.
4. Preview the command with `-WhatIf`. In the interactive menu, choose the
   change and decline or preview before applying where offered.
5. Run the command and type `APPLY` only after checking the displayed arguments.
6. Open the result CSV. Every input row receives a status and error detail so a
   partial failure is visible.

FastPAS verifies that a supplied CSV or baseline path exists before it starts a
command. Changes also use per-object `ShouldProcess` checks. Unattended changes
require `-NonInteractive -Force -Confirm:$false`; omitting any safety switch
causes the command to stop.

## Common input terms

- **Profile**: a saved tenant/login definition, not a saved password.
- **SafeName**: the exact display name of a CyberArk safe.
- **AccountId**: CyberArk's immutable account ID, not the username.
- **PlatformId**: the exact target platform identifier.
- **CSV path**: the full path to a reviewed input file, such as
  `C:\Work\safe-members-reviewed.csv`.
- **OutputPath**: where reports and result files are written. The default is the
  project's `output` folder.

## When a command fails

Read the first error message before retrying. The most common causes are an
incorrect object ID, missing CyberArk permission, a changed or unsupported API
for that tenant, or a CSV header/value error. Run **Check local FastPAS
dependencies** for workstation issues and **Test CyberArk and SIA endpoint
connectivity** for DNS/TCP issues. Use a fresh export if a guarded apply reports
a snapshot conflict.

Tenant roles and enabled CyberArk services determine which optional APIs are
available. Reports that combine optional endpoints preserve the usable data and
list unavailable endpoints as warnings instead of hiding the whole result.

