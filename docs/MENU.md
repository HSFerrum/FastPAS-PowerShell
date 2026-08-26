# Menu and workflows

FastPAS uses a hierarchical menu driven by `config/commands.psd1`. `Sections`
allows one command script to appear in several logical locations without code
duplication. Direct command execution continues to use the stable command ID.
Every page includes a **Previous page** entry. Commands within each section are
split into **Read-only reports and inspection** and **Changes and repair
actions**. `[READ]` commands do not mutate CyberArk. `[CHANGE]` commands use
PowerShell `ShouldProcess`, support `-WhatIf`, and require explicit approval.
Command pages return to the risk-group page, section pages return to the main
menu, and the main menu returns to profile selection.

## Telemetry and Reports

The telemetry implementation ports the complete dashboard set from the original
FastPAS desktop project:

1. **Most Used Components** queries recent PSM recordings, groups connection
   components and access methods, and calculates counts and percentages.
2. **Identity User Activity** queries Identity SCIM users and classifies them as
   active this week, inactive one to four weeks, or inactive at least a month.
3. **Account Failures** combines CPM account-management signals with failed PSM
   recordings and exposes the guarded repair workflow.

Every telemetry command creates a CSV and a styled HTML dashboard while also
showing its current rows in the console. Safe, member, account, and platform
inventory reports use the same output convention.

The CyberArk API Runner PSM-user report is available here as well. It groups
recordings by vault user and reports session counts, first/last use, protocols,
clients, safes, and remote machines.

## Bulk workflow

Use the exports in the Bulk Actions menu to capture current state. Copy a file
from `templates/csv`, edit the copy, and provide its path to the matching apply
command. Each row is isolated so one API error does not hide the status of the
remaining rows; a result CSV is always produced.

Bulk mutations require the normal `APPLY` confirmation. Use `-WhatIf` to preview
every target. Unattended mutations require `-Force -Confirm:$false` as well.
FastPAS limits each bulk run and never accepts passwords in CSV.

Two safe-member modes are available: role-based add/update/delete, and the API
Runner-compatible add-missing importer with exact flattened permission columns.
Dedicated safe CPM export/apply commands use snapshot conflict detection,
post-write verification, and resumable failed-row checkpoints.

## Troubleshooting

Dependency checks validate the local PowerShell runtime and session. The
connectivity diagnostic tests DNS and TCP/443 for tenant-derived endpoints and
accepts exact documented SIA/product endpoints through `outbound-endpoints.csv`.
It does not guess regional product hostnames or scan ports. CPM and PSM analysis,
account repair, and local-to-domain account conversion are shared with their
other relevant menu sections.

## Expanded operations

The ten expanded feature areas are registered across the same six sections:

1. Compliance and hygiene command center (`compliance.posture`)
2. Discovery-to-onboarding workbench (`onboarding.discovered*`)
3. Linked and dependent-account relationships (`relationships.*`)
4. Effective-access and license governance (`governance.entitlements`)
5. Component health and capacity (`telemetry.system-health`)
6. Platform baseline and guarded drift changes (`platform.drift*`)
7. PSM session and incident console (`psm.sessions*`)
8. Application ID/provider exposure (`aam.exposure`)
9. Dual-control request operations (`request.*`)
10. Safe-to-safe migration planning and execution (`safe.migration.*`)
