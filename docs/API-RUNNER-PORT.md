# CyberArk API Runner port

FastPAS now includes every operational menu item from
`C:\Projects\cyberark-api-runner\CyberArkApiRunner.ps1`. Authentication,
profiles, token refresh, auditing, output paths, and write confirmation use the
FastPAS implementations instead of duplicating the runner infrastructure.

| API Runner item | FastPAS command |
|---|---|
| Fetch safe members and groups | `safe.members.report` |
| Add missing safe members/groups from CSV | `bulk.safe-members.import-compatible` |
| Export PSM users from recordings | `telemetry.psm-users` |
| Audit PMTerminal platform references | `platform.pmterminal.audit` |
| Export safe CPM assignments | `safe.cpm.export` |
| Update safe CPM assignments | `safe.cpm.apply` |

The PSM-user report uses the active profile's recordings API. The runner's
on-prem PVWA authentication model is now implemented centrally: on-prem and
standalone profiles support CyberArk, LDAP, RADIUS, and Windows PVWA logon and
send the raw PVWA session token required by self-hosted API calls.

## Corrections made during the port

- Safe-member exports use a stable, complete permission schema. The runner
  built columns dynamically, so permissions found only after the first row
  could be omitted by `Export-Csv`.
- Permission imports accept the runner and epv-api-scripts column spellings but
  reject values other than explicit booleans. Legacy
  `RequestsAuthorizationLevel` values 0-2 are converted to the current level-1
  and level-2 flags.
- Member imports require a real `safeUrlId`; they never substitute a URL-encoded
  safe name as an ID. Existing members are read and skipped rather than having
  permissions overwritten.
- Target-platform enumeration uses `Platforms/Targets`; platform detail reads
  use `Platforms/{id}`. PMTerminal inspection remains read-only because there is
  no supported in-place REST mutation for that internal plug-in value.
- Safe CPM exports read each safe's full current details and add a SHA-256
  snapshot hash. Imports pre-read every safe, reject stale snapshots, build the
  required full `PUT` body from live data, and verify the CPM assignment after
  the update. This removes the runner's direct-write stale-overwrite risk.
- Safe CPM imports retain failed/conflicted rows in a checkpoint under the
  selected FastPAS output directory. Successful and already-compliant rows are
  removed immediately.
- All writes use the FastPAS `APPLY`, `-WhatIf`, unattended-write, row-limit,
  audit, redaction, and per-row result conventions.

Use `safe.cpm.export` to generate CPM input; edit only `ManagingCPM`. Blank
values skip a row, while `NULL` or `<NONE>` clears the CPM assignment.
