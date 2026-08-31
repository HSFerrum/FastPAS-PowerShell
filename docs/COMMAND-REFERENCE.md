# FastPAS command reference

The catalog contains 47 commands. The primary menu below identifies the best
place to look first; cross-functional commands also appear in other relevant
menus. The interactive launcher displays the same description before asking for
inputs. Run `Get-FastPASCommand -Id <id>` after importing the module to inspect
parameters, required values, defaults, risk, and the suggested CSV template.

## Telemetry and Reports

- `telemetry.components` — most-used PSM connection components dashboard.
- `telemetry.active-users` — Identity user activity and inactivity dashboard.
- `telemetry.account-failures` — combined CPM and PSM failure dashboard.
- `telemetry.psm-users` — PSM usage grouped by Vault user.
- `telemetry.license-capacity` — Privilege Cloud licensed, used, available, and utilization capacity.
- `compliance.posture` — compliance, password-age, safe, and account hygiene.
- `governance.entitlements` — direct/effective safe access and license data.
- `telemetry.system-health` — component health, CPM load, and PSM capacity.
- `psm.sessions` — active and historical PSM session console/export.

## Bulk Actions

- `bulk.safes.apply` — create, update, or delete safes from CSV.
- `bulk.safe-members.apply` — role-based safe-member changes from CSV.
- `bulk.safe-members.import-compatible` — add missing members with exact exported permissions.
- `bulk.accounts.apply` — create, update, or delete account metadata from CSV.
- `platform.accounts.move` — assign accounts to another target platform from CSV.
- `resolution.account-failures` — guarded bulk unlock, management enablement, and reconciliation.

Bulk Actions also contains the matching inventory, plan, queue, and exposure
exports needed to prepare changes safely.

## Safe Management

- `safe.list` — list or search visible safes.
- `safe.detail` — show complete data for one exact safe.
- `safe.create` — create one safe with conservative defaults.
- `safe.members.list` — list members and permissions for one safe.
- `safe.members.add` — add one member using a standard permission role.
- `safe.members.report` — export members and exact permissions for visible safes.
- `safe.inventory` — export safe metadata and retention settings.
- `safe.cpm.export` — export safe-to-CPM assignments with snapshot hashes.
- `safe.cpm.apply` — apply verified safe-to-CPM changes.
- `safe.migration.plan` — validate a safe-to-safe account migration.
- `safe.migration.apply` — execute a current, verified migration plan.

## Account Management

- `account.search` — search account metadata by text and optional safe.
- `account.detail` — show complete metadata for one account ID.
- `account.inventory` — export account metadata without passwords.
- `onboarding.discovered` — discovered-account review and recommendation workbench.
- `onboarding.discovered.apply` — apply explicit onboard/ignore decisions.
- `relationships.report` — report logon, reconcile, linked, and dependent relationships.
- `relationships.apply` — create or remove logon/reconcile links from CSV.
- `request.queue` — view dual-control requests and approvals.
- `request.action` — create, approve, or reject requests from CSV.
- `account.safe-transfer` — high-volume, checkpointed transfer by
  `OldSafe,NewSafe`, carrying only the current secret and supported metadata
  before verified source deletion and final reconciliation. Its opt-in
  `FullFidelity` relationship mode preserves supported direct links and
  dependent accounts with their platform-specific fields and links, while
  blocking unsupported fidelity risks. See the
  [large-run guide](HIGH-VOLUME-ACCOUNT-TRANSFER.md).

## Platform Management

- `platform.list` — list and export target platforms.
- `platform.accounts.report` — report accounts by platform.
- `platform.pmterminal.audit` — read-only search for obsolete PMTerminal references.
- `platform.drift` — export or compare platform configuration baselines.
- `platform.drift.apply` — apply guarded, hash-verified platform properties.
- `aam.exposure` — audit Application IDs, authentication methods, and reachable safes.
- `aam.exposure.apply` — add or remove reviewed Application ID authentication methods.

## Troubleshooting and Tools

- `troubleshooting.dependencies` — validate PowerShell, module, profile, and local requirements.
- `troubleshooting.connectivity` — test DNS and TCP 443 for CyberArk and supplied SIA endpoints.
- `troubleshooting.local-to-domain` — convert selected local-account metadata from CSV.
- `psm.sessions.action` — suspend, resume, or terminate PSM sessions with a reason.

Failure, health, relationship, platform-drift, application-exposure, CPM, and
PSM reports also appear here because they provide evidence for troubleshooting.

## Deployment compatibility

Commands backed by core PVWA APIs are available to ISPSS, on-premises, and
standalone profiles. FastPAS uses each profile's normalized Vault API base and
correct Authorization header rather than hard-coded cloud hosts. Two features
have narrower product dependencies and are labeled `[UNAVAILABLE]` elsewhere:

- `telemetry.active-users` requires ISPSS CyberArk Identity/SCIM.
- `telemetry.license-capacity` requires ISPSS Privilege Cloud and a Privilege Cloud administrator role.
- `aam.exposure*` uses self-hosted Application ID WebServices and is limited to
  on-premises profiles.

Other optional product APIs can still depend on installed components, PAM
version, licensing, and operator permissions; read workflows preserve usable
results and report an unavailable endpoint as a warning.
