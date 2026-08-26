# Expanded FastPAS operations

The expanded suite turns the ten prioritized ideas into seventeen commands. Each
environment can expose a different subset of Privilege Cloud or self-hosted EPV
APIs. Read commands therefore preserve partial results and report unavailable
endpoints as warnings. A warning is not treated as proof that the underlying
CyberArk component is unhealthy.

## Safe operating model

- Start with the report, workbench, baseline, queue, or plan command.
- Use the generated CSV/JSON rather than reconstructing object identifiers.
- Preview every matching action command with `-WhatIf`.
- Interactive writes require `APPLY`. Unattended writes require `-Force` and
  `-Confirm:$false` in addition to the absence of `-WhatIf`.
- FastPAS stores no passwords in profiles, templates, checkpoints, or reports.
- Platform changes require a matching configuration hash. Safe migrations
  require a matching account hash and a destination duplicate check.
- PSM and approval actions require a reason and are included in the redacted
  operational audit log.

## API availability

Account, safe, platform, recording, and membership APIs form the core path.
Discovered accounts, component monitoring, live PSM sessions, applications,
licenses, and dual-control requests may depend on product edition, tenant
generation, feature enablement, and the authenticated user's authorization.
FastPAS tries known current route variants only where they represent the same
operation; it does not silently substitute a different mutation.

## Workflows

### Compliance and governance

`compliance.posture` correlates accounts, safes, safe owners, password-management
signals, duplicates, broad permissions, and Vault users. `governance.entitlements`
exports direct and group/role safe assignments. Directory-group nesting is
labeled rather than guessed when directory expansion APIs are unavailable.

### Onboarding and relationships

`onboarding.discovered` produces an editable workbench with duplicate and
dependency signals. `onboarding.discovered.apply` processes only explicit
Onboard or Ignore decisions. `relationships.report` inventories relationships;
`relationships.apply` limits modification to documented Logon and Reconcile
link types.

### Health, platforms, and sessions

`telemetry.system-health` combines component endpoints with CPM account workload
and live PSM capacity. `platform.drift` captures complete JSON and hashes it;
`platform.drift.apply` permits one guarded top-level property per row. PSM
session reporting is read-only, while active-session actions are isolated in a
separate high-impact command.

### Applications, requests, and migration

`aam.exposure` correlates Application IDs, authentication methods, and safe
membership where application APIs are exposed. Request commands separate queue
review from create/approve/reject. Safe migration is a two-step process: create
a verified plan, then apply that exact plan. It uses the account metadata move
API and never retrieves account content.
