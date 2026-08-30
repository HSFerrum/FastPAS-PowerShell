# Changelog

Notable project changes are recorded here. The project follows semantic
versioning once tagged releases begin.

## 0.4.0

- Rebuilt `account.safe-transfer` for migrations of up to tens of thousands of
  accounts with bounded parallel worker sessions and proactive token renewal.
- Added cached source/destination inventories, destination collision checks,
  append-only per-worker checkpoints, immutable input hashes, and safe resume.
- Added conservative handling for ambiguous create/delete responses: write
  requests are never blindly retried and the source is retained unless the
  destination was positively verified.
- Added final source/destination reconciliation plus `results.csv`,
  `issues.csv`, `all-attempts.csv`, and a run manifest with no secret content.
- Added destination-secret retrieval and fixed-time verification before any
  source deletion.
- Added high-volume transfer safety and recovery tests.

## 0.3.0

- Added ISPSS, on-premises, and standalone deployment-aware profiles.
- Added direct PVWA CyberArk, LDAP, RADIUS, and Windows authentication with
  normalized on-prem/standalone API URLs and raw PVWA authorization tokens.
- Added a Windows popup profile builder plus deployment-aware text wizard.
- Added catalog compatibility checks and on-prem-aware diagnostics.
- Added guarded `OldSafe,NewSafe` current-secret-only account transfers with
  destination verification and metadata-only checkpoints.
- Expanded parser/Pester coverage to 32 tests and 46 commands.

## 0.2.0

- Added a six-section operator menu with read/change grouping and backward navigation.
- Added metadata-only multi-profile login selection and `-Profile` targeting.
- Added native, OAuth, and federated/eIDP authentication with system-browser challenges.
- Ported the original FastPAS telemetry dashboards and API Runner workflows.
- Added 45 cataloged commands covering reporting, bulk operations, safes,
  accounts, platforms, troubleshooting, governance, requests, PSM, AAM, and migration.
- Added guarded CSV workflows, snapshot conflicts, `-WhatIf`, explicit apply
  confirmation, structured results, HTML/CSV reports, and redacted audit logs.
- Added operator, CLI, command, architecture, security, support, and contributor documentation.
