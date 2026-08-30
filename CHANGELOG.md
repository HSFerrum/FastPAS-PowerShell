# Changelog

Notable project changes are recorded here. The project follows semantic
versioning once tagged releases begin.

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
