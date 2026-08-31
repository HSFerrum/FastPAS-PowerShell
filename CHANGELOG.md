# Changelog

## Unreleased

- Added first-class Windows PowerShell 5.1 support while retaining PowerShell
  7+, removed the PS7 relaunch/install requirement, and made the double-click
  launcher fall back automatically to the built-in Windows runtime.
- Added compatibility handling for JSON, HTTP errors, TLS 1.2, certificate
  bypass, UTF-8 artifacts, and fixed-time secret comparison, plus a dedicated
  Windows PowerShell 5.1 CI job. High-volume parallel transfer safely falls
  back to one worker on 5.1.
- Fixed Identity MFA sessions that continued polling after approval by honoring
  the CyberArk Identity pod redirect, including `TenantId` in every challenge
  request, and stopping immediately on completed or rejected states.
- Federated browser authentication now supports both PIN continuation and
  no-PIN `OobAuthStatus` completion flows.
- Added an ISPSS Privilege Cloud license-capacity dashboard with licensed,
  used, available, utilization, and threshold status data in CSV, HTML, and
  raw JSON artifacts.
- Added opt-in `FullFidelity` safe-transfer mode for discovery, recreation, and
  read-back verification of supported Logon/Reconcile account links.
- Added CPM operational-state attestation and pre-delete source
  password-version/current-secret consistency checks.
- Full-fidelity transfers now recreate and verify dependent accounts such as
  Windows Services, Scheduled Tasks, and IIS application pools, including
  their complete platform-property bags, management settings, and links.
- Full-fidelity transfers fail closed for account groups, unresolved dependent
  shapes, unresolved relationships, and linked targets in the same run.

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
