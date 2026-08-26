# Security model

FastPAS PowerShell performs privileged administration. Use a least-privileged
profile and validate workflows against a non-production tenant first.

- Passwords and OAuth client secrets are never persisted. They are accepted as
  `SecureString` values only for the current authentication attempt and are
  requested again on the next run.
- Loading a legacy schema-v1 profile removes its old FastPAS entry from Windows
  Credential Manager and rewrites the profile as metadata-only schema v2.
- Federated eIDP passwords are never requested, intercepted, or stored; the
  system browser owns the external IdP session, MFA, and conditional access.
- Browser redirects are accepted only when CyberArk returns an absolute,
  non-local HTTPS URL without embedded credentials.
- Platform tokens remain in memory and are cleared on disconnect.
- TLS validation uses the PowerShell/.NET defaults; there is no certificate
  bypass option.
- Authorization headers and known secret fields are redacted from JSONL audit
  events.
- Interactive mutations require an exact `APPLY`; unattended mutations require
  `-Force -Confirm:$false`; all write commands support `-WhatIf`.
- Remediation is limited to 500 unique account IDs and validates IDs before
  constructing API paths.
- CPM resolution is not reported as successful until automatic management is
  enabled and CyberArk returns a successful management status.
- Report files may expose safe, account, user, address, and platform metadata.
  Protect and remove them according to local retention policy.
- Bulk CSV files never accept passwords. Every bulk mutation has a row limit,
  supports `-WhatIf`, requires the normal write confirmation, and produces a
  per-row result report. Review delete rows especially carefully.
- Safe CPM imports never trust stale exported safe bodies. They re-read each
  safe, compare the exported snapshot/hash, build the update from live values,
  verify the resulting assignment, and retain failures in a resumable CSV.
- API Runner-compatible permission imports reject ambiguous boolean strings and
  skip existing members instead of silently replacing their permissions.
- Connectivity diagnostics probe only DNS and TCP/443 for explicit or
  tenant-derived hosts. They do not send authentication data, scan port ranges,
  or guess SIA regional endpoints.

Do not enable PowerShell transcription around FastPAS unless the transcript
destination and access controls are approved for authentication-related data.
Never commit generated output or local profile exports.
