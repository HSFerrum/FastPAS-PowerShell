# High-volume current-secret account transfer

[Home](../README.md) · [Operator guide](OPERATOR-GUIDE.md) · [CLI reference](CLI-REFERENCE.md) · [Security](../SECURITY.md)

`account.safe-transfer` is designed for reviewed migrations containing tens of
thousands of accounts. It recreates accounts; it is not a native move of Vault
history. Only the current secret and supported account metadata are copied.
Before deleting the source, FastPAS retrieves the destination secret and uses a
fixed-time hash comparison to confirm that CyberArk stored the expected value.
Password versions, audit history, recordings, requests, linked-account
relationships, and account-group membership do not move.

## Recommended 30,000-account run

1. Use a dedicated, least-privilege automation identity with list/read/retrieve,
   add, and delete rights only on the mapped safes. For ISPSS, prefer an OAuth
   service user. For on-premises or standalone, use a dedicated direct PVWA
   CyberArk/LDAP/Windows profile.
2. Create and review a copy of `templates/csv/account-safe-transfers.csv`.
   Each source safe may appear once. Do not chain a destination safe back into
   the source column.
3. Schedule a controlled migration window and pause CPM/reconcile activity for
   the source scope. FastPAS verifies what it copied, but no migration tool can
   safely preserve a password changed by another process during source deletion.
4. Run `-WhatIf`. Inspect the generated plan and correct every collision,
   missing safe, missing platform, linked account, or account-group issue.
5. Start with `Concurrency=12` and `DetailMode=Always`. Observe PVWA/Vault CPU,
   response latency, and HTTP 429/5xx rates. Reduce concurrency if service
   health degrades; increase it only after a representative pilot.
6. Keep the PowerShell process running, but use `ResumePath` if it is
   interrupted. Never edit a run manifest, checkpoint, or result CSV.
7. Treat the run as complete only when `issues.csv` is empty and the manifest
   status is `Completed`.

Preview:

```powershell
$secret = Read-Host 'OAuth client secret or PVWA password' -AsSecureString
& ./FastPAS.ps1 -Profile migration-service `
  -Command account.safe-transfer `
  -ArgumentsJson '{"CsvPath":"C:\\Work\\safe-map.csv","Concurrency":12,"DetailMode":"Always"}' `
  -Secret $secret -WhatIf
```

Apply unattended after approval:

```powershell
& ./FastPAS.ps1 -Profile migration-service `
  -Command account.safe-transfer `
  -ArgumentsJson '{"CsvPath":"C:\\Work\\safe-map.csv","Concurrency":12,"DetailMode":"Always","MaxGetRetries":5,"Reason":"Approved migration CHG001234"}' `
  -Secret $secret -NonInteractive -Force -Confirm:$false
```

Resume using the exact original mapping CSV and profile:

```powershell
& ./FastPAS.ps1 -Profile migration-service `
  -Command account.safe-transfer `
  -ArgumentsJson '{"CsvPath":"C:\\Work\\safe-map.csv","Concurrency":12,"ResumePath":"C:\\Work\\output\\account_safe_transfer_20260829_200000_000"}' `
  -Secret $secret -NonInteractive -Force -Confirm:$false
```

## Execution and token model

FastPAS inventories each unique source and destination safe once before work,
then distributes accounts round-robin across bounded workers. Each parallel
worker owns a separate authenticated session and refreshes its token before
expiry. A 30,000-account run should not depend on one token lasting for the
entire migration. Federated, interactive, and RADIUS sessions cannot be safely
renewed without a person or a fresh OTP, so they are limited to
`Concurrency=1`.

The default `DetailMode=Always` reads authoritative account details before
retrieval. `Inventory` removes that detail request and can be faster, but it
trusts the account-list response to contain all metadata needed to detect
relationships. Use it only after validating that behavior for the exact
CyberArk version and deployment.

Read-only GET requests retry transient 429, 502, 503, 504, and timeout failures
with exponential backoff and jitter. Create, retrieve, and delete requests are
never blindly replayed. If a create response is ambiguous, FastPAS retains the
source and reconciles both safes.

## Run artifacts

Every run has its own directory:

- `manifest.json` records the input SHA-256, profile, deployment, attempt,
  settings, counts, duration, and final status.
- `attempt-NNN-plan.csv` is the secret-free account plan.
- `attempt-NNN-worker-NNN.csv` is an append-only checkpoint written after each
  account attempt.
- `all-attempts.csv` preserves attempt history across resumes.
- `results.csv` contains the latest reconciled result for each account.
- `issues.csv` contains only rows requiring attention, including the exact
  issue and recommended action.

No artifact contains current secrets, runtime passwords, OAuth secrets, or
tokens. Generated files still contain sensitive account and safe metadata and
must be protected accordingly.

## Important result statuses

| Status | Meaning and action |
|---|---|
| `Reconciled` | Source absent and destination present. No action required. |
| `RetrieveFailed` | Current-secret retrieval failed. Correct permissions/reason policy and retry. |
| `CreateRejected` | Destination rejected the create before a successful response. Correct the reported problem and retry. |
| `CreateUncertain` | The create outcome is ambiguous. Inspect both safes before any retry. |
| `DestinationSecretMismatch` | Destination retrieval did not match the source value. The source remains intact; correct the destination. |
| `DuplicateNeedsCleanup` | Both accounts exist. Verify the destination, then remove the source manually if appropriate. |
| `SourceRetainedDestinationMissing` | Source is safe; destination is absent. Correct the create issue and retry. |
| `ReconciliationUnavailable` | Final inventories failed. Inspect both safes; do not automatically retry. |
| `CriticalMissing` | Neither account is visible. Escalate immediately and inspect Vault audit/recovery. |
| `LinkedAccountBlocked` / `AccountGroupBlocked` | Migration would discard a relationship. Migrate the relationship explicitly first. |

The tool intentionally favors a retained duplicate over an unverified deletion.
