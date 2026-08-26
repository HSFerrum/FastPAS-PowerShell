# Contributing

Use PowerShell 7 and keep runtime code free of PowerShell Gallery dependencies.
Before submitting changes, run:

```powershell
pwsh ./tools/Format-Project.ps1
pwsh ./tools/Test-Project.ps1
pwsh ./tools/Test-ExpandedOperations.ps1
```

To add a workflow:

1. Add a descriptor to `config/commands.psd1`. Give it one primary category and
   only the additional sections where an operator would reasonably look for it.
2. Add its plain-language description, required inputs, safe defaults, and CSV
   template name to `config/operator-help.psd1`.
3. Add a focused script beneath `Commands/<area>` using the established
   parameter contract and returning `New-FastPASResult`.
4. Use `Invoke-FastPASApiRequest` and `Get-FastPASPagedItems`; never construct
   authorization headers in feature scripts.
5. Use named parameters for shared helpers, validate every external input, and
   use `ShouldProcess` for every mutation.
6. Return a summary, structured data, warnings, artifacts, and sanitized audit
   events through `New-FastPASResult`.
7. Add mocked tests for success, service errors, empty results, and `-WhatIf`.

Keep fixtures synthetic and never add tenant exports, tokens, passwords, client
secrets, or real hostnames to the repository.
