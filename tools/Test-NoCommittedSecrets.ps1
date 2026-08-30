#requires -Version 7.0
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$excludedDirectories = @('.git', '.test-runtime', 'output', 'reports', 'logs')
$extensions = @('.ps1', '.psm1', '.psd1', '.md', '.json', '.yml', '.yaml', '.csv', '.cmd')
$findings = [Collections.Generic.List[string]]::new()
$privateKeyPattern = '-----BEGIN ' + '(?:RSA |EC |OPENSSH )?PRIVATE KEY-----'

$files = @(Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object {
        $_.Extension -in $extensions -and
        -not @($_.FullName.Substring($root.Length).TrimStart('\', '/') -split '[\\/]' | Where-Object { $_ -in $excludedDirectories }).Count
    })
foreach ($file in $files) {
    if ($file.Name -ieq 'profiles.json' -or $file.Name -match '(?i)^\.env(?:\.|$)') {
        $findings.Add("Sensitive configuration filename is present: $($file.FullName)")
        continue
    }
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $file.FullName) {
        $lineNumber++
        if ($line -match $privateKeyPattern) {
            $findings.Add("$($file.FullName):$lineNumber contains a private-key header.")
            continue
        }
        if ($line -match '(?i)(?:password|client[_-]?secret|access[_-]?token|authorization)\s*[:=]\s*["''][^"'']{12,}["'']' -and
            $line -notmatch '\$' -and
            $line -notmatch '(?i)synthetic|example|invalid|redacted|placeholder|your[-_ ]') {
            $findings.Add("$($file.FullName):$lineNumber contains a credential-like literal.")
        }
        if ($line -match '(?i)Bearer\s+eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}') {
            $findings.Add("$($file.FullName):$lineNumber contains a JWT-like bearer token.")
        }
    }
}
if ($findings.Count) {
    $findings | ForEach-Object { Write-Error $_ }
    throw 'Potential committed credentials were found. Replace them with documented placeholders before publishing.'
}
Write-Host "Credential scan passed for $($files.Count) repository files." -ForegroundColor Green
