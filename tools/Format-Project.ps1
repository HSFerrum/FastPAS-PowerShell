#requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$analyzerManifest = Get-ChildItem -LiteralPath (Join-Path $root '.test-runtime/Modules/PSScriptAnalyzer') `
    -Recurse -Filter PSScriptAnalyzer.psd1 -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending |
    Select-Object -First 1

if (-not $analyzerManifest) {
    throw 'PSScriptAnalyzer is required. Save it under .test-runtime/Modules before running this formatter.'
}

Import-Module $analyzerManifest.FullName -Force

$formatSettings = @{
    IncludeRules = @(
        'PSPlaceOpenBrace',
        'PSPlaceCloseBrace',
        'PSUseConsistentIndentation',
        'PSUseConsistentWhitespace',
        'PSUseCorrectCasing'
    )
    Rules = @{
        PSPlaceOpenBrace = @{ Enable = $true;
            OnSameLine = $true;
            NewLineAfter = $true
        }
        PSPlaceCloseBrace = @{ Enable = $true;
            NewLineAfter = $true;
            IgnoreOneLineBlock = $true
        }
        PSUseConsistentIndentation = @{ Enable = $true;
            Kind = 'space';
            IndentationSize = 4
        }
        PSUseConsistentWhitespace = @{
            Enable = $true;
            CheckInnerBrace = $true;
            CheckOpenBrace = $true
            CheckOpenParen = $true;
            CheckOperator = $true;
            CheckSeparator = $true
        }
        PSUseCorrectCasing = @{ Enable = $true }
    }
}

$files = Get-ChildItem -LiteralPath $root -Recurse -File -Include *.ps1, *.psm1 |
    Where-Object {
        $_.FullName -notlike "$(Join-Path $root '.test-runtime')*" -and
        $_.FullName -notlike "$(Join-Path $root '.devtools')*"
    }

foreach ($file in $files) {
    $content = Get-Content -LiteralPath $file.FullName -Raw
    $tokens = $null
    $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseInput($content, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors) {
        throw "Cannot format '$($file.FullName)' because it has parser errors."
    }

    # Add a line break after real statement-separator tokens. Parser tokens are
    # used so semicolons embedded in strings or regular expressions are untouched.
    foreach ($token in @($tokens | Where-Object Kind -EQ Semi | Sort-Object { $_.Extent.EndOffset } -Descending)) {
        if ($token.Extent.EndOffset -lt $content.Length -and $content[$token.Extent.EndOffset] -notin "`r", "`n") {
            $content = $content.Insert($token.Extent.EndOffset, "`n")
        }
    }

    $formatted = Invoke-Formatter -ScriptDefinition $content -Settings $formatSettings
    $formatted = $formatted -replace '(?m)[ \t]+$', ''
    Set-Content -LiteralPath $file.FullName -Value $formatted -Encoding utf8NoBOM -NoNewline
}

Write-Host "Formatted $($files.Count) PowerShell script/module file(s)." -ForegroundColor Green
