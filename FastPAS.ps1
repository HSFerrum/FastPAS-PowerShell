[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Alias('Profile', 'ProfileName')]
    [string]$TargetProfile,
    [string]$Command,
    [string]$ArgumentsJson,
    [string]$OutputPath = (Join-Path $PWD 'output'),
    [Security.SecureString]$Secret,
    [switch]$NonInteractive,
    [switch]$Force
)

# Windows still associates .ps1 files with Windows PowerShell 5.1 on many
# systems. Keep this small bootstrap compatible with 5.1, then run the actual
# application in PowerShell 7 where the module and feature scripts are supported.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    $powerShell7 = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    if (-not $powerShell7) {
        $powerShell7Candidates = @(
            (Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'),
            (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\pwsh.exe'),
            (Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell\pwsh.exe')
        )
        $powerShell7Path = $powerShell7Candidates |
            Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } |
            Select-Object -First 1
        if ($powerShell7Path) { $powerShell7 = Get-Item -LiteralPath $powerShell7Path }
    }
    if (-not $powerShell7) {
        throw 'FastPAS requires PowerShell 7 or newer. Install it from https://aka.ms/powershell-release?tag=stable and run: pwsh ./FastPAS.ps1'
    }

    $relaunchArguments = @('-NoLogo', '-NoProfile', '-File', $PSCommandPath)
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Key -eq 'Secret') {
            throw 'A runtime SecureString cannot be transferred from Windows PowerShell 5.1. Start pwsh first, then run FastPAS and enter the secret again.'
        }
        if ($entry.Value -is [System.Management.Automation.SwitchParameter]) {
            if ($entry.Value.IsPresent) { $relaunchArguments += "-$($entry.Key)" }
        }
        elseif ($entry.Value -is [bool]) {
            $relaunchArguments += "-$($entry.Key):`$$($entry.Value.ToString().ToLowerInvariant())"
        }
        else {
            $relaunchArguments += "-$($entry.Key)"
            $relaunchArguments += [string]$entry.Value
        }
    }

    $powerShell7Executable = if ($powerShell7.Source) { $powerShell7.Source } else { $powerShell7.FullName }
    & $powerShell7Executable @relaunchArguments
    exit $LASTEXITCODE
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'FastPAS.PowerShell.psd1') -Force

function Read-FastPASMenuChoice {
    param([Parameter(Mandatory)][string]$Prompt, [Parameter(Mandatory)][object[]]$Items)
    for ($index = 0;
        $index -lt $Items.Count;
        $index++) {
        Write-Host ('{0,2}. {1}' -f ($index + 1), $Items[$index].DisplayName)
    }
    do {
        $answer = Read-Host $Prompt
        $number = 0
        $valid = [int]::TryParse($answer, [ref]$number) -and $number -ge 1 -and $number -le $Items.Count
    } until ($valid)
    return $Items[$number - 1]
}

function ConvertFrom-FastPASArgumentsJson {
    param([string]$Json)
    if ([string]::IsNullOrWhiteSpace($Json)) { return @{} }
    $parsed = $Json | ConvertFrom-Json -AsHashtable -Depth 20
    if ($parsed -isnot [hashtable]) { throw 'ArgumentsJson must contain a JSON object.' }
    return $parsed
}

function Get-FastPASSelectedProfile {
    param([Parameter(Mandatory)][string]$Selector)
    $selected = Get-FastPASProfile -Name $Selector
    if (-not $selected) { $selected = Get-FastPASProfile -Id $Selector }
    return $selected
}

function Read-FastPASCommandArguments {
    param([Parameter(Mandatory)]$Descriptor)

    $arguments = @{}
    if ($Descriptor.Template) {
        $templatePath = Join-Path $PSScriptRoot "templates/csv/$($Descriptor.Template)"
        Write-Host "Suggested template: $templatePath" -ForegroundColor Cyan
        Write-Host 'Copy the template or use the latest export produced by the matching report/plan command.' -ForegroundColor DarkGray
    }

    foreach ($name in @($Descriptor.Parameters)) {
        $isInputPath = $name -in @('CsvPath', 'BaselinePath', 'EndpointCsvPath')
        $helpText = [string]$Descriptor.ParameterHelp[$name]
        if ($helpText) { Write-Host "`n$name - $helpText" -ForegroundColor DarkGray }

        $required = $Descriptor.RequiredParameters -contains $name
        $hasDefault = $Descriptor.Defaults.ContainsKey($name)
        $default = if ($hasDefault) { $Descriptor.Defaults[$name] } else { $null }
        $prompt = if ($hasDefault) {
            "$name [$default]"
        }
        elseif ($required) {
            "$name (required)"
        }
        else {
            "$name (optional; press Enter to skip)"
        }

        do {
            $pathWasInvalid = $false
            $value = Read-Host $prompt
            if ([string]::IsNullOrWhiteSpace($value) -and $hasDefault) { $value = $default }
            if ($isInputPath -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                $value = [Environment]::ExpandEnvironmentVariables(([string]$value).Trim().Trim('"'))
                if (-not (Test-Path -LiteralPath $value -PathType Leaf)) {
                    Write-Warning "The file was not found: $value"
                    $value = $null
                    $pathWasInvalid = $true
                }
            }
            if ($required -and [string]::IsNullOrWhiteSpace([string]$value)) {
                Write-Warning "$name is required. Enter a value to continue."
            }
        } while (($required -and [string]::IsNullOrWhiteSpace([string]$value)) -or $pathWasInvalid)

        if ([string]::IsNullOrWhiteSpace([string]$value)) { continue }
        if ($name -eq 'AccountIds') {
            $value = @([string]$value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }
        $arguments[$name] = $value
    }

    return $arguments
}

function Show-FastPASCommandIntroduction {
    param([Parameter(Mandatory)]$Descriptor)

    $riskLabel = if ($Descriptor.RiskLevel -eq 'Write') { 'CHANGE - confirmation required' } else { 'READ ONLY' }
    $riskColor = if ($Descriptor.RiskLevel -eq 'Write') { 'Yellow' } else { 'Green' }
    Write-Host "`n$($Descriptor.DisplayName)" -ForegroundColor Cyan
    Write-Host $riskLabel -ForegroundColor $riskColor
    Write-Host $Descriptor.Description
    Write-Host "Command ID: $($Descriptor.Id)" -ForegroundColor DarkGray
}

function Show-FastPASCommandResult {
    param([Parameter(Mandatory)]$Result)

    Write-Host "`n$($Result.Summary)" -ForegroundColor $(if ($Result.Success) { 'Green' }else { 'Red' })
    $rows = @($Result.Data)
    if ($rows.Count) {
        $previewLimit = 50
        $rows | Select-Object -First $previewLimit | Format-Table -Wrap -AutoSize | Out-Host
        if ($rows.Count -gt $previewLimit) {
            Write-Host "Showing the first $previewLimit of $($rows.Count) rows. Use the exported artifact for the complete result." -ForegroundColor Yellow
        }
    }
    foreach ($artifact in @($Result.Artifacts)) { Write-Host "Created: $artifact" -ForegroundColor Cyan }
    foreach ($warning in @($Result.Warnings)) { Write-Warning $warning }
}

function New-FastPASInteractiveProfile {
    Write-Host 'Create a FastPAS profile.' -ForegroundColor Yellow
    $name = Read-Host 'Profile name'
    $subdomain = Read-Host 'Tenant subdomain'
    try {
        $tenantResolution = Resolve-FastPASTenant -Subdomain $subdomain
        $identityHost = $tenantResolution.IdentityHost
        Write-Host "Discovered Identity host: $identityHost" -ForegroundColor Cyan
    }
    catch {
        Write-Warning "Identity host discovery failed: $($_.Exception.Message)"
        $identityHost = Read-Host 'Identity host (hostname only)'
        if ([string]::IsNullOrWhiteSpace($identityHost)) { throw 'Identity host is required when automatic discovery fails.' }
    }
    $authChoice = Read-Host 'Authentication type (oauth/interactive/federated) [oauth]'
    if ([string]::IsNullOrWhiteSpace($authChoice)) { $authChoice = 'oauth' }
    if ($authChoice -in @('federated', 'eidp')) {
        $username = Read-Host 'Federated username'
        return New-FastPASProfile -Name $name -Subdomain $subdomain -IdentityHost $identityHost -AuthType federated -Username $username -SetActive
    }
    if ($authChoice -eq 'interactive') {
        $username = Read-Host 'Username'
        return New-FastPASProfile -Name $name -Subdomain $subdomain -IdentityHost $identityHost -AuthType interactive -Username $username -SetActive
    }
    $applicationId = Read-Host 'OAuth application ID'
    $clientId = Read-Host 'OAuth client ID / login name'
    return New-FastPASProfile -Name $name -Subdomain $subdomain -IdentityHost $identityHost -AuthType oauth -ApplicationId $applicationId -ClientId $clientId -SetActive
}

function Start-FastPASInteractive {
    $fixedProfile = $null
    if ($TargetProfile) {
        $fixedProfile = Get-FastPASSelectedProfile -Selector $TargetProfile
        if (-not $fixedProfile) { throw "Profile '$TargetProfile' was not found." }
    }
    while ($true) {
        $selectedProfile = if ($fixedProfile) { $fixedProfile }else {
            $profiles = @(Get-FastPASProfile)
            $profileItems = @($profiles | ForEach-Object { [pscustomobject]@{DisplayName = "$($_.Name) [$($_.AuthType)]";
                        Value = $_
                    } })
            $profileItems += [pscustomobject]@{DisplayName = 'Create a new profile';
                Value = '__new__'
            }
            $profileItems += [pscustomobject]@{DisplayName = 'Previous page / Exit';
                Value = '__exit__'
            }
            Write-Host "`nFastPAS Profiles" -ForegroundColor Cyan
            $selection = Read-FastPASMenuChoice -Prompt 'Choose a profile' -Items $profileItems
            if ($selection.Value -eq '__exit__') { return }
            if ($selection.Value -eq '__new__') { New-FastPASInteractiveProfile }else { $selection.Value }
        }
        $context = Connect-FastPAS -ProfileId $selectedProfile.Id
        try {
            $returnToProfiles = $false
            while ($true) {
                Write-Host "`nFastPAS PowerShell - $($selectedProfile.Name)" -ForegroundColor Cyan
                $commands = @(Get-FastPASCommand);
                $sections = @(Get-FastPASMenuSection)
                $sectionItems = @($sections | ForEach-Object { [pscustomobject]@{DisplayName = $_;
                            Value = $_
                        } })
                $sectionItems += [pscustomobject]@{DisplayName = $(if ($fixedProfile) { 'Previous page / Exit' }else { 'Previous page (profiles)' });
                    Value = '__previous__'
                }
                $sectionItems += [pscustomobject]@{DisplayName = 'Exit';
                    Value = '__exit__'
                }
                $selectedSection = Read-FastPASMenuChoice -Prompt 'Choose a section' -Items $sectionItems
                if ($selectedSection.Value -eq '__exit__') { return }
                if ($selectedSection.Value -eq '__previous__') {
                    $returnToProfiles = $true;
                    break
                }
                $sectionCommands = @($commands | Where-Object { $_.Sections -contains $selectedSection.Value })
                while ($true) {
                    $groupNames = @($sectionCommands.MenuGroup | Sort-Object -Unique)
                    $groupItems = @($groupNames | ForEach-Object { [pscustomobject]@{DisplayName = $_;
                                Value = $_
                            } })
                    $groupItems += [pscustomobject]@{DisplayName = 'Previous page';
                        Value = '__previous__'
                    }
                    Write-Host "`n$($selectedSection.Value)" -ForegroundColor Yellow
                    $selectedGroup = Read-FastPASMenuChoice -Prompt 'Choose an option type' -Items $groupItems
                    if ($selectedGroup.Value -eq '__previous__') { break }

                    while ($true) {
                        $commandsInGroup = @($sectionCommands |
                                Where-Object MenuGroup -EQ $selectedGroup.Value |
                                Sort-Object DisplayName)
                        $commandItems = @($commandsInGroup | ForEach-Object {
                                $prefix = if ($_.RiskLevel -eq 'Write') { '[CHANGE]' } else { '[READ]' }
                                [pscustomobject]@{DisplayName = "$prefix $($_.DisplayName)";
                                    Value = $_
                                }
                            })
                        $commandItems += [pscustomobject]@{DisplayName = 'Previous page';
                            Value = '__previous__'
                        }

                        Write-Host "`n$($selectedSection.Value) > $($selectedGroup.Value)" -ForegroundColor Yellow
                        $selected = Read-FastPASMenuChoice -Prompt 'Choose an action' -Items $commandItems
                        if ($selected.Value -eq '__previous__') { break }

                        $descriptor = $selected.Value
                        Show-FastPASCommandIntroduction -Descriptor $descriptor
                        $arguments = Read-FastPASCommandArguments -Descriptor $descriptor
                        try {
                            $result = Invoke-FastPASCommand -Id $descriptor.Id -Context $context -Arguments $arguments -OutputPath $OutputPath
                            Show-FastPASCommandResult -Result $result
                        }
                        catch {
                            Write-Host "`nCommand failed: $($_.Exception.Message)" -ForegroundColor Red
                            Write-Host 'No additional action was taken after this error. Review the message, permissions, CSV, or tenant capability and try again.' -ForegroundColor Yellow
                        }
                        $null = Read-Host 'Press Enter to continue'
                    }
                }
            }
            if ($fixedProfile -or -not $returnToProfiles) { return }
        }
        finally { Disconnect-FastPAS -Context $context }
    }
}

if (-not [string]::IsNullOrWhiteSpace($Command)) {
    $selectedProfile = if ($TargetProfile) { Get-FastPASSelectedProfile -Selector $TargetProfile } else { $null }
    if (-not $selectedProfile) { throw 'Specify an existing profile with -Profile for command mode.' }
    $context = Connect-FastPAS -ProfileId $selectedProfile.Id -Secret $Secret -NonInteractive:$NonInteractive
    try {
        $invoke = @{
            Id = $Command;
            Context = $context;
            Arguments = (ConvertFrom-FastPASArgumentsJson $ArgumentsJson)
            OutputPath = $OutputPath;
            NonInteractive = $NonInteractive;
            Force = $Force
            WhatIf = $WhatIfPreference;
            Confirm = $false
        }
        $result = Invoke-FastPASCommand @invoke
        $result
        if (-not $result.Success) { exit 1 }
    }
    finally { Disconnect-FastPAS -Context $context }
}
elseif ($NonInteractive) {
    throw '-NonInteractive requires -Command and -Profile.'
}
else {
    Start-FastPASInteractive
}
