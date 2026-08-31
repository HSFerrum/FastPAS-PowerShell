[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Alias('Profile', 'ProfileName')]
    [string]$TargetProfile,
    [string]$Command,
    [string]$ArgumentsJson,
    [string]$OutputPath = (Join-Path $PWD 'output'),
    [Security.SecureString]$Secret,
    [Security.SecureString]$OneTimePassword,
    [switch]$NonInteractive,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'FastPAS.PowerShell.psd1') -Force
. (Join-Path $PSScriptRoot 'ui/Show-FastPASProfileDialog.ps1')

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
    $parsed = if ($PSVersionTable.PSVersion.Major -ge 6) { $Json | ConvertFrom-Json -Depth 20 } else { $Json | ConvertFrom-Json }
    if ($null -eq $parsed -or $parsed -is [string] -or $parsed -is [ValueType] -or $parsed -is [Collections.IEnumerable]) {
        throw 'ArgumentsJson must contain a JSON object.'
    }
    $arguments = @{}
    foreach ($property in $parsed.PSObject.Properties) { $arguments[$property.Name] = $property.Value }
    return $arguments
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
    do { $name = Read-Host 'Profile name' }until(-not [string]::IsNullOrWhiteSpace($name))
    $deployment = (Read-FastPASMenuChoice -Prompt 'Choose deployment type' -Items @(
            [pscustomobject]@{DisplayName = 'ISPSS / Privilege Cloud Shared Services'; Value = 'ispss' },
            [pscustomobject]@{DisplayName = 'On-premises PAM Self-Hosted'; Value = 'onprem' },
            [pscustomobject]@{DisplayName = 'Standalone / legacy Privilege Cloud'; Value = 'standalone' }
        )).Value
    if ($deployment -eq 'ispss') {
        do { $subdomain = Read-Host 'ISPSS tenant subdomain' }until(-not [string]::IsNullOrWhiteSpace($subdomain))
        $identityHost = $null
        $vaultApiBaseUrl = $null
        try {
            $tenantResolution = Resolve-FastPASTenant -Subdomain $subdomain
            $identityHost = $tenantResolution.IdentityHost
            $vaultApiBaseUrl = $tenantResolution.VaultApiBaseUrl
            Write-Host "Discovered Identity host: $identityHost" -ForegroundColor Cyan
            Write-Host "Privilege Cloud API: $vaultApiBaseUrl" -ForegroundColor Cyan
        }
        catch {
            Write-Warning "Automatic tenant discovery failed: $($_.Exception.Message)"
            do { $identityHost = Read-Host 'CyberArk Identity host (for example AAT1234.id.cyberark.cloud)' }until(-not [string]::IsNullOrWhiteSpace($identityHost))
            do { $vaultApiBaseUrl = Read-Host 'Privilege Cloud API URL (ending in /PasswordVault/API)' }until(-not [string]::IsNullOrWhiteSpace($vaultApiBaseUrl))
        }
        $authType = (Read-FastPASMenuChoice -Prompt 'Choose ISPSS authentication' -Items @(
                [pscustomobject]@{DisplayName = 'OAuth service user'; Value = 'oauth' },
                [pscustomobject]@{DisplayName = 'Identity user with CyberArk MFA'; Value = 'interactive' },
                [pscustomobject]@{DisplayName = 'External IdP (Entra, Okta, Ping, etc.)'; Value = 'federated' }
            )).Value
        if ($authType -eq 'oauth') {
            do { $applicationId = Read-Host 'OAuth application ID' }until(-not [string]::IsNullOrWhiteSpace($applicationId))
            do { $clientId = Read-Host 'OAuth client ID / service-user login name' }until(-not [string]::IsNullOrWhiteSpace($clientId))
            return New-FastPASProfile -Name $name -DeploymentType ispss -Subdomain $subdomain -IdentityHost $identityHost -VaultApiBaseUrl $vaultApiBaseUrl -AuthType oauth -ApplicationId $applicationId -ClientId $clientId -SetActive
        }
        do { $username = Read-Host 'Identity username' }until(-not [string]::IsNullOrWhiteSpace($username))
        return New-FastPASProfile -Name $name -DeploymentType ispss -Subdomain $subdomain -IdentityHost $identityHost -VaultApiBaseUrl $vaultApiBaseUrl -AuthType $authType -Username $username -SetActive
    }

    $urlPrompt = if ($deployment -eq 'onprem') { 'PVWA URL (for example https://pvwa.example.com/PasswordVault)' }else { 'Privilege Cloud PVWA URL (for example https://tenant.privilegecloud.cyberark.cloud/PasswordVault)' }
    do { $pvwaUrl = Read-Host $urlPrompt }until(-not [string]::IsNullOrWhiteSpace($pvwaUrl))
    $authType = (Read-FastPASMenuChoice -Prompt 'Choose PVWA authentication' -Items @(
            [pscustomobject]@{DisplayName = 'CyberArk Vault user'; Value = 'cyberark' },
            [pscustomobject]@{DisplayName = 'LDAP user'; Value = 'ldap' },
            [pscustomobject]@{DisplayName = 'RADIUS user (password + runtime OTP)'; Value = 'radius' },
            [pscustomobject]@{DisplayName = 'Windows authentication'; Value = 'windows' }
        )).Value
    do { $username = Read-Host 'Vault username' }until(-not [string]::IsNullOrWhiteSpace($username))
    $profileParameters = @{Name = $name; DeploymentType = $deployment; PVWAUrl = $pvwaUrl; AuthType = $authType; Username = $username; SetActive = $true }
    if ($authType -eq 'radius') { $profileParameters.RadiusOtpDelimiter = Read-Host 'Password/OTP delimiter [,]' ; if ($profileParameters.RadiusOtpDelimiter -eq '') { $profileParameters.RadiusOtpDelimiter = ',' } }
    if ($deployment -eq 'onprem' -and (Read-Host 'Skip TLS certificate validation? Type YES only for an approved internal/self-signed PVWA certificate') -ceq 'YES') { $profileParameters.SkipCertificateCheck = $true }
    return New-FastPASProfile @profileParameters
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
            $profileItems = @($profiles | ForEach-Object {
                    $deployment = if ($_.DeploymentType) { $_.DeploymentType }else { 'ispss' }
                    [pscustomobject]@{DisplayName = "$($_.Name) [$deployment/$($_.AuthType)]";
                        Value = $_
                    } })
            $runningOnWindows = if (Get-Variable IsWindows -ErrorAction SilentlyContinue) { $IsWindows } else { $env:OS -eq 'Windows_NT' }
            if ($runningOnWindows) {
                $profileItems += [pscustomobject]@{DisplayName = 'Create a new profile (GUI)'; Value = '__new_gui__' }
            }
            $profileItems += [pscustomobject]@{DisplayName = 'Create a new profile (text wizard)';
                Value = '__new_text__'
            }
            $profileItems += [pscustomobject]@{DisplayName = 'Previous page / Exit';
                Value = '__exit__'
            }
            Write-Host "`nFastPAS Profiles" -ForegroundColor Cyan
            $selection = Read-FastPASMenuChoice -Prompt 'Choose a profile' -Items $profileItems
            if ($selection.Value -eq '__exit__') { return }
            if ($selection.Value -eq '__new_gui__') {
                $created = Show-FastPASProfileDialog
                if (-not $created) { continue }
                $created
            }
            elseif ($selection.Value -eq '__new_text__') { New-FastPASInteractiveProfile }else { $selection.Value }
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
                                $deployment = if ($context.DeploymentType) { $context.DeploymentType }else { 'ispss' }
                                $available = $deployment -in @($_.Deployments)
                                $prefix = if (-not $available) { '[UNAVAILABLE]' }elseif ($_.RiskLevel -eq 'Write') { '[CHANGE]' } else { '[READ]' }
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
    $context = Connect-FastPAS -ProfileId $selectedProfile.Id -Secret $Secret -OneTimePassword $OneTimePassword -NonInteractive:$NonInteractive
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
