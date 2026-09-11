#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$testRoot = Join-Path ([IO.Path]::GetTempPath()) "fastpas-catalog-$([guid]::NewGuid().ToString('N'))"
$previousDataRoot = $env:FASTPAS_DATA_ROOT

try {
    $env:FASTPAS_DATA_ROOT = Join-Path $testRoot 'data'
    $outputRoot = Join-Path $testRoot 'output'
    $fixtureRoot = Join-Path $testRoot 'fixtures'
    $null = New-Item -ItemType Directory -Path $outputRoot, $fixtureRoot -Force
    Import-Module (Join-Path $root 'FastPAS.PowerShell.psd1') -Force

    & (Get-Module FastPAS.PowerShell) {
        param($OutputRoot, $FixtureRoot)

        $originalPaged = ${function:Get-FastPASPagedItems}
        $originalOptional = ${function:Get-FastPASOptionalItems}
        $originalAccount = ${function:Resolve-FastPASAccount}
        $originalSafe = ${function:Resolve-FastPASSafe}
        $originalApi = ${function:Invoke-FastPASApiRequest}
        $originalRaw = ${function:Invoke-FastPASRawRequest}
        $originalHostAddress = ${function:Resolve-FastPASHostAddress}
        $originalTcpPort = ${function:Test-FastPASTcpPort}
        $tested = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

        $global:FastPASCatalogSmokeAccount = [pscustomobject]@{
            id = 'account-1'; name = 'root'; safeName = 'Old'; userName = 'root'; address = 'server01'
            platformId = 'Unix'; locked = $false
            secretManagement = [pscustomobject]@{automaticManagementEnabled = $true; status = 'success'; managingCPM = 'PasswordManager'}
        }
        $global:FastPASCatalogSmokeSafe = [pscustomobject]@{
            safeName = 'Demo'; safeUrlId = 'safe-1'; description = 'Runtime smoke safe'; managingCPM = 'PasswordManager'
            olacEnabled = $false; numberOfVersionsRetention = 5; creator = 'Administrator'
        }
        $global:FastPASCatalogSmokePlatform = [pscustomobject]@{
            id = 'Unix'; platformId = 'Unix'; PolicyName = 'Unix'; Name = 'Unix'
            Active = $true; Description = 'Runtime smoke platform'; Policy = [pscustomobject]@{General = [pscustomobject]@{interval = 30}}
        }

        function New-CatalogCsv {
            param([string]$Name, $Row)
            $path = Join-Path $FixtureRoot $Name
            @($Row) | Export-Csv -LiteralPath $path -NoTypeInformation
            return $path
        }

        function Invoke-CatalogCase {
            param([string]$Id, [hashtable]$Arguments, $Context, [switch]$Write, [switch]$AllowUnsuccessful)
            $caseOutput = Join-Path $OutputRoot ($Id -replace '[^A-Za-z0-9_.-]', '_')
            try {
                if ($Write) {
                    $result = Invoke-FastPASCommand -Id $Id -Context $Context -Arguments $Arguments `
                        -OutputPath $caseOutput -NonInteractive -WhatIf -Confirm:$false
                }
                else {
                    $result = Invoke-FastPASCommand -Id $Id -Context $Context -Arguments $Arguments `
                        -OutputPath $caseOutput -NonInteractive
                }
                if ($null -eq $result -or $result.PSTypeNames -notcontains 'FastPAS.CommandResult') {
                    throw 'The command did not return a FastPAS.CommandResult.'
                }
                if (-not $AllowUnsuccessful -and -not $result.Success) {
                    $details = @($result.Data | ForEach-Object { Get-FastPASObjectString $_ @('Detail', 'Issue') } | Where-Object { $_ }) -join ' | '
                    throw "The command reported failure: $($result.Summary) $details"
                }
                $null = $tested.Add($Id)
            }
            catch { throw "Catalog runtime test failed for '$Id': $($_.Exception.Message)" }
        }

        try {
            Set-Item Function:Get-FastPASPagedItems {
                param($Context, $Path, $Query, $CollectionNames, $Limit, $MaximumPages)
                if ($Path -eq 'Accounts') {
                    if ($Query -and $Query.ContainsKey('filter') -and $Query['filter'] -match '(?i)(New|Demo)') { return @() }
                    return @($global:FastPASCatalogSmokeAccount)
                }
                if ($Path -eq 'Safes') { return @($global:FastPASCatalogSmokeSafe) }
                if ($Path -like 'Safes/*/Members') {
                    return @([pscustomobject]@{
                            memberName = 'Owners'; memberType = 'Group'; searchIn = 'Vault'
                            permissions = [pscustomobject]@{listAccounts = $true; manageSafeMembers = $true; viewAuditLog = $true}
                        })
                }
                if ($Path -match '(?i)^Platforms(?:/Targets)?$') { return @($global:FastPASCatalogSmokePlatform) }
                if ($Path -eq 'Recordings') {
                    return @([pscustomobject]@{
                            RecordingID = 'recording-1'; User = 'operator'; SafeName = 'Old'; AccountName = 'root'
                            ConnectionComponentID = 'PSM-RDP'; PSMStartTime = [DateTimeOffset]::UtcNow.AddMinutes(-5).ToString('o')
                            Status = 'Succeeded'; RemoteMachine = 'client01'
                        })
                }
                return @()
            }
            Set-Item Function:Get-FastPASOptionalItems { return @() }
            Set-Item Function:Resolve-FastPASAccount { param($Context, $AccountId) return $global:FastPASCatalogSmokeAccount }
            Set-Item Function:Resolve-FastPASSafe {
                param($Context, $SafeName)
                return [pscustomobject]@{
                    safeName = $SafeName; safeUrlId = 'safe-1'; description = 'Runtime smoke safe'; managingCPM = 'PasswordManager'
                    olacEnabled = $false; numberOfVersionsRetention = 5; creator = 'Administrator'
                }
            }
            Set-Item Function:Invoke-FastPASRawRequest {
                return [pscustomobject]@{
                    StatusCode = 200; Raw = '{}'
                    Data = [pscustomobject]@{Resources = @(); totalResults = 0}
                }
            }
            Set-Item Function:Resolve-FastPASHostAddress { param($HostName) return '192.0.2.10' }
            Set-Item Function:Test-FastPASTcpPort { param($HostName, $Port, $TimeoutMilliseconds) return }
            Set-Item Function:Invoke-FastPASApiRequest {
                param($Context, $Method, $Path, $Query, $Body, [switch]$NoRetry)
                if ($Method -ne 'GET') { throw "A mutation was attempted during WhatIf: $Method $Path" }
                if ($Path -like 'Safes/*/Members/*') { throw 'GET synthetic request failed with HTTP 404.' }
                if ($Path -like 'Safes/*') { return $global:FastPASCatalogSmokeSafe }
                if ($Path -like 'Accounts/*') { return $global:FastPASCatalogSmokeAccount }
                if ($Path -eq 'ComponentsMonitoringSummary') { return [pscustomobject]@{Components = @(); Vaults = @()} }
                if ($Path -like 'Platforms/*') { return $global:FastPASCatalogSmokePlatform }
                if ($Path -eq 'licenses/pcloud/') {
                    return [pscustomobject]@{
                        componentName = 'Privilege Cloud'
                        optionalSummary = [pscustomobject]@{name = 'Users'; used = 1; total = 10}
                        licensesData = @([pscustomobject]@{
                                licenseSubCategory = 'User Types'
                                licencesElements = @([pscustomobject]@{name = 'EPVUser'; used = 1; total = 10})
                            })
                    }
                }
                return [pscustomobject]@{}
            }

            $ispssProfile = [pscustomobject]@{
                Id = 'catalog-ispss'; Name = 'catalog-ispss'; DeploymentType = 'ispss'; Subdomain = 'example'
                IdentityHost = 'example.id.cyberark.cloud'; PVWAUrl = 'https://example.invalid/PasswordVault'
                VaultApiBaseUrl = 'https://example.invalid/PasswordVault/API'
            }
            $onPremProfile = [pscustomobject]@{
                Id = 'catalog-onprem'; Name = 'catalog-onprem'; DeploymentType = 'onprem'; Subdomain = ''
                IdentityHost = ''; PVWAUrl = 'https://localhost/PasswordVault'
                VaultApiBaseUrl = 'https://localhost/PasswordVault/API'
            }
            $ispssContext = [pscustomobject]@{
                Profile = $ispssProfile; DeploymentType = 'ispss'; PlatformToken = 'token'; IdentityToken = 'identity-token'
                ExpiresAt = [DateTimeOffset]::UtcNow.AddMinutes(10); CorrelationId = 'catalog-ispss'
                NonInteractive = $true; Disconnected = $false
            }
            $onPremContext = [pscustomobject]@{
                Profile = $onPremProfile; DeploymentType = 'onprem'; PlatformToken = 'token'; IdentityToken = ''
                ExpiresAt = [DateTimeOffset]::UtcNow.AddMinutes(10); CorrelationId = 'catalog-onprem'
                NonInteractive = $true; Disconnected = $false
            }
            $standaloneProfile = [pscustomobject]@{
                Id = 'catalog-standalone'; Name = 'catalog-standalone'; DeploymentType = 'standalone'; Subdomain = ''
                IdentityHost = ''; PVWAUrl = 'https://localhost/PasswordVault'
                VaultApiBaseUrl = 'https://localhost/PasswordVault/API'
            }
            $standaloneContext = [pscustomobject]@{
                Profile = $standaloneProfile; DeploymentType = 'standalone'; PlatformToken = 'token'; IdentityToken = ''
                ExpiresAt = [DateTimeOffset]::UtcNow.AddMinutes(10); CorrelationId = 'catalog-standalone'
                NonInteractive = $true; Disconnected = $false
            }
            $contextsByDeployment = @{
                ispss = $ispssContext
                onprem = $onPremContext
                standalone = $standaloneContext
            }

            $migrationInput = New-CatalogCsv 'safe-migration-input.csv' ([pscustomobject]@{
                    AccountId = 'account-1'; DestinationSafeName = 'New'
                })
            $readCases = @(
                @{Id = 'telemetry.components'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'telemetry.active-users'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'telemetry.account-failures'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'telemetry.psm-users'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'telemetry.license-capacity'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'account.inventory'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'safe.members.report'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'safe.inventory'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'safe.list'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'safe.detail'; Arguments = @{SafeName = 'Demo'}; Context = $ispssContext},
                @{Id = 'safe.members.list'; Arguments = @{SafeName = 'Demo'}; Context = $ispssContext},
                @{Id = 'safe.cpm.export'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'account.search'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'account.detail'; Arguments = @{AccountId = 'account-1'}; Context = $ispssContext},
                @{Id = 'platform.list'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'platform.accounts.report'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'platform.pmterminal.audit'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'troubleshooting.dependencies'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'troubleshooting.connectivity'; Arguments = @{}; Context = $onPremContext},
                @{Id = 'compliance.posture'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'onboarding.discovered'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'relationships.report'; Arguments = @{MaxAccounts = 10}; Context = $ispssContext},
                @{Id = 'governance.entitlements'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'telemetry.system-health'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'platform.drift'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'psm.sessions'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'aam.exposure'; Arguments = @{}; Context = $onPremContext},
                @{Id = 'request.queue'; Arguments = @{}; Context = $ispssContext},
                @{Id = 'safe.migration.plan'; Arguments = @{CsvPath = $migrationInput}; Context = $ispssContext}
            )
            foreach ($case in $readCases) {
                $deployments = @((Get-FastPASCommand -Id $case.Id).Deployments)
                foreach ($deployment in $deployments) {
                    Invoke-CatalogCase -Id $case.Id -Arguments $case.Arguments -Context $contextsByDeployment[$deployment] `
                        -AllowUnsuccessful:($case.ContainsKey('AllowUnsuccessful') -and [bool]$case.AllowUnsuccessful)
                }
            }

            $safeHash = Get-FastPASSafeSnapshotHash $global:FastPASCatalogSmokeSafe
            $accountHash = Get-FastPASObjectHash $global:FastPASCatalogSmokeAccount
            $platformHash = Get-FastPASObjectHash $global:FastPASCatalogSmokePlatform
            $writeCases = @(
                @{Id = 'bulk.safes.apply'; Context = $ispssContext; Row = [pscustomobject]@{Action = 'Create'; SafeName = 'New'; Description = 'Smoke'; ManagingCPM = 'PasswordManager'; NumberOfVersionsRetention = 5; NumberOfDaysRetention = ''}},
                @{Id = 'bulk.safe-members.apply'; Context = $ispssContext; Row = [pscustomobject]@{Action = 'Add'; SafeName = 'Demo'; MemberName = 'new-user'; MemberType = 'user'; SearchIn = 'Vault'; Role = 'Viewer'}},
                @{Id = 'bulk.safe-members.import-compatible'; Context = $ispssContext; Row = [pscustomobject]@{SafeName = 'Demo'; UserName = 'new-user'; MemberType = 'user'; ListAccounts = 'TRUE'}},
                @{Id = 'bulk.accounts.apply'; Context = $ispssContext; Row = [pscustomobject]@{Action = 'Create'; AccountId = ''; Name = 'svc'; Address = 'server02'; UserName = 'svc'; PlatformId = 'Unix'; SafeName = 'Demo'; SecretType = 'password'}},
                @{Id = 'platform.accounts.move'; Context = $ispssContext; Row = [pscustomobject]@{AccountId = 'account-1'; TargetPlatformId = 'UnixDomain'}},
                @{Id = 'resolution.account-failures'; Context = $ispssContext; Arguments = @{AccountIds = @('account-1')}},
                @{Id = 'safe.create'; Context = $ispssContext; Arguments = @{SafeName = 'New'}},
                @{Id = 'safe.members.add'; Context = $ispssContext; Arguments = @{SafeName = 'Demo'; MemberName = 'new-user'; MemberType = 'user'; Role = 'Viewer'}},
                @{Id = 'safe.cpm.apply'; Context = $ispssContext; Row = [pscustomobject]@{CpmUpdateMode = 'VerifiedSnapshot'; SafeName = 'Demo'; SafeUrlId = 'safe-1'; SnapshotHash = $safeHash; CurrentManagingCPM = 'PasswordManager'; ManagingCPM = 'NewCPM'; Description = 'Runtime smoke safe'; OLACEnabled = 'FALSE'; NumberOfVersionsRetention = 5; NumberOfDaysRetention = ''}},
                @{Id = 'troubleshooting.local-to-domain'; Context = $ispssContext; Row = [pscustomobject]@{AccountId = 'account-1'; DomainUserName = 'CORP\root'; DomainAddress = 'corp.example'; TargetPlatformId = 'WinDomain'}},
                @{Id = 'onboarding.discovered.apply'; Context = $ispssContext; Row = [pscustomobject]@{Action = 'Onboard'; DiscoveredAccountId = 'discovered-1'; Name = 'svc'; Address = 'server02'; UserName = 'svc'; RecommendedPlatformId = 'Unix'; RecommendedSafeName = 'Demo'; ShouldReconcileAccount = 'FALSE'; DuplicateAccountId = ''}},
                @{Id = 'relationships.apply'; Context = $ispssContext; Row = [pscustomobject]@{Action = 'Link'; SourceAccountId = 'account-1'; LinkType = 'Reconcile'; TargetSafeName = 'Demo'; TargetAccountName = 'reconcile'; TargetFolder = 'Root'}},
                @{Id = 'platform.drift.apply'; Context = $ispssContext; Row = [pscustomobject]@{PlatformId = 'Unix'; ExpectedHash = $platformHash; Property = 'Policy/General/interval'; NewValue = '45'}},
                @{Id = 'psm.sessions.action'; Context = $ispssContext; Row = [pscustomobject]@{SessionId = 'session-1'; Action = 'Suspend'; Reason = 'Runtime smoke test'}},
                @{Id = 'aam.exposure.apply'; Context = $onPremContext; Row = [pscustomobject]@{Action = 'Add'; ApplicationId = 'app-1'; AuthenticationId = ''; AuthType = 'machineAddress'; AuthValue = '192.0.2.10'; IsFolder = 'FALSE'; AllowInternalScripts = 'FALSE'}},
                @{Id = 'request.action'; Context = $ispssContext; Row = [pscustomobject]@{Action = 'Create'; RequestId = ''; AccountId = 'account-1'; Reason = 'Runtime smoke test'; From = ''; To = ''; MultipleAccessRequired = 'FALSE'}},
                @{Id = 'safe.migration.apply'; Context = $ispssContext; Row = [pscustomobject]@{AccountId = 'account-1'; AccountName = 'root'; SourceSafeName = 'Old'; DestinationSafeName = 'New'; ExpectedAccountHash = $accountHash; State = 'Ready'; RelationshipCheck = 'No relationship objects returned.'; Detail = 'Validated'}},
                @{Id = 'account.safe-transfer'; Context = $ispssContext; Row = [pscustomobject]@{OldSafe = 'Old'; NewSafe = 'New'}}
            )
            foreach ($case in $writeCases) {
                $arguments = if ($case.ContainsKey('Arguments')) { $case.Arguments } else {
                    @{CsvPath = New-CatalogCsv "$($case.Id -replace '\.', '-').csv" $case.Row}
                }
                foreach ($deployment in @((Get-FastPASCommand -Id $case.Id).Deployments)) {
                    Invoke-CatalogCase -Id $case.Id -Arguments $arguments -Context $contextsByDeployment[$deployment] -Write
                }
            }

            $catalog = @(Get-FastPASCommand)
            $missing = @($catalog | Where-Object { -not $tested.Contains($_.Id) } | ForEach-Object Id)
            $unexpected = @($tested | Where-Object { $_ -notin @($catalog.Id) })
            if ($missing.Count -or $unexpected.Count -or $tested.Count -ne $catalog.Count) {
                throw "Catalog coverage mismatch. Tested $($tested.Count) of $($catalog.Count). Missing: $($missing -join ', '). Unexpected: $($unexpected -join ', ')."
            }
            Write-Host "PowerShell $($PSVersionTable.PSVersion) runtime smoke passed for all $($tested.Count) FastPAS commands." -ForegroundColor Green
        }
        finally {
            Set-Item Function:Get-FastPASPagedItems $originalPaged
            Set-Item Function:Get-FastPASOptionalItems $originalOptional
            Set-Item Function:Resolve-FastPASAccount $originalAccount
            Set-Item Function:Resolve-FastPASSafe $originalSafe
            Set-Item Function:Invoke-FastPASApiRequest $originalApi
            Set-Item Function:Invoke-FastPASRawRequest $originalRaw
            Set-Item Function:Resolve-FastPASHostAddress $originalHostAddress
            Set-Item Function:Test-FastPASTcpPort $originalTcpPort
            Remove-Variable FastPASCatalogSmokeAccount, FastPASCatalogSmokeSafe, FastPASCatalogSmokePlatform -Scope Global -ErrorAction SilentlyContinue
        }
    } $outputRoot $fixtureRoot
}
finally {
    Remove-Module FastPAS.PowerShell -Force -ErrorAction SilentlyContinue
    if ($null -eq $previousDataRoot) { Remove-Item Env:FASTPAS_DATA_ROOT -ErrorAction SilentlyContinue }
    else { $env:FASTPAS_DATA_ROOT = $previousDataRoot }

    $fullTestRoot = [IO.Path]::GetFullPath($testRoot)
    $fullTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($fullTestRoot.StartsWith($fullTempRoot, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $fullTestRoot)) {
        Remove-Item -LiteralPath $fullTestRoot -Recurse -Force
    }
}
