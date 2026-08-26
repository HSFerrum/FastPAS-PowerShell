$script:ProjectRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $script:ProjectRoot 'FastPAS.PowerShell.psd1') -Force

BeforeAll {
    $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
    $env:FASTPAS_DATA_ROOT = Join-Path $TestDrive 'data'
}

AfterAll {
    Remove-Module FastPAS.PowerShell -Force -ErrorAction SilentlyContinue
    Remove-Item Env:FASTPAS_DATA_ROOT -ErrorAction SilentlyContinue
}

Describe 'FastPAS command catalog' {
    It 'contains unique IDs and existing scripts' {
        $commands = @(Get-FastPASCommand)
        $commands.Count | Should -BeGreaterThan 5
        @($commands.Id | Sort-Object -Unique).Count | Should -Be $commands.Count
        foreach ($command in $commands) { Test-Path (Join-Path $script:ProjectRoot $command.Script) | Should -BeTrue }
    }

    It 'marks every command with a valid risk level' {
        Get-FastPASCommand | ForEach-Object { $_.RiskLevel | Should -BeIn @('Read', 'Write') }
    }

    It 'contains all main-menu sections and the complete original telemetry set' {
        $commands = @(Get-FastPASCommand)
        foreach ($section in 'Telemetry and Reports', 'Bulk Actions', 'Safe Management', 'Account Management', 'Platform Management', 'Troubleshooting and Tools') {
            @($commands | Where-Object { $_.Sections -contains $section }).Count | Should -BeGreaterThan 0
        }
        foreach ($id in 'telemetry.components', 'telemetry.active-users', 'telemetry.account-failures') {
            Get-FastPASCommand -Id $id | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'FastPAS profiles' {
    BeforeEach {
        Remove-Item -LiteralPath $env:FASTPAS_DATA_ROOT -Recurse -Force -ErrorAction SilentlyContinue
        Mock -ModuleName FastPAS.PowerShell Remove-FastPASLegacyCredential {}
        Mock -ModuleName FastPAS.PowerShell Resolve-FastPASTenant { [pscustomobject]@{IdentityHost = 'discovered.my.idaptive.app' } }
    }

    It 'stores OAuth profile metadata without requesting or serializing a secret' {
        $profileRecord = New-FastPASProfile -name test -Subdomain example -AuthType oauth -ApplicationId app -ClientId client -SetActive
        $profileRecord.Name | Should -Be 'test'
        $profileRecord.IdentityHost | Should -Be 'discovered.my.idaptive.app'
        $raw = Get-Content (Join-Path $env:FASTPAS_DATA_ROOT 'profiles.json') -Raw
        $raw | Should -Not -Match 'SyntheticSecret'
        $raw | Should -Not -Match 'clientSecret'
        (Get-FastPASProfile -Active).Id | Should -Be $profileRecord.Id
    }

    It 'rejects incomplete OAuth profiles' {
        { New-FastPASProfile -name invalid -Subdomain example -AuthType oauth } | Should -Throw
    }

    It 'creates a federated profile without storing a password' {
        $profileRecord = New-FastPASProfile -name federated -Subdomain example -IdentityHost discovered.my.idaptive.app -AuthType federated -Username user@example.invalid
        $profileRecord.AuthType | Should -Be 'federated'
        $profileRecord.PSObject.Properties.Name | Should -Not -Contain 'SecretStored'
    }

    It 'keeps multiple profiles and resolves each by name or ID' {
        $first = New-FastPASProfile -name first -Subdomain example -AuthType interactive -Username first@example.invalid
        $second = New-FastPASProfile -name second -Subdomain example -AuthType interactive -Username second@example.invalid
        @(Get-FastPASProfile).Count | Should -Be 2
        (Get-FastPASProfile -name first).Id | Should -Be $first.Id
        (Get-FastPASProfile -Id $second.Id).Name | Should -Be 'second'
    }

    It 'migrates schema v1 profiles and deletes their legacy credentials' {
        $dataRoot = $env:FASTPAS_DATA_ROOT
        $null = New-Item -ItemType Directory -Path $dataRoot -Force
        '{"schemaVersion":1,"activeProfileId":"old-id","profiles":[{"id":"old-id","name":"old","authType":"interactive","subdomain":"example","username":"user","secretStored":true}]}' | Set-Content (Join-Path $dataRoot 'profiles.json')
        $profileRecord = Get-FastPASProfile -name old
        $profileRecord.PSObject.Properties.Name | Should -Not -Contain 'SecretStored'
        Should -Invoke Remove-FastPASLegacyCredential -ModuleName FastPAS.PowerShell -Times 1 -ParameterFilter { $ProfileId -eq 'old-id' }
        (Get-Content (Join-Path $dataRoot 'profiles.json') -Raw | ConvertFrom-Json).schemaVersion | Should -Be 2
    }
}

Describe 'FastPAS API client' {
    InModuleScope FastPAS.PowerShell {
        BeforeEach {
            $script:context = [pscustomobject]@{
                Profile = [pscustomobject]@{Id = 'p1';
                    Name = 'test';
                    Subdomain = 'example';
                    VaultApiBaseUrl = 'https://example.invalid/API'
                }
                PlatformToken = 'synthetic-token';
                ExpiresAt = [DateTimeOffset]::UtcNow.AddMinutes(10);
                CorrelationId = 'c1';
                NonInteractive = $true;
                Disconnected = $false
            }
        }

        It 'URL-encodes query values and returns parsed data' {
            Mock Invoke-FastPASRawRequest { param($Method, $Uri) [pscustomobject]@{StatusCode = 200;
                    Uri = $Uri;
                    Data = [pscustomobject]@{value = @() };
                    Raw = '{}'
                } }
            $null = Invoke-FastPASApiRequest -Context $script:context -Method GET -Path Accounts -Query @{search = 'name with spaces' }
            Should -Invoke Invoke-FastPASRawRequest -Times 1 -ParameterFilter { $Uri -match 'search=name%20with%20spaces' }
        }

        It 'rejects calls through disconnected contexts' {
            $script:context.Disconnected = $true
            { Invoke-FastPASApiRequest -Context $script:context -Method GET -Path Accounts } | Should -Throw '*disconnected*'
        }

        It 'redacts known secret fields in audit values' {
            $protected = Protect-FastPASAuditValue @{Authorization = 'Bearer secret';
                nested = @{password = 'secret';
                    safe = 'visible'
                }
            }
            $protected.Authorization | Should -Be '[REDACTED]'
            $protected.nested.password | Should -Be '[REDACTED]'
            $protected.nested.safe | Should -Be 'visible'
        }
    }
}

Describe 'CyberArk API Runner compatibility helpers' {
    InModuleScope FastPAS.PowerShell {
        It 'strictly validates permission booleans and converts legacy authorization levels' {
            $permissions = New-FastPASPermissionsFromCsvRow ([pscustomobject]@{ListAccounts = 'TRUE';
                    RequestsAuthorizationLevel = '2'
                })
            $permissions.listAccounts | Should -BeTrue
            $permissions.requestsAuthorizationLevel1 | Should -BeTrue
            $permissions.requestsAuthorizationLevel2 | Should -BeTrue
            { New-FastPASPermissionsFromCsvRow ([pscustomobject]@{ListAccounts = 'sometimes' }) } | Should -Throw '*TRUE or FALSE*'
        }

        It 'detects snapshot changes and recursively finds PMTerminal values' {
            $safe = [pscustomobject]@{safeName = 'A';
                safeUrlId = '1';
                managingCPM = 'CPM';
                description = 'x';
                olacEnabled = $false;
                numberOfVersionsRetention = 5
            }
            $first = Get-FastPASSafeSnapshotHash $safe
            $safe.description = 'changed'
            Get-FastPASSafeSnapshotHash $safe | Should -Not -Be $first
            $stringMatches = @(Find-FastPASStringMatch ([pscustomobject]@{one = [pscustomobject]@{command = 'PMTerminal.exe' } }) '(?i)pmterminal(?:\.exe)?')
            $stringMatches.Count | Should -Be 1
            $stringMatches[0].PropertyPath | Should -Be 'one.command'
        }
    }
}

Describe 'Federated eIDP authentication' {
    InModuleScope FastPAS.PowerShell {
        It 'opens the validated redirect and submits OOBAUTHPIN without an IdP password' {
            $script:federatedStep = 0
            Mock Invoke-FastPASRawRequest {
                $script:federatedStep++
                if ($script:federatedStep -eq 1) {
                    return [pscustomobject]@{StatusCode = 200;
                        Raw = '';
                        Data = [pscustomobject]@{success = $true;
                            Result = [pscustomobject]@{IdpRedirectShortUrl = 'https://login.example.invalid/short';
                                IdpLoginSessionId = 'session'
                            }
                        }
                    }
                }
                $Body.MechanismId | Should -Be 'OOBAUTHPIN'
                $Body.Action | Should -Be 'Answer'
                return [pscustomobject]@{StatusCode = 200;
                    Raw = '';
                    Data = [pscustomobject]@{success = $true;
                        Result = [pscustomobject]@{Token = 'synthetic' }
                    }
                }
            }
            Mock Start-Process {}
            Mock Read-FastPASChallengeAnswer { '123456' }
            $profileRecord = [pscustomobject]@{IdentityHost = 'tenant.id.cyberark.cloud';
                Username = 'user@example.invalid';
                Subdomain = 'tenant'
            }
            Invoke-FastPASFederatedAuthentication -Profile $profileRecord | Should -Be 'synthetic'
            Should -Invoke Start-Process -Times 1 -ParameterFilter { $FilePath -eq 'https://login.example.invalid/short' }
            Should -Invoke Invoke-FastPASRawRequest -Times 2
        }

        It 'rejects non-HTTPS and local redirects' {
            Test-FastPASFederatedRedirectUrl 'http://example.invalid' | Should -BeFalse
            Test-FastPASFederatedRedirectUrl 'https://localhost/callback' | Should -BeFalse
        }
    }
}

Describe 'Guarded remediation' {
    InModuleScope FastPAS.PowerShell {
        BeforeEach {
            $script:context = [pscustomobject]@{
                Profile = [pscustomobject]@{Id = 'p1';
                    Name = 'test';
                    Subdomain = 'example';
                    VaultApiBaseUrl = 'https://example.invalid/API'
                }
                PlatformToken = 'synthetic-token';
                ExpiresAt = [DateTimeOffset]::UtcNow.AddMinutes(10);
                CorrelationId = 'c1';
                NonInteractive = $false;
                Disconnected = $false
            }
            Mock Resolve-FastPASAccount { [pscustomobject]@{id = '1';
                    name = 'root';
                    safeName = 'Demo';
                    userName = 'root';
                    address = 'host';
                    platformId = 'Unix';
                    locked = $false;
                    secretManagement = [pscustomobject]@{automaticManagementEnabled = $false;
                        status = 'failure'
                    }
                } }
            Mock Invoke-FastPASApiRequest { throw 'A mutation should not be sent during WhatIf.' }
        }

        It 'returns a preview and sends no API mutation under WhatIf' {
            $script:context.NonInteractive = $true
            $result = Invoke-FastPASCommand -Id resolution.account-failures -Context $script:context -Arguments @{AccountIds = @('1') } -OutputPath (Join-Path $TestDrive 'out') -NonInteractive -WhatIf -Confirm:$false
            $result.Success | Should -BeTrue
            $result.Data[0].CompletionStatus | Should -Be 'whatif'
            Should -Invoke Invoke-FastPASApiRequest -Times 0
        }

        It 'requires Force and disabled confirmation for unattended writes' {
            { $null = Invoke-FastPASCommand -Id resolution.account-failures -Context $script:context -Arguments @{AccountIds = @('1') } -OutputPath (Join-Path $TestDrive 'out') -NonInteractive } | Should -Throw '*-Force*'
        }
    }
}

Describe 'Telemetry degradation' {
    InModuleScope FastPAS.PowerShell {
        It 'returns CPM results when recordings are unavailable' {
            $context = [pscustomobject]@{Profile = [pscustomobject]@{Id = 'p1';
                    Name = 'test';
                    Subdomain = 'example';
                    VaultApiBaseUrl = 'https://example.invalid/API'
                };
                PlatformToken = 'x';
                ExpiresAt = [DateTimeOffset]::UtcNow.AddMinutes(10);
                CorrelationId = 'c2';
                NonInteractive = $true;
                Disconnected = $false
            }
            Mock Get-FastPASPagedItems {
                if ($Path -eq 'Accounts') {
                    return @([pscustomobject]@{id = '1';
                            name = 'root';
                            safeName = 'Demo';
                            secretManagement = [pscustomobject]@{automaticManagementEnabled = $false;
                                status = 'failure';
                                failureReason = 'Synthetic failure'
                            }
                        })
                }
                throw 'HTTP 403'
            }
            $result = Invoke-FastPASCommand -Id telemetry.account-failures -Context $context -Arguments @{LookbackDays = 7 } -OutputPath (Join-Path $TestDrive 'telemetry') -NonInteractive
            $result.Success | Should -BeTrue
            $result.Warnings[0] | Should -Match 'PSM recording evidence was unavailable'
            @($result.Data | Where-Object Service -EQ 'CPM').Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Expanded operations suite' {
    InModuleScope FastPAS.PowerShell {
        BeforeEach {
            $script:expandedContext = [pscustomobject]@{Profile = [pscustomobject]@{Id = 'p1';
                    Name = 'test';
                    Subdomain = 'example';
                    VaultApiBaseUrl = 'https://example.invalid/API'
                };
                PlatformToken = 'x';
                ExpiresAt = [DateTimeOffset]::UtcNow.AddMinutes(10);
                CorrelationId = 'expanded';
                NonInteractive = $true;
                Disconnected = $false
            }
        }

        It 'finds disabled management and empty-safe hygiene issues' {
            Mock Get-FastPASPagedItems {
                if ($Path -eq 'Accounts') {
                    return @([pscustomobject]@{id = '1';
                            name = 'root';
                            safeName = 'Demo';
                            userName = 'root';
                            address = 'server';
                            platformId = 'Unix';
                            locked = $false;
                            secretManagement = [pscustomobject]@{automaticManagementEnabled = $false;
                                status = 'success'
                            }
                        })
                }
                if ($Path -eq 'Safes') {
                    return @([pscustomobject]@{safeName = 'Empty';
                            safeUrlId = '10'
                        })
                }
                if ($Path -like 'Safes/*/Members') {
                    return @([pscustomobject]@{memberName = 'Owners';
                            memberType = 'Group';
                            permissions = [pscustomobject]@{manageSafeMembers = $true }
                        })
                }
                if ($Path -eq 'Users') { return @() }
                return @()
            }
            $result = Invoke-FastPASCommand -Id compliance.posture -Context $script:expandedContext -Arguments @{} -OutputPath (Join-Path $TestDrive 'compliance') -NonInteractive
            $result.Success | Should -BeTrue
            @($result.Data | Where-Object Category -EQ 'Automatic management disabled').Count | Should -Be 1
            @($result.Data | Where-Object Category -EQ 'Empty safe').Count | Should -Be 1
        }

        It 'previews a hash-verified safe migration without mutation' {
            $account = [pscustomobject]@{id = '1';
                name = 'root';
                safeName = 'Old';
                userName = 'root';
                address = 'server';
                platformId = 'Unix'
            }
            $planPath = Join-Path $TestDrive 'plan.csv'
            [pscustomobject]@{AccountId = '1';
                AccountName = 'root';
                SourceSafeName = 'Old';
                DestinationSafeName = 'New';
                ExpectedAccountHash = (Get-FastPASObjectHash $account);
                State = 'Ready';
                Detail = 'Validated'
            } | Export-Csv -LiteralPath $planPath -NoTypeInformation
            Mock Resolve-FastPASAccount { $account }
            Mock Resolve-FastPASSafe { [pscustomobject]@{safeName = 'New';
                    safeUrlId = '2'
                } }
            Mock Invoke-FastPASApiRequest { throw 'No mutation should occur under WhatIf.' }
            $result = Invoke-FastPASCommand -Id safe.migration.apply -Context $script:expandedContext -Arguments @{CsvPath = $planPath } -OutputPath (Join-Path $TestDrive 'migration') -NonInteractive -WhatIf -Confirm:$false
            $result.Success | Should -BeTrue
            $result.Data[0].Status | Should -Be 'WhatIf'
            Should -Invoke Invoke-FastPASApiRequest -Times 0
        }
    }
}
