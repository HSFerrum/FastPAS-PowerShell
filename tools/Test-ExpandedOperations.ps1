#requires -Version 7.0
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'FastPAS.PowerShell.psd1') -Force
$output = Join-Path $root '.test-runtime/expanded-smoke'
$null = New-Item -ItemType Directory -Path $output -Force
& (Get-Module FastPAS.PowerShell) {
    $originalPaged = ${function:Get-FastPASPagedItems}
    $originalAccount = ${function:Resolve-FastPASAccount}
    $originalSafe = ${function:Resolve-FastPASSafe}
    $originalApi = ${function:Invoke-FastPASApiRequest}
    try {
        Set-Item Function:Get-FastPASPagedItems {
            param($Context, $Path, $Query, $CollectionNames, $Limit, $MaximumPages)
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
            return @()
        }
        Set-Item Function:Invoke-FastPASApiRequest { return $null }
        $context = [pscustomobject]@{Profile = [pscustomobject]@{Id = 'smoke';
                Name = 'smoke';
                Subdomain = 'example';
                VaultApiBaseUrl = 'https://example.invalid/API'
            };
            PlatformToken = 'x';
            DeploymentType = 'onprem';
            IdentityToken = '';
            ExpiresAt = [DateTimeOffset]::UtcNow.AddMinutes(10);
            CorrelationId = 'expanded-smoke';
            NonInteractive = $true;
            Disconnected = $false
        }
        $compliance = Invoke-FastPASCommand -Id compliance.posture -Context $context -Arguments @{} -OutputPath $output -NonInteractive
        if (-not $compliance.Success -or @($compliance.Data | Where-Object Category -EQ 'Automatic management disabled').Count -ne 1 -or @($compliance.Data | Where-Object Category -EQ 'Empty safe').Count -ne 1) { throw 'Compliance runtime smoke test failed.' }
        Write-Host 'Compliance runtime smoke test passed.' -ForegroundColor Green

        $script:smokeAccount = [pscustomobject]@{id = '1';
            name = 'root';
            safeName = 'Old';
            userName = 'root';
            address = 'server';
            platformId = 'Unix'
        }
        Set-Item Function:Resolve-FastPASAccount { param($Context, $AccountId) return [pscustomobject]@{id = '1';
                name = 'root';
                safeName = 'Old';
                userName = 'root';
                address = 'server';
                platformId = 'Unix'
            } }
        Set-Item Function:Resolve-FastPASSafe { param($Context, $SafeName) return [pscustomobject]@{safeName = $SafeName;
                safeUrlId = '2'
            } }
        foreach ($smoke in @(
                @{Id = 'onboarding.discovered';
                    Arguments = @{}
                }, @{Id = 'relationships.report';
                    Arguments = @{MaxAccounts = 10 }
                },
                @{Id = 'governance.entitlements';
                    Arguments = @{}
                }, @{Id = 'telemetry.system-health';
                    Arguments = @{}
                },
                @{Id = 'platform.drift';
                    Arguments = @{}
                }, @{Id = 'psm.sessions';
                    Arguments = @{LookbackDays = 7 }
                },
                @{Id = 'aam.exposure';
                    Arguments = @{}
                }, @{Id = 'request.queue';
                    Arguments = @{}
                }
            )) {
            $readResult = Invoke-FastPASCommand -Id $smoke.Id -Context $context -Arguments $smoke.Arguments -OutputPath $output -NonInteractive;
            if (-not $readResult.Success) { throw "Read-command smoke test failed for '$($smoke.Id)'." }
        }
        Write-Host 'Expanded read-command runtime smoke tests passed.' -ForegroundColor Green

        $plan = Join-Path $output 'safe-migration-smoke-plan.csv'
        [pscustomobject]@{AccountId = '1';
            AccountName = 'root';
            SourceSafeName = 'Old';
            DestinationSafeName = 'New';
            ExpectedAccountHash = (Get-FastPASObjectHash $script:smokeAccount);
            State = 'Ready';
            Detail = 'Validated'
        } | Export-Csv -LiteralPath $plan -NoTypeInformation
        Set-Item Function:Invoke-FastPASApiRequest { throw 'A mutation was attempted during WhatIf.' }
        $migration = Invoke-FastPASCommand -Id safe.migration.apply -Context $context -Arguments @{CsvPath = $plan } -OutputPath $output -NonInteractive -WhatIf -Confirm:$false
        if (-not $migration.Success -or $migration.Data[0].Status -ne 'WhatIf') { throw "Safe migration WhatIf runtime smoke test failed: $($migration|ConvertTo-Json -Depth 10 -Compress)" }
        Write-Host 'Safe migration WhatIf runtime smoke test passed.' -ForegroundColor Green

        $script:platformSmoke = [pscustomobject]@{PolicyName = 'Unix';
            Active = $true;
            Description = 'Smoke'
        }
        Set-Item Function:Invoke-FastPASApiRequest { param($Context, $Method, $Path, $Query, $Body, $NoRetry) if ($Method -eq 'GET') {
                return [pscustomobject]@{PolicyName = 'Unix';
                    Active = $true;
                    Description = 'Smoke'
                }
            };
            throw 'A mutation was attempted during WhatIf.' }
        $writeCases = @(
            @{Id = 'onboarding.discovered.apply';
                Name = 'onboarding.csv';
                Row = [pscustomobject]@{Action = 'Onboard';
                    DiscoveredAccountId = 'd1';
                    Name = 'svc';
                    Address = 'server';
                    UserName = 'svc';
                    RecommendedPlatformId = 'Unix';
                    RecommendedSafeName = 'New';
                    DuplicateAccountId = ''
                }
            },
            @{Id = 'relationships.apply';
                Name = 'links.csv';
                Row = [pscustomobject]@{Action = 'Link';
                    SourceAccountId = '1';
                    LinkType = 'Reconcile';
                    TargetSafeName = 'New';
                    TargetAccountName = 'reconcile';
                    TargetFolder = 'Root'
                }
            },
            @{Id = 'platform.drift.apply';
                Name = 'platform.csv';
                Row = [pscustomobject]@{PlatformId = 'Unix';
                    ExpectedHash = (Get-FastPASObjectHash $script:platformSmoke);
                    Property = 'Policy/General/interval';
                    NewValue = '30'
                }
            },
            @{Id = 'psm.sessions.action';
                Name = 'psm.csv';
                Row = [pscustomobject]@{SessionId = 'session1';
                    Action = 'Suspend';
                    Reason = 'Smoke test'
                }
            },
            @{Id = 'aam.exposure.apply';
                Name = 'application.csv';
                Row = [pscustomobject]@{Action = 'Add';
                    ApplicationId = 'app1';
                    AuthenticationId = '';
                    AuthType = 'machineAddress';
                    AuthValue = '192.0.2.10';
                    IsFolder = 'FALSE';
                    AllowInternalScripts = 'FALSE'
                }
            },
            @{Id = 'request.action';
                Name = 'request.csv';
                Row = [pscustomobject]@{Action = 'Create';
                    RequestId = '';
                    AccountId = '1';
                    Reason = 'Smoke test';
                    From = '';
                    To = '';
                    MultipleAccessRequired = 'FALSE'
                }
            }
        )
        foreach ($case in $writeCases) {
            $casePath = Join-Path $output $case.Name;
            $case.Row | Export-Csv -LiteralPath $casePath -NoTypeInformation;
            $preview = Invoke-FastPASCommand -Id $case.Id -Context $context -Arguments @{CsvPath = $casePath } -OutputPath $output -NonInteractive -WhatIf -Confirm:$false;
            if (-not $preview.Success -or $preview.Data[0].Status -ne 'WhatIf') { throw "Write-command WhatIf smoke test failed for '$($case.Id)': $($preview|ConvertTo-Json -Depth 10 -Compress)" }
        }
        Write-Host 'Expanded write-command WhatIf smoke tests passed.' -ForegroundColor Green
    }
    finally {
        Set-Item Function:Get-FastPASPagedItems $originalPaged
        Set-Item Function:Resolve-FastPASAccount $originalAccount
        Set-Item Function:Resolve-FastPASSafe $originalSafe
        Set-Item Function:Invoke-FastPASApiRequest $originalApi
    }
}
