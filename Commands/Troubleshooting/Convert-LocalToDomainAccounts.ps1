[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$csvPath = [string]$Arguments['CsvPath'];
if (-not $csvPath -or -not(Test-Path -LiteralPath $csvPath -PathType Leaf)) { throw 'CsvPath must identify an existing local-to-domain-accounts CSV file.' }
$items = @(Import-Csv -LiteralPath $csvPath);
if (-not $items.Count) { throw 'The CSV contains no data rows.' };
if ($items.Count -gt 1000) { throw 'Local-to-domain conversions are limited to 1000 rows.' }
foreach ($required in 'AccountId', 'DomainUserName', 'DomainAddress', 'TargetPlatformId') { if ($items[0].PSObject.Properties.Name -notcontains $required) { throw "The CSV requires a '$required' column." } }
$results = [Collections.Generic.List[object]]::new()
foreach ($item in $items) {
    $id = [string]$item.AccountId;
    $status = 'Completed';
    $detail = ''
    try {
        if (-not $id -or $id -match '[/\\?#]' -or -not $item.DomainUserName -or -not $item.DomainAddress -or -not $item.TargetPlatformId) { throw 'AccountId, DomainUserName, DomainAddress, and TargetPlatformId are required.' }
        $account = Resolve-FastPASAccount -Context $Context -AccountId $id;
        $before = ConvertTo-FastPASAccountRow $account
        if (-not $PSCmdlet.ShouldProcess("$($before.SafeName)/$($before.Name)", "Convert local account to $($item.DomainUserName) on $($item.DomainAddress) using $($item.TargetPlatformId)")) {
            $status = 'WhatIf';
            $detail = 'No mutation was sent.'
        }
        else {
            $patch = @(@{op = 'replace';
                    path = '/userName';
                    value = [string]$item.DomainUserName
                }, @{op = 'replace';
                    path = '/address';
                    value = [string]$item.DomainAddress
                }, @{op = 'replace';
                    path = '/platformID';
                    value = [string]$item.TargetPlatformId
                });
            $null = Invoke-FastPASApiRequest -Context $Context -Method PATCH -Path "Accounts/$([uri]::EscapeDataString($id))" -Body $patch;
            $detail = 'Username, address, and platform updated.'
        }
        $results.Add([pscustomobject]@{AccountId = $id;
                AccountName = $before.Name;
                SafeName = $before.SafeName;
                PreviousUserName = $before.UserName;
                DomainUserName = [string]$item.DomainUserName;
                PreviousAddress = $before.Address;
                DomainAddress = [string]$item.DomainAddress;
                PreviousPlatformId = $before.PlatformId;
                TargetPlatformId = [string]$item.TargetPlatformId;
                Status = $status;
                Detail = $detail
            })
    }
    catch {
        $results.Add([pscustomobject]@{AccountId = $id;
                AccountName = '';
                SafeName = '';
                PreviousUserName = '';
                DomainUserName = [string]$item.DomainUserName;
                PreviousAddress = '';
                DomainAddress = [string]$item.DomainAddress;
                PreviousPlatformId = '';
                TargetPlatformId = [string]$item.TargetPlatformId;
                Status = 'Failed';
                Detail = $_.Exception.Message
            })
    }
}
$data = @($results);
$csv = Export-FastPASCsv $data $OutputPath 'local_to_domain_result';
$failed = @($data | Where-Object Status -EQ 'Failed').Count
New-FastPASResult -Success ($failed -eq 0) -Summary "Local-to-domain conversion complete: $($data.Count-$failed) succeeded/previewed, $failed failed." -Data $data -Artifacts @($csv) -AuditEvents @($data)
