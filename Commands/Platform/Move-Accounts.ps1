[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$csvPath = [string]$Arguments['CsvPath'];
if (-not $csvPath -or -not(Test-Path -LiteralPath $csvPath -PathType Leaf)) { throw 'CsvPath must identify an existing platform-account-moves CSV file.' }
$items = @(Import-Csv -LiteralPath $csvPath);
if (-not $items.Count) { throw 'The CSV contains no data rows.' };
if ($items.Count -gt 1000) { throw 'Platform moves are limited to 1000 rows.' }
foreach ($required in 'AccountId', 'TargetPlatformId') { if ($items[0].PSObject.Properties.Name -notcontains $required) { throw "The CSV requires a '$required' column." } }
$results = [Collections.Generic.List[object]]::new()
foreach ($item in $items) {
    $id = [string]$item.AccountId;
    $target = [string]$item.TargetPlatformId;
    $status = 'Completed';
    $detail = ''
    try {
        if (-not $id -or -not $target -or $id -match '[/\\?#]') { throw 'AccountId and TargetPlatformId are required and AccountId contains unsupported characters.' }
        $account = Resolve-FastPASAccount -Context $Context -AccountId $id;
        $row = ConvertTo-FastPASAccountRow $account
        if (-not $PSCmdlet.ShouldProcess("$($row.SafeName)/$($row.Name)", "Move from platform '$($row.PlatformId)' to '$target'")) {
            $status = 'WhatIf';
            $detail = 'No mutation was sent.'
        }
        else {
            $null = Invoke-FastPASApiRequest -Context $Context -Method PATCH -Path "Accounts/$([uri]::EscapeDataString($id))" -Body @(@{op = 'replace';
                    path = '/platformID';
                    value = $target
                });
            $detail = 'Platform updated.'
        }
        $results.Add([pscustomobject]@{AccountId = $id;
                AccountName = $row.Name;
                SafeName = $row.SafeName;
                PreviousPlatformId = $row.PlatformId;
                TargetPlatformId = $target;
                Status = $status;
                Detail = $detail
            })
    }
    catch {
        $results.Add([pscustomobject]@{AccountId = $id;
                AccountName = '';
                SafeName = '';
                PreviousPlatformId = '';
                TargetPlatformId = $target;
                Status = 'Failed';
                Detail = $_.Exception.Message
            })
    }
}
$data = @($results);
$csv = Export-FastPASCsv $data $OutputPath 'platform_moves_result';
$failed = @($data | Where-Object Status -EQ 'Failed').Count
New-FastPASResult -Success ($failed -eq 0) -Summary "Platform move operation complete: $($data.Count-$failed) succeeded/previewed, $failed failed." -Data $data -Artifacts @($csv) -AuditEvents @($data)
