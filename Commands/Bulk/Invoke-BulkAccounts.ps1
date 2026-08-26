[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$csvPath = [string]$Arguments['CsvPath'];
if (-not $csvPath -or -not(Test-Path -LiteralPath $csvPath -PathType Leaf)) { throw 'CsvPath must identify an existing bulk-accounts CSV file.' }
$items = @(Import-Csv -LiteralPath $csvPath);
if (-not $items.Count) { throw 'The CSV contains no data rows.' };
if ($items.Count -gt 1000) { throw 'Bulk account operations are limited to 1000 rows.' }
if ($items[0].PSObject.Properties.Name -notcontains 'Action') { throw "The CSV requires an 'Action' column." }
$results = [Collections.Generic.List[object]]::new()
foreach ($item in $items) {
    $action = [string]$item.Action;
    $id = [string]$item.AccountId;
    $name = [string]$item.Name;
    $status = 'Completed';
    $detail = ''
    try {
        if ($action -notin @('Create', 'Update', 'Delete')) { throw "Unsupported Action '$action'. Use Create, Update, or Delete." };
        if ($action -ne 'Create' -and -not $id) { throw 'AccountId is required for Update and Delete.' }
        $target = if ($id) { $id }else { "$($item.SafeName)/$name" };
        if (-not $PSCmdlet.ShouldProcess($target, "$action CyberArk account")) {
            $status = 'WhatIf';
            $detail = 'No mutation was sent.'
        }
        elseif ($action -eq 'Delete') {
            $null = Invoke-FastPASApiRequest -Context $Context -Method DELETE -Path "Accounts/$([uri]::EscapeDataString($id))";
            $detail = 'Account deleted.'
        }
        elseif ($action -eq 'Create') {
            foreach ($required in 'Name', 'Address', 'UserName', 'PlatformId', 'SafeName') { if (-not $item.$required) { throw "$required is required for Create." } }
            $body = [ordered]@{name = [string]$item.Name;
                address = [string]$item.Address;
                userName = [string]$item.UserName;
                platformId = [string]$item.PlatformId;
                safeName = [string]$item.SafeName;
                secretType = if ($item.SecretType) { [string]$item.SecretType }else { 'password' }
            }
            $null = Invoke-FastPASApiRequest -Context $Context -Method POST -Path 'Accounts' -Body $body;
            $detail = 'Account creation request sent without storing a secret in CSV.'
        }
        else {
            $patch = [Collections.Generic.List[object]]::new();
            foreach ($mapping in @(@('Name', '/name'), @('Address', '/address'), @('UserName', '/userName'), @('PlatformId', '/platformID'), @('SafeName', '/safeName'))) {
                if ($item.($mapping[0])) {
                    $patch.Add(@{op = 'replace';
                            path = $mapping[1];
                            value = [string]$item.($mapping[0])
                        })
                }
            }
            if (-not $patch.Count) { throw 'Update requires at least one metadata value.' };
            $null = Invoke-FastPASApiRequest -Context $Context -Method PATCH -Path "Accounts/$([uri]::EscapeDataString($id))" -Body @($patch);
            $detail = 'Account metadata updated.'
        }
    }
    catch {
        $status = 'Failed';
        $detail = $_.Exception.Message
    }
    $results.Add([pscustomobject]@{Action = $action;
            AccountId = $id;
            Name = $name;
            SafeName = [string]$item.SafeName;
            Status = $status;
            Detail = $detail
        })
}
$data = @($results);
$csv = Export-FastPASCsv $data $OutputPath 'bulk_accounts_result';
$failed = @($data | Where-Object Status -EQ 'Failed').Count
New-FastPASResult -Success ($failed -eq 0) -Summary "Bulk account operation complete: $($data.Count-$failed) succeeded/previewed, $failed failed." -Data $data -Artifacts @($csv) -AuditEvents @($data)
