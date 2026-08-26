[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$path = [string]$Arguments['CsvPath'];
if (-not $path -or -not(Test-Path -LiteralPath $path -PathType Leaf)) { throw 'CsvPath must identify an exported safe migration plan.' };
$items = @(Import-Csv $path);
if (-not $items.Count) { throw 'The plan contains no rows.' };
$results = [Collections.Generic.List[object]]::new();
$checkpoint = [Collections.Generic.List[object]]::new()
foreach ($item in $items) {
    $id = [string]$item.AccountId;
    $destination = [string]$item.DestinationSafeName;
    $status = 'Completed';
    $detail = '';
    try {
        if ($item.State -ne 'Ready') { throw "Plan row is not Ready: $($item.Detail)" };
        $before = Resolve-FastPASAccount $Context $id;
        $currentHash = Get-FastPASObjectHash $before;
        if (-not $item.ExpectedAccountHash -or $currentHash -ne $item.ExpectedAccountHash) { throw 'Account details changed after planning; generate a new plan.' };
        $source = Get-FastPASObjectString $before @('safeName', 'SafeName');
        $checkpoint.Add([pscustomobject]@{AccountId = $id;
                SourceSafeName = $source;
                DestinationSafeName = $destination;
                BeforeHash = $currentHash;
                Before = $before
            });
        $null = Resolve-FastPASSafe $Context $destination
        if (-not $PSCmdlet.ShouldProcess($id, "Move account from '$source' to '$destination'")) {
            $status = 'WhatIf';
            $detail = 'No mutation was sent.'
        }
        else {
            $patch = @(@{op = 'replace';
                    path = '/safeName';
                    value = $destination
                });
            $null = Invoke-FastPASApiRequest -Context $Context -Method PATCH -Path "Accounts/$([uri]::EscapeDataString($id))" -Body $patch;
            $after = Resolve-FastPASAccount $Context $id;
            $actual = Get-FastPASObjectString $after @('safeName', 'SafeName');
            if ($actual -ne $destination) { throw "Verification returned safe '$actual'." };
            $detail = "Moved and verified. New account hash: $(Get-FastPASObjectHash $after)."
        }
    }
    catch {
        $status = 'Failed';
        $detail = $_.Exception.Message
    };
    $results.Add([pscustomobject]@{AccountId = $id;
            AccountName = [string]$item.AccountName;
            SourceSafeName = [string]$item.SourceSafeName;
            DestinationSafeName = $destination;
            Status = $status;
            Detail = $detail
        })
}
$checkpointPath = Export-FastPASJson @($checkpoint) $OutputPath 'safe_migration_checkpoint';
$data = @($results);
$csv = Export-FastPASCsv $data $OutputPath 'safe_migration_results';
$failed = @($data | Where-Object Status -EQ Failed).Count;
$summary = "Processed $($data.Count) safe migration(s): $failed failed. A metadata checkpoint was saved; no password content was retrieved or written."
$artifacts = @($checkpointPath, $csv)
New-FastPASResult -Success ($failed -eq 0) -Summary $summary -Data $data -Artifacts $artifacts -AuditEvents @($data)
