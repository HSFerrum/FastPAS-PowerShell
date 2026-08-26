[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param($Context, [hashtable]$Arguments = @{}, [string]$OutputPath, [switch]$NonInteractive, [switch]$Force)
$path = [string]$Arguments['CsvPath'];
if (-not $path -or -not(Test-Path -LiteralPath $path -PathType Leaf)) { throw 'CsvPath must identify an account-links CSV.' };
$items = @(Import-Csv $path);
if (-not $items.Count) { throw 'The CSV contains no rows.' }
$results = [Collections.Generic.List[object]]::new();
foreach ($item in $items) {
    $action = ([string]$item.Action).Trim();
    $source = [string]$item.SourceAccountId;
    $kind = ([string]$item.LinkType).Trim();
    $index = if ($kind -ieq 'Logon') { 1 }elseif ($kind -ieq 'Reconcile') { 3 }else { 0 };
    $status = 'Completed';
    $detail = ''
    try {
        if ($action -notin @('Link', 'Unlink')) { throw "Action must be Link or Unlink; received '$action'." };
        if (-not $source) { throw 'SourceAccountId is required.' };
        if (-not $index) { throw 'LinkType must be Logon or Reconcile.' };
        # Resolve first so invalid account IDs fail before any mutation is attempted.
        $null = Resolve-FastPASAccount -Context $Context -AccountId $source
        if (-not $PSCmdlet.ShouldProcess($source, "$action $kind account link")) {
            $status = 'WhatIf';
            $detail = 'No mutation was sent.'
        }
        elseif ($action -eq 'Unlink') {
            $null = Invoke-FastPASApiRequest -Context $Context -Method DELETE -Path "Accounts/$([uri]::EscapeDataString($source))/LinkAccount/$index";
            $detail = 'Link removed.'
        }
        else {
            foreach ($required in 'TargetSafeName', 'TargetAccountName') { if (-not $item.$required) { throw "$required is required for Link." } };
            $body = @{safe = [string]$item.TargetSafeName;
                extraPasswordIndex = $index;
                name = [string]$item.TargetAccountName;
                folder = if ($item.TargetFolder) { [string]$item.TargetFolder }else { 'Root' }
            };
            $null = Invoke-FastPASApiRequest -Context $Context -Method POST -Path "Accounts/$([uri]::EscapeDataString($source))/LinkAccount" -Body $body;
            $detail = 'Link created.'
        }
    }
    catch {
        $status = 'Failed';
        $detail = $_.Exception.Message
    }
    $results.Add([pscustomobject]@{Action = $action;
            SourceAccountId = $source;
            LinkType = $kind;
            TargetSafeName = [string]$item.TargetSafeName;
            TargetAccountName = [string]$item.TargetAccountName;
            Status = $status;
            Detail = $detail
        })
}
$data = @($results);
$csv = Export-FastPASCsv $data $OutputPath 'account_link_results';
$failed = @($data | Where-Object Status -EQ Failed).Count;
New-FastPASResult -Success ($failed -eq 0) -Summary "Processed $($data.Count) account link change(s): $failed failed." -Data $data -Artifacts @($csv) -AuditEvents @($data)
